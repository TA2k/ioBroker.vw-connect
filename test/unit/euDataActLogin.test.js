"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const { once } = require("node:events");
const { EuDataActClient } = require("../../lib/euDataAct");
const { main, runFlow, createLogger, traceHttp } = require("../../tools/test_login");

describe("EU Data Act login diagnostics", () => {
  let server;
  let baseUrl;
  let events;
  let client;

  beforeEach(async () => {
    events = [];
    server = http.createServer((req, res) => {
      if (req.url === "/start") {
        res.writeHead(302, { Location: "/middle?code=secret", "Set-Cookie": "session=active; Path=/" });
        res.end();
      } else if (req.url.startsWith("/middle")) {
        res.writeHead(303, { Location: "/final" });
        res.end();
      } else if (req.url === "/final") {
        res.end(JSON.stringify({ method: req.method, cookie: req.headers.cookie }));
      } else if (req.url === "/binary") {
        res.end(Buffer.from([0, 1, 2, 255]));
      } else if (req.url === "/disconnect") {
        req.socket.destroy();
      } else if (req.url === "/slow") {
        // Let the client's timeout end this request.
      } else {
        res.writeHead(503);
        res.end("Unavailable");
      }
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    baseUrl = `http://127.0.0.1:${server.address().port}`;
    client = new EuDataActClient({
      email: "test@example.com",
      password: "test-password",
      trace: (event) => events.push(event),
      timeout: 1000,
    });
  });

  afterEach(async () => {
    const closed = new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
    server.closeAllConnections();
    await closed;
  });

  for (const method of ["GET", "POST"]) {
    it(`traces every ${method} redirect and preserves normal cookies and method changes`, async () => {
      const result = method === "POST"
        ? await client._postForm(`${baseUrl}/start`, { email: client.email, password: client.password })
        : await client._getText(`${baseUrl}/start`);
      assert.equal(result.status, 200);
      assert.deepEqual(JSON.parse(result.body), { method: "GET", cookie: "session=active" });
      const responses = events.filter((event) => event.statusCode);
      assert.deepEqual(responses.map((event) => event.statusCode), [302, 303, 200]);
      assert.deepEqual(responses.map((event) => event.method), [method, "GET", "GET"]);
      assert.deepEqual(responses.map((event) => event.url), [
        `${baseUrl}/start`, `${baseUrl}/middle?code=secret`, `${baseUrl}/final`,
      ]);
      assert.equal(responses[0].location, "/middle?code=secret");
      assert.ok(responses.every((event) => event.elapsedMs >= 0));
      assert.equal(events.filter((event) => !event.statusCode).length, 3);
      assert.ok(!JSON.stringify(events).includes(client.password));
    });
  }

  it("traces binary downloads and HTTP failures", async () => {
    const result = await client._getBuffer(`${baseUrl}/binary`);
    assert.deepEqual(result.body, Buffer.from([0, 1, 2, 255]));
    await assert.rejects(client._getJson(`${baseUrl}/failure`), /HTTP 503/);
    assert.deepEqual(events.filter((event) => event.statusCode).map((event) => event.statusCode), [200, 503]);
  });

  it("traces network failures and propagates them", async () => {
    await assert.rejects(client._getText(`${baseUrl}/disconnect`), { code: "ECONNRESET" });
    assert.equal(events.at(-1).errorCode, "ECONNRESET");
    assert.equal(events.at(-1).url, `${baseUrl}/disconnect`);
  });

  it("times out without reporting success", async () => {
    client.timeout = 30;
    await assert.rejects(client._getText(`${baseUrl}/slow`), (err) => /ECONNABORTED|ETIMEDOUT|TIMEDOUT/.test(err.code));
    assert.match(events.at(-1).errorCode, /ECONNABORTED|ETIMEDOUT|TIMEDOUT/);
  });

  it("keeps tracing optional for the adapter", async () => {
    client.trace = undefined;
    const result = await client._getText(`${baseUrl}/final`);
    assert.equal(result.status, 200);
    assert.deepEqual(events, []);
  });

  it("redacts credentials, URL query values, fragments and error body snippets", () => {
    const output = [];
    const log = createLogger(["user@example.com", "secret-password"], (line) => output.push(line));
    traceHttp(log, {
      method: "POST",
      url: "https://user:pass@example.com/auth?code=secret-code&hmac=secret-hmac#secret-fragment",
      statusCode: 302,
      location: "/login?token=secret-token",
      elapsedMs: 10,
    });
    log.debug("user@example.com secret-password user%40example.com");
    log.error("GET https://example.com/api -> HTTP 500 body=private response");
    const text = output.join("\n");
    assert.match(text, /TRACE POST https:\/\/example.com\/auth\?code=REDACTED&hmac=REDACTED#REDACTED -> HTTP 302/);
    assert.match(text, /Location: https:\/\/example.com\/login\?token=REDACTED/);
    for (const secret of ["user:", "pass@", "secret-", "user@example.com", "user%40example.com", "private response"]) {
      assert.ok(!text.includes(secret), secret);
    }
  });
});

describe("EU Data Act login callback completion", () => {
  const portal = "https://eu-data-act.drivesomethinggreater.com";
  const idp = "https://identity.vwgroup.io";
  const identifierPath = "/signin-service/v1/test/login/identifier";
  const authenticatePath = "/signin-service/v1/test/login/authenticate";
  const apiPath = "/proxy_api/consent/me/vehicles";
  let server;
  let client;
  let requests;
  let events;
  let logs;
  let fixture;

  beforeEach(async () => {
    requests = [];
    events = [];
    logs = [];
    fixture = {
      location: `${portal}/content/euda/de/en/user.html`,
      cookies: ["access_token=fixture-token; Path=/; Secure; HttpOnly"],
      status: 302,
      idpLocation: `${portal}/login?state=fixture-state&code=fixture-code`,
      apiFailures: 0,
    };
    const form = (action) =>
      `<form action="${action}"><input name="hmac" value="fixture-hmac">` +
      "<input name=\"_csrf\" value=\"fixture-csrf\"></form>";
    server = http.createServer((req, res) => {
      const url = new URL(req.url, `https://${req.headers.host}`);
      requests.push({ method: req.method, url: url.href, cookie: req.headers.cookie });
      const redirect = (location) => {
        res.writeHead(302, { Location: location });
        res.end();
      };
      switch (url.pathname) {
        case "/oidc/v1/authorize":
          return redirect(`${idp}${identifierPath}`);
        case identifierPath:
          res.end(form(req.method === "POST" ? authenticatePath : identifierPath));
          return;
        case authenticatePath:
          return redirect(`${idp}/oidc/v1/oauth/sso`);
        case "/oidc/v1/oauth/sso":
          return redirect(`${idp}/oidc/v1/oauth/client/callback/success`);
        case "/oidc/v1/oauth/client/callback/success":
          return redirect(fixture.idpLocation);
        case "/login":
          return redirect("/services/callbacklogin?state=fixture-state&code=fixture-code");
        case "/services/callbacklogin":
          if (fixture.location) res.setHeader("Location", fixture.location);
          if (fixture.cookies.length) res.setHeader("Set-Cookie", fixture.cookies);
          res.statusCode = fixture.status;
          res.end();
          return;
        case apiPath:
          if (fixture.apiFailures > 0) {
            fixture.apiFailures--;
            res.writeHead(403);
          }
          res.end("[]");
          return;
        case "/signin-service/v1/consent/fixture":
          res.end("<div class=\"consent-screen\">Allow or deny</div>");
          return;
        case "/signin-service/v1/error":
          res.end("Authentication failed");
          return;
        case "/error":
        case "/landing":
          res.end("Landing page");
          return;
        default:
          // The user pages are deliberately unavailable. Login must not need them.
          res.writeHead(503);
          res.end("User page unavailable");
      }
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const log = createLogger([], (line) => logs.push(line));
    client = new EuDataActClient({
      email: "test@example.com",
      password: "test-password",
      log,
      trace: (event) => {
        events.push(event);
        traceHttp(log, event);
      },
      timeout: 1000,
    });
    // Route transport to the fixture while retaining the real HTTPS URLs for
    // redirect decisions and Secure/domain/path cookie handling (now done in
    // the client's own loop). A custom axios adapter forwards each hop to the
    // local server; the logical https host is sent as Host so the fixture
    // reconstructs the real URL it records.
    client._http.defaults.adapter = (config) =>
      new Promise((resolve, reject) => {
        const u = new URL(config.url);
        const headers =
          config.headers && typeof config.headers.toJSON === "function"
            ? config.headers.toJSON()
            : { ...(config.headers || {}) };
        headers.host = u.host;
        const proxyReq = http.request(
          {
            hostname: "127.0.0.1",
            port: server.address().port,
            method: (config.method || "GET").toUpperCase(),
            path: u.pathname + u.search,
            headers,
            agent: false,
          },
          (res) => {
            const chunks = [];
            res.on("data", (chunk) => chunks.push(chunk));
            res.on("end", () => {
              const buf = Buffer.concat(chunks);
              resolve({
                data: config.responseType === "arraybuffer" ? buf : buf.toString("utf8"),
                status: res.statusCode,
                statusText: res.statusMessage || "",
                headers: res.headers,
                config,
                request: proxyReq,
              });
            });
          },
        );
        proxyReq.on("error", reject);
        if (config.data) proxyReq.write(config.data);
        proxyReq.end();
      });
  });

  afterEach(async () => {
    const closed = new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
    server.closeAllConnections();
    await closed;
  });

  function assertNoUserPageRequests() {
    assert.ok(!requests.some((entry) => new URL(entry.url).pathname.endsWith("/user.html")));
    assert.ok(!events.some((event) => new URL(event.url).pathname.endsWith("/user.html")));
  }

  it("completes both portal callbacks, stores the cookie, and goes directly to the API", async () => {
    await client.login();
    assert.equal(client._loggedIn, true);
    assert.deepEqual(requests.map((entry) => [entry.method, new URL(entry.url).pathname]), [
      ["GET", "/oidc/v1/authorize"],
      ["GET", identifierPath],
      ["POST", identifierPath],
      ["POST", authenticatePath],
      ["GET", "/oidc/v1/oauth/sso"],
      ["GET", "/oidc/v1/oauth/client/callback/success"],
      ["GET", "/login"],
      ["GET", "/services/callbacklogin"],
    ]);
    const callback = events.at(-1);
    assert.equal(callback.statusCode, 302);
    assert.equal(callback.location, fixture.location);
    assert.match(callback.url, /\/services\/callbacklogin\?/);
    assert.match(logs.join("\n"), /callback completed \(HTTP 302\).*intentionally skipped/);
    assert.ok(!logs.join("\n").includes("fixture-token"));

    assert.deepEqual(await client.listVehicles(), []);
    assert.equal(new URL(requests.at(-1).url).pathname, apiPath);
    assert.equal(requests.at(-1).cookie, "access_token=fixture-token");
    assert.equal(requests.length, 9);
    assertNoUserPageRequests();
  });

  for (const location of [
    "/content/euda/de/en/user.html",
    "/de/en/user.html",
    `${portal}/es/es/user.html`,
    "../content/euda/es/es/user.html",
  ]) {
    it(`stops before the localized destination ${location}`, async () => {
      fixture.location = location;
      client.country = "es";
      client.language = "es";
      await client.login();
      assert.equal(client._loggedIn, true);
      assert.equal(new URL(requests.at(-1).url).pathname, "/services/callbacklogin");
      assertNoUserPageRequests();
    });
  }

  for (const status of [301, 303, 307, 308]) {
    it(`accepts a completed callback with HTTP ${status} without following it`, async () => {
      fixture.status = status;
      await client.login();
      assert.equal(client._loggedIn, true);
      assert.equal(events.at(-1).statusCode, status);
      assertNoUserPageRequests();
    });
  }

  for (const [description, cookies] of [
    ["missing", []],
    ["empty", ["access_token=; Path=/; Secure"]],
    ["expired", ["access_token=fixture-token; Path=/; Secure; Expires=Thu, 01 Jan 1970 00:00:00 GMT"]],
    ["wrong path", ["access_token=fixture-token; Path=/services; Secure"]],
    ["wrong domain", ["access_token=fixture-token; Path=/; Domain=identity.vwgroup.io; Secure"]],
  ]) {
    it(`rejects a ${description} API cookie and leaves login state false`, async () => {
      client._loggedIn = true;
      fixture.cookies = cookies;
      await assert.rejects(client.login(), /usable access_token cookie/);
      assert.equal(client._loggedIn, false);
      assert.equal(new URL(requests.at(-1).url).pathname, "/services/callbacklogin");
      assertNoUserPageRequests();
    });
  }

  it("preserves the same completion boundary during automatic reauthentication", async () => {
    await client.login();
    fixture.apiFailures = 1;
    fixture.cookies = ["access_token=refreshed-fixture-token; Path=/; Secure; HttpOnly"];
    assert.deepEqual(await client.listVehicles(), []);
    assert.equal(requests.filter((entry) => new URL(entry.url).pathname === "/oidc/v1/authorize").length, 2);
    assert.equal(requests.at(-1).cookie, "access_token=refreshed-fixture-token");
    assert.equal(client._loggedIn, true);
    assertNoUserPageRequests();
  });

  it("does not treat an IDP redirect directly to user.html as completed authentication", async () => {
    fixture.idpLocation = fixture.location;
    await assert.rejects(client.login(), /HTTP 503/);
    assert.equal(client._loggedIn, false);
    assert.ok(requests.some((entry) => entry.url === fixture.location));
  });

  for (const target of [
    "https://example.com/landing",
    "https://eu-data-act.drivesomethinggreater.com.example.com/landing",
    "http://eu-data-act.drivesomethinggreater.com/landing",
  ]) {
    it(`does not accept a callback to a different origin: ${target}`, async () => {
      fixture.location = target;
      await assert.rejects(client.login(), /Login did not complete/);
      assert.equal(client._loggedIn, false);
      assert.equal(events.at(-1).url, target);
    });
  }

  it("retains consent and incorrect-password diagnostics", async () => {
    fixture.idpLocation = `${idp}/signin-service/v1/consent/fixture`;
    await assert.rejects(client.login(), /consent screen is blocking the login/);
    fixture.idpLocation = `${idp}/signin-service/v1/error?error=login.errors.password_invalid`;
    await assert.rejects(client.login(), /password incorrect/);
    assert.equal(client._loggedIn, false);
    assertNoUserPageRequests();
  });

  it("does not accept portal error pages as completion", async () => {
    fixture.location = "/error";
    await assert.rejects(client.login(), /Login failed/);
    assert.equal(client._loggedIn, false);
  });

  it("rejects callback HTTP failures and unfinished redirects even with a cookie", async () => {
    fixture.status = 500;
    await assert.rejects(client.login(), /HTTP 500/);
    fixture.status = 302;
    fixture.location = null;
    await assert.rejects(client.login(), /Login did not complete/);
    assert.equal(client._loggedIn, false);
    assertNoUserPageRequests();
  });

  it("preserves a successful non-redirect landing, but still requires the API cookie", async () => {
    fixture.status = 200;
    fixture.location = null;
    await client.login();
    assert.equal(client._loggedIn, true);
    fixture.cookies = ["access_token=; Path=/; Secure; Max-Age=0"];
    await assert.rejects(client.login(), /usable access_token cookie/);
    assert.equal(client._loggedIn, false);
    assertNoUserPageRequests();
  });
});

describe("standalone EU Data Act flow", () => {
  const vin = "WVW00000000000001";
  const anotherVin = "WVW00000000000002";
  let client;
  let log;
  let calls;

  beforeEach(() => {
    calls = [];
    log = createLogger([], () => {});
    client = {
      async login() { calls.push(["login"]); },
      async listVehicles() { calls.push(["vehicles"]); return [{ vin }, { vin: anotherVin }]; },
      async getMetadata(selectedVin) { calls.push(["metadata", selectedVin]); return { Identifier: "subscription" }; },
      async listDatasets(selectedVin, identifier) {
        calls.push(["list", selectedVin, identifier]);
        return [
          { name: "new.zip", createdOn: "2026-10-02T09:00:00Z" },
          { name: "old.zip", createdOn: "2026-10-01T09:00:00Z" },
          { name: "latest_no_content_found.zip", createdOn: "2026-10-02T10:00:00Z" },
        ];
      },
      async downloadDataset(...args) {
        calls.push(["download", ...args]);
        return { json: { vin, Data: [{ key: "soc", value: 50 }] }, fileName: "data.json", byteSize: 123 };
      },
    };
  });

  it("uses the regular client methods and downloads the newest real dataset", async () => {
    assert.equal(await runFlow(client, log), 0);
    assert.deepEqual(calls, [
      ["login"], ["vehicles"], ["metadata", vin],
      ["list", vin, "subscription"], ["download", vin, "subscription", "new.zip"],
    ]);
  });

  it("supports selecting a VIN", async () => {
    assert.equal(await runFlow(client, log, anotherVin), 0);
    assert.deepEqual(calls.at(-1), ["download", anotherVin, "subscription", "new.zip"]);
  });

  it("rejects login failures and stops before calling APIs", async () => {
    client.login = async () => { throw new Error("Login rejected"); };
    await assert.rejects(runFlow(client, log), /Login rejected/);
    assert.deepEqual(calls, []);
  });

  it("rejects missing vehicles and unknown VINs", async () => {
    await assert.rejects(runFlow(client, log, "unknown"), /was not returned/);
    client.listVehicles = async () => [];
    await assert.rejects(runFlow(client, log), /No vehicles/);
  });

  it("returns 2 when a subscription is missing", async () => {
    client.getMetadata = async () => ({});
    assert.equal(await runFlow(client, log), 2);
    assert.ok(!calls.some(([method]) => method === "list" || method === "download"));
  });

  for (const datasets of [[], [{ name: "snapshot_no_content_found.zip" }]]) {
    it(`returns 2 for ${datasets.length ? "no-content snapshots" : "an empty delivery list"}`, async () => {
      client.listDatasets = async () => datasets;
      assert.equal(await runFlow(client, log), 2);
      assert.ok(!calls.some(([method]) => method === "download"));
    });
  }

  it("does not report an empty or malformed downloaded dataset as success", async () => {
    client.downloadDataset = async () => ({ json: { Data: [] } });
    assert.equal(await runFlow(client, log), 2);
    client.downloadDataset = async () => ({ json: {} });
    await assert.rejects(runFlow(client, log), /no Data array/);
  });

  it("propagates API failures", async () => {
    client.getMetadata = async () => { throw new Error("HTTP 400"); };
    await assert.rejects(runFlow(client, log), /HTTP 400/);
  });

  it("rejects missing credentials and invalid options before connecting", async () => {
    assert.equal(await main([], {}), 1);
    assert.equal(await main(["--brand", "invalid"], {}), 1);
    assert.equal(await main(["--country", "invalid"], {}), 1);
    assert.equal(await main(["--unknown"], {}), 1);
  });
});
