"use strict";

/**
 * VW OAuth 2.0 *device authorization* login flow.
 *
 * Faithful port of robinostlund/volkswagencarnet PR #340 (VWLoginFlow), with
 * one necessary real-world addition: some accounts get a `marketConsent`
 * interstitial between the password and code-confirmation steps. The PR's
 * rigid identifier->password->confirm route breaks on those; this port drives
 * a stage state-machine instead and clears the consent by following the
 * pre-signed callback VW embeds in the page.
 *
 * Why device flow at all: VW retired the classic VW-ID OAuth client
 * (a24fba63-...), so the old authorization-code login returns 403. The device
 * flow uses a different, still-working client ("Volkswagen OneApp",
 * 650d46ca-...) and yields an access_token for the SAME data API
 * (emea.bff.cariad.digital) the adapter's getIdStatus already uses.
 *
 * Cookie reuse is the point: the first login sets a ~24h session cookie plus a
 * ~1-year device cookie. While the session cookie is valid VW skips the
 * email/password prompt entirely (QUICK_ROUTE = confirm only), so we only
 * submit credentials about once per day instead of on every hourly token
 * refresh. That is what keeps VW from throttling us.
 *
 * The class is decoupled from ioBroker: it manages the cookie jar internally
 * and exposes serializeCookies()/loadCookies() so the caller can persist the
 * jar wherever it likes (the adapter stores it in a state to survive restart).
 * Verified end-to-end against identity.vwgroup.io via .docu/testVwDeviceFlow.js.
 */

const request = require("request");
const JSON5 = require("json5");
const tough = require("tough-cookie");
const { URL, URLSearchParams } = require("url");

// --- constants (verbatim from volkswagencarnet vw_const.py) ---------------
const IDENTITY = "https://identity.vwgroup.io";
const DEVICE_FLOW_CLIENT_ID = "650d46ca-2475-4384-85c2-6af3bf3d52f1@apps_vw-dilab_com";
const CLIENT_SCOPE = "openid profile badge cars dealers vin offline_access";
const DEVICE_AUTHORIZATION_URL = IDENTITY + "/oidc/v1/device_authorization";
const TOKEN_URL = IDENTITY + "/oidc/v1/token";
const IDENTIFIER_URL = IDENTITY + "/signin-service/v1/{client_id}/login/identifier";
const AUTHENTICATE_URL = IDENTITY + "/signin-service/v1/{client_id}/login/authenticate";
const CODE_CONFIRMATION_URL = IDENTITY + "/signin-service/v1/device/{client_id}/{user_code}";

const BROWSER_HEADERS = {
  "User-Agent": "volkswagencarnet-auth/1.0 (+https://github.com/robinostlund/volkswagencarnet)",
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
};
const BROWSER_HEADERS_FIREFOX = {
  "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0",
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
};

// IdKitStage template values (window._IDK.templateModel.template)
const STAGE = {
  IDENTIFIER: "loginIdentifier",
  PASSWORD: "loginAuthenticate",
  CONFIRM: "codeConfirmation",
  SUCCESS: "verificationSuccess",
  MARKET_CONSENT: "marketConsent",
};

const TRANSIENT_POLL_STATUSES = new Set([429, 500, 502, 503, 504]);
const TRANSIENT_POLL_ERRORS = new Set(["temporarily_unavailable", "server_error"]);

const NOOP_LOG = { info() {}, warn() {}, error() {}, debug() {} };

class VwLoginFlow {
  /**
   * @param {object} [opts]
   * @param {object} [opts.log] logger with debug/info/warn/error (defaults to no-op)
   * @param {boolean} [opts.useFakeUserAgent] send a Firefox UA if VW blocks the library UA
   */
  constructor(opts = {}) {
    this.log = opts.log || NOOP_LOG;
    this.headers = opts.useFakeUserAgent ? BROWSER_HEADERS_FIREFOX : BROWSER_HEADERS;
    this.jar = request.jar();
  }

  /**
   * Restore a previously serialized cookie jar (from serializeCookies()).
   * Silently ignores malformed input so a corrupt persisted value just means
   * "log in fresh".
   *
   * @param {string|object|null} serialized value produced by serializeCookies()
   * @returns {boolean} whether cookies were restored
   */
  loadCookies(serialized) {
    if (!serialized) return false;
    try {
      const data = typeof serialized === "string" ? JSON.parse(serialized) : serialized;
      this.jar._jar = tough.CookieJar.deserializeSync(data);
      return true;
    } catch (err) {
      this.log.debug("[vwLoginFlow] loadCookies failed (ignored): " + err.message);
      return false;
    }
  }

  /**
   * Serialize the current cookie jar to a JSON string for persistence.
   *
   * @returns {string|null}
   */
  serializeCookies() {
    try {
      return JSON.stringify(this.jar._jar.serializeSync());
    } catch (err) {
      this.log.debug("[vwLoginFlow] serializeCookies failed: " + err.message);
      return null;
    }
  }

  /**
   * Run the full device-authorization login and return the token payload.
   * Uses saved cookies (QUICK_ROUTE) to skip credentials when possible.
   *
   * @param {string} username VW account e-mail
   * @param {string} password VW account password
   * @returns {Promise<{access_token: string, id_token: string, refresh_token: string, expires_in: number}>}
   */
  async login(username, password) {
    if (!username || !password) {
      throw new Error("vwLoginFlow: username and password are required");
    }
    const device = await this._startDeviceFlow();
    const deviceCode = device.device_code;
    const verificationUri = device.verification_uri_complete || device.verification_uri;
    if (!deviceCode || !verificationUri) {
      throw new Error("vwLoginFlow: device flow response missing device_code/verification_uri");
    }
    await this._runBrowserRoute(verificationUri, username, password);
    return this._pollToken(deviceCode, device.interval || 5, device.expires_in || 330);
  }

  /**
   * Refresh the access token using the OIDC refresh_token grant. Returns null
   * if VW rejects it (caller should fall back to login(), which reuses cookies
   * and usually skips credentials).
   *
   * @param {string} refreshToken
   * @returns {Promise<object|null>} token payload or null
   */
  async refresh(refreshToken) {
    if (!refreshToken) return null;
    const r = await this._req({
      method: "POST",
      url: TOKEN_URL,
      form: {
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: DEVICE_FLOW_CLIENT_ID,
      },
    });
    if (r.status === 200) {
      try {
        return JSON.parse(r.body);
      } catch (err) {
        this.log.debug("[vwLoginFlow] refresh: invalid JSON: " + err.message);
        return null;
      }
    }
    this.log.debug(`[vwLoginFlow] refresh_token grant failed: HTTP ${r.status}`);
    return null;
  }

  // --- internal flow -------------------------------------------------------

  async _startDeviceFlow() {
    const r = await this._req({
      method: "POST",
      url: DEVICE_AUTHORIZATION_URL,
      form: { client_id: DEVICE_FLOW_CLIENT_ID, scope: CLIENT_SCOPE },
    });
    if (r.status !== 200) {
      throw new Error(`vwLoginFlow: device_authorization HTTP ${r.status}`);
    }
    return JSON.parse(r.body);
  }

  async _runBrowserRoute(verificationUri, username, password) {
    let r = await this._get(verificationUri);
    const info = {};
    // Stage state-machine: handles identifier/password/confirm plus the
    // optional marketConsent interstitial, in whatever order VW serves them.
    for (let step = 0; step < 10; step++) {
      let view;
      try {
        view = this._idkView(this._extractIdk(r.body));
      } catch (err) {
        // Distinguish "success page has no _IDK" (route end) from "the page
        // HAS _IDK but we failed to parse it" (a real error we must surface,
        // not silently swallow into a 330s token poll).
        if (r.body && r.body.indexOf("window._IDK") < 0) {
          this.log.debug("[vwLoginFlow] no _IDK on page, route complete: url=" + r.url);
          return;
        }
        throw new Error("vwLoginFlow: failed to parse login page (_IDK): " + err.message);
      }

      if (view.stage === STAGE.SUCCESS) return;

      // accumulate sticky + rotating fields across pages
      info.csrf_token = view.csrf_token;
      if (view.client_id) info.client_id = view.client_id;
      if (view.relay_state) info.relay_state = view.relay_state;
      if (view.hmac) info.hmac = view.hmac;
      if (view.user_code) info.user_code = view.user_code;
      if (view.user_id) info.user_id = view.user_id;
      if (view.client_identity_name) info.client_identity_name = view.client_identity_name;

      if (view.stage === STAGE.MARKET_CONSENT) {
        // Client-rendered marketing consent. VW embeds a pre-signed callback
        // (with consentedScopes + hmac) that continues to the device success
        // endpoint. Following it clears the interstitial without opting in.
        const tm = this._extractIdk(r.body).templateModel || {};
        if (!tm.callback) throw new Error("vwLoginFlow: marketConsent page without callback URL");
        r = await this._get(tm.callback, { Referer: r.url });
        if (r.status >= 400) throw new Error(`vwLoginFlow: marketConsent callback HTTP ${r.status}`);
        continue;
      }

      if (view.stage === STAGE.IDENTIFIER || view.stage === STAGE.PASSWORD || view.stage === STAGE.CONFIRM) {
        const built = this._buildRequest(view.stage, info, username, password);
        r = await this._postForm(built.url, built.form, { Referer: r.url });
        if (r.status >= 400) throw new Error(`vwLoginFlow: stage ${view.stage} HTTP ${r.status}`);
        const errParam = this._errorParam(r.url);
        if (errParam) throw new Error(`vwLoginFlow: VW rejected ${view.stage}: error=${errParam}`);
        continue;
      }

      // Unknown stage: VW likely changed the flow. Surface it so we notice.
      throw new Error(`vwLoginFlow: unhandled login stage '${view.stage}'`);
    }
    throw new Error("vwLoginFlow: login did not converge within step budget");
  }

  _buildRequest(stage, info, username, password) {
    if (stage === STAGE.IDENTIFIER) {
      return {
        url: IDENTIFIER_URL.replace("{client_id}", info.client_id || DEVICE_FLOW_CLIENT_ID),
        form: { _csrf: info.csrf_token, relayState: info.relay_state, hmac: info.hmac, email: username },
      };
    }
    if (stage === STAGE.PASSWORD) {
      return {
        url: AUTHENTICATE_URL.replace("{client_id}", this._require(info.client_id, "client_id")),
        form: {
          _csrf: info.csrf_token,
          relayState: info.relay_state,
          hmac: info.hmac,
          email: username,
          password: password,
        },
      };
    }
    // CONFIRM
    const query = new URLSearchParams({
      relayState: this._require(info.relay_state, "relayState"),
      user_id: this._require(info.user_id, "user_id"),
      hmac: this._require(info.hmac, "hmac"),
    }).toString();
    return {
      url:
        CODE_CONFIRMATION_URL.replace("{client_id}", this._require(info.client_id, "client_id")).replace(
          "{user_code}",
          this._require(info.user_code, "user_code"),
        ) +
        "?" +
        query,
      form: {
        _csrf: info.csrf_token,
        client_identity_name: this._require(info.client_identity_name, "client_identity_name"),
        allow: "",
      },
    };
  }

  async _pollToken(deviceCode, interval, expiresIn) {
    const deadline = Date.now() + Math.max(330, expiresIn - 5) * 1000;
    let wait = Math.max(interval, 1);
    while (Date.now() < deadline) {
      await this._sleep(wait * 1000);
      const r = await this._req({
        method: "POST",
        url: TOKEN_URL,
        form: {
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: deviceCode,
          client_id: DEVICE_FLOW_CLIENT_ID,
        },
      });
      if (r.status === 200) return JSON.parse(r.body);
      if (TRANSIENT_POLL_STATUSES.has(r.status)) continue;
      let body;
      try {
        body = JSON.parse(r.body);
      } catch {
        body = {};
      }
      const code = body.error || "";
      if (code === "authorization_pending") continue;
      if (code === "slow_down") {
        wait += 5;
        continue;
      }
      if (TRANSIENT_POLL_ERRORS.has(code)) continue;
      throw new Error(`vwLoginFlow: token poll failed HTTP ${r.status} error=${code}`);
    }
    throw new Error("vwLoginFlow: token poll timed out");
  }

  // --- window._IDK parsing -------------------------------------------------

  _extractIdk(html) {
    const marker = "window._IDK";
    const start = html.indexOf(marker);
    if (start < 0) throw new Error("window._IDK not found");
    const eq = html.indexOf("=", start + marker.length);
    if (eq < 0) throw new Error("window._IDK has no assignment");
    const braceStart = html.indexOf("{", eq);
    if (braceStart < 0) throw new Error("window._IDK has no object literal");
    // Brace-match while skipping string contents so a literal { or } inside a
    // string value (URLs, HTML snippets) can't truncate the object.
    let depth = 0;
    let end = -1;
    let quote = null; // active string delimiter: ' " or `
    for (let i = braceStart; i < html.length; i++) {
      const ch = html[i];
      if (quote) {
        if (ch === "\\") {
          i++; // skip escaped char
        } else if (ch === quote) {
          quote = null;
        }
        continue;
      }
      // Skip JSON5 comments (only occur outside strings in a data literal).
      if (ch === "/" && html[i + 1] === "/") {
        const nl = html.indexOf("\n", i + 2);
        if (nl < 0) break;
        i = nl;
        continue;
      }
      if (ch === "/" && html[i + 1] === "*") {
        const close = html.indexOf("*/", i + 2);
        if (close < 0) break;
        i = close + 1;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === "`") {
        quote = ch;
      } else if (ch === "{") {
        depth++;
      } else if (ch === "}") {
        depth--;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }
    if (end < 0) throw new Error("window._IDK object literal not balanced");
    return JSON5.parse(html.slice(braceStart, end));
  }

  _idkView(idk) {
    const tm = idk.templateModel;
    if (!tm || typeof tm !== "object") throw new Error("window._IDK missing templateModel");
    const deviceUrl = this._parseDeviceUrl(tm);
    const cle = tm.clientLegalEntityModel;
    return {
      stage: tm.template,
      csrf_token: idk.csrf_token,
      client_id: (cle && cle.clientId) || deviceUrl.client_id,
      relay_state: tm.relayState || deviceUrl.relayState,
      hmac: tm.hmac || deviceUrl.hmac,
      user_code: deviceUrl.user_code,
      user_id: deviceUrl.user_id,
      client_identity_name: tm.clientIdentityName,
    };
  }

  _parseDeviceUrl(templateModel) {
    const result = {};
    const raw = templateModel && templateModel.url;
    if (!raw || typeof raw !== "string") return result;
    let parsed;
    try {
      parsed = new URL(raw, IDENTITY);
    } catch {
      return result;
    }
    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length === 3 && parts[0] === "device") {
      result.client_id = parts[1];
      result.user_code = parts[2];
    }
    for (const key of ["relayState", "user_id", "hmac"]) {
      const v = parsed.searchParams.get(key);
      if (v) result[key] = v;
    }
    return result;
  }

  // --- http helpers --------------------------------------------------------

  _req(opts) {
    return new Promise((resolve, reject) => {
      request(
        {
          jar: this.jar,
          gzip: true,
          followAllRedirects: true,
          // Bound every hop so a stalled IdP request can't hang the caller
          // (onReady awaits login()); without this the fallback never runs.
          timeout: 30000,
          ...opts,
          headers: { ...this.headers, ...(opts.headers || {}) },
        },
        (err, resp, body) => {
          if (err) return reject(err);
          resolve({ status: resp.statusCode, url: resp.request.uri.href, body, headers: resp.headers });
        },
      );
    });
  }

  _get(url, headers) {
    return this._req({ method: "GET", url, headers });
  }

  _postForm(url, form, headers) {
    return this._req({
      method: "POST",
      url,
      form,
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...(headers || {}) },
    });
  }

  _errorParam(url) {
    try {
      return new URL(url).searchParams.get("error");
    } catch {
      return null;
    }
  }

  _require(value, field) {
    if (value == null || value === "") throw new Error(`vwLoginFlow: missing ${field}`);
    return value;
  }

  _sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }
}

module.exports = VwLoginFlow;
