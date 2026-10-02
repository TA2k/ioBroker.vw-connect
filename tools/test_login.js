#!/usr/bin/env node
"use strict";

const { parseArgs } = require("node:util");
const { EuDataActClient, SUPPORTED_BRANDS } = require("../lib/euDataAct");

const BRAND_ALIASES = Object.fromEntries(SUPPORTED_BRANDS.map((brand) => [brand.toLowerCase(), brand]));
BRAND_ALIASES.volkswagen = "VOLKSWAGEN_PASSENGER_CARS";
BRAND_ALIASES.volkswagen_commercial = "VOLKSWAGEN_COMMERCIAL_VEHICLES";

const HELP = `Test the adapter's real EU Data Act login and dataset flow without ioBroker.

Usage:
  EUDA_EMAIL='you@example.com' EUDA_PASSWORD='secret' npm run test:login -- --brand audi
  node tools/test_login.js --brand cupra --country es --language es
  node tools/test_login.js --list-brands

Options:
  --brand NAME     Brand slug or portal key (EUDA_BRAND; default: volkswagen)
  --country CODE   Two-letter country (EUDA_COUNTRY; default: de)
  --language CODE  Two-letter language (EUDA_LANGUAGE; default: en, like the adapter)
  --vin VIN        Select a vehicle instead of the first returned (EUDA_VIN)
  --list-brands    List supported brand names without logging in
  --help          Show this help

Email and password may also be supplied as two positional arguments.
Prefer environment variables to avoid exposing credentials in the process list.
HTTP tracing is always enabled, including redirects, status codes and durations.
URL query values/fragments and supplied credentials are redacted; no bodies or
headers are dumped. VINs and dataset identifiers remain visible: review logs
before sharing. Each HTTP request has a 60-second timeout.

Exit codes: 0 = real dataset downloaded; 1 = login/API/input error;
            2 = login OK, but no subscription or real data yet.
`;

function redactUrl(value) {
  if (!URL.canParse(value)) return "[REDACTED URL]";
  const url = new URL(value);
  url.username = "";
  url.password = "";
  for (const key of new Set(url.searchParams.keys())) {
    url.searchParams.set(key, "REDACTED");
  }
  if (url.hash) url.hash = "#REDACTED";
  return url.toString();
}

function createLogger(secrets = [], write = console.log) {
  const redact = (message) => {
    let text = String(message)
      .replace(/\bbody=[\s\S]*/g, "body=[REDACTED]")
      .replace(/https?:\/\/[^\s"'<>]+/g, (url) => redactUrl(url));
    for (const secret of secrets.filter(Boolean)) {
      text = text.split(secret).join("[REDACTED]");
      text = text.split(encodeURIComponent(secret)).join("[REDACTED]");
    }
    return text.replace(/[\r\n]/g, " ");
  };
  const log = {};
  for (const level of ["info", "warn", "error", "debug", "trace"]) {
    log[level] = (message) => write(`${new Date().toISOString()} ${level.toUpperCase()} ${redact(message)}`);
  }
  return log;
}

function traceHttp(log, event) {
  const { method, url, statusCode, location, elapsedMs, errorCode } = event;
  if (errorCode) {
    log.trace(`${method} ${url} -> ERROR ${errorCode} (no completed response)`);
  } else if (statusCode != null) {
    const redirect = location ? ` Location: ${new URL(location, url).href}` : "";
    log.trace(`${method} ${url} -> HTTP ${statusCode} (${elapsedMs}ms)${redirect}`);
  } else {
    log.trace(`${method} ${url} -> sending`);
  }
}

async function runFlow(client, log, selectedVin) {
  log.info("Logging in");
  await client.login();
  log.info("LOGIN OK");

  const vehicles = await client.listVehicles();
  for (const vehicle of vehicles) {
    log.info(`Vehicle: ${vehicle.vin} nickname=${vehicle.nickname || "(none)"}`);
  }
  if (!vehicles.length) {
    throw new Error("No vehicles returned. Check the portal vehicle link and selected brand.");
  }
  const vehicle = selectedVin ? vehicles.find((entry) => entry.vin === selectedVin) : vehicles[0];
  if (!vehicle) throw new Error(`Vehicle ${selectedVin} was not returned by the portal.`);
  const vin = vehicle.vin;

  const metadata = await client.getMetadata(vin);
  const identifier = metadata && metadata.Identifier;
  log.info(`Metadata: Identifier=${identifier || "(none)"} Frequency=${metadata && metadata.Frequency}`);
  if (!identifier) {
    log.warn("NO SUBSCRIPTION: enable a continuous 15-minute data request in the portal first.");
    return 2;
  }

  const datasets = await client.listDatasets(vin, identifier);
  log.info(`${datasets.length} file(s) in delivery list`);
  const content = datasets
    .filter((entry) => entry.name && !entry.name.endsWith("_no_content_found.zip"))
    .sort((a, b) => String(b.createdOn || b.name).localeCompare(String(a.createdOn || a.name)));
  for (const entry of content.slice(0, 5)) {
    log.info(`Dataset: ${entry.name} createdOn=${entry.createdOn}`);
  }
  if (!content.length) {
    log.warn(
      datasets.length
        ? "NO CONTENT YET: only empty snapshots. Wait for the next 15-minute interval while the vehicle is active."
        : "WAITING: subscription active, but no datasets delivered yet.",
    );
    return 2;
  }

  log.info(`Downloading ${content[0].name}`);
  const { json, byteSize, fileName } = await client.downloadDataset(vin, identifier, content[0].name);
  if (!json || !Array.isArray(json.Data)) {
    throw new Error("Downloaded JSON has no Data array.");
  }
  log.info(`Parsed ${fileName}: ${byteSize} bytes, vin=${json.vin}, points=${json.Data.length}`);
  if (!json.Data.length) {
    log.warn("NO CONTENT YET: downloaded dataset contains no data points.");
    return 2;
  }
  log.info("ALL OK: real dataset downloaded through the adapter's EU Data Act client.");
  return 0;
}

async function main(args = process.argv.slice(2), env = process.env) {
  let log = createLogger([env.EUDA_EMAIL, env.EUDA_PASSWORD]);
  try {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        brand: { type: "string", default: env.EUDA_BRAND || "volkswagen" },
        country: { type: "string", default: env.EUDA_COUNTRY || "de" },
        language: { type: "string", default: env.EUDA_LANGUAGE || "en" },
        vin: { type: "string", default: env.EUDA_VIN },
        "list-brands": { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
    });
    if (values.help) {
      console.log(HELP);
      return 0;
    }
    if (values["list-brands"]) {
      for (const [slug, brand] of Object.entries(BRAND_ALIASES)) console.log(`${slug}: ${brand}`);
      return 0;
    }
    const [email = env.EUDA_EMAIL, password = env.EUDA_PASSWORD] = positionals;
    log = createLogger([email, password]);
    if (positionals.length > 2) throw new Error("Expected at most two positional arguments: email and password.");
    const brand = BRAND_ALIASES[values.brand.toLowerCase()];
    if (!SUPPORTED_BRANDS.includes(brand)) throw new Error("Unknown brand. Use --list-brands.");
    const country = values.country.toLowerCase();
    const language = values.language.toLowerCase();
    if (!/^[a-z]{2}$/.test(country) || !/^[a-z]{2}$/.test(language)) {
      throw new Error("Country and language must be two-letter codes.");
    }
    if (!email || !password) throw new Error("Set EUDA_EMAIL and EUDA_PASSWORD, or provide email and password arguments.");
    log.info(`Brand: ${brand}; OIDC state: ${country}__${language}__${brand}`);
    const client = new EuDataActClient({
      email, password, brand, country, language, log,
      trace: (event) => traceHttp(log, event),
      timeout: 60000,
    });
    return await runFlow(client, log, values.vin);
  } catch (err) {
    log.error(`FAILED: ${err.message}`);
    return 1;
  }
}

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  });
}

module.exports = { main, runFlow, createLogger, traceHttp };
