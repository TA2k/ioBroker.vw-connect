"use strict";

/**
 * VW EU Data Act portal client.
 *
 * Replaces the old WeConnect / BFF flow for `config.type === "id"`. The
 * portal at https://eu-data-act.drivesomethinggreater.com publishes the
 * vehicle's "continuous data" (15-min interval) per the EU Data Act and is
 * the only source still authorized for ID/Volkswagen accounts.
 *
 * Reference implementation:
 *   .docu/hass-vw-eu-data-act/custom_components/vw_eu_data_act/api.py
 *
 * Login uses the OIDC code flow at identity.vwgroup.io with the EU-Data-Act
 * specific client_id `9b58543e-...@apps_vw-dilab_com`. The portal's own
 * `/services/redirect/authentication` servlet returns 500 for non-browser
 * clients, so we build the authorize URL directly. Same email/password as
 * the WeConnect / Volkswagen App, but a different OIDC client.
 *
 * IMPORTANT prerequisite: the user must once log in on the portal in a
 * browser, link the vehicle and enable a continuous 15-min data request
 * (Data clusters → Vehicle overview → Get customised data → continuous,
 * 15 min). Without it the vehicles endpoint returns `[]` and there is
 * nothing to fetch.
 */

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");
const { URL, URLSearchParams } = require("url");
const axios = require("axios");
const tough = require("tough-cookie");
const packageJson = require("../package.json");

// --- endpoints / constants -------------------------------------------------

const BASE_URL = "https://eu-data-act.drivesomethinggreater.com";
const IDENTITY_BASE = "https://identity.vwgroup.io";
const OIDC_AUTHORIZE_URL = IDENTITY_BASE + "/oidc/v1/authorize";
const OIDC_SCOPE = "openid cars profile";
const OIDC_REDIRECT_URI = BASE_URL + "/login";

// Brand -> OIDC client_id, verified live from the portal's brand selector
// at https://eu-data-act.drivesomethinggreater.com/de/en/login.html — for
// each brand option we clicked Login and captured the resulting authorize
// URL. VW PC and VW Commercial Vehicles share one client_id; SEAT and CUPRA
// share another. The portal also UI-defaults the OIDC state to
// "de__en__<BRAND>" — we mirror that as the default country/language.
const BRAND_CLIENT_IDS = {
  VOLKSWAGEN_PASSENGER_CARS: "9b58543e-1c15-4193-91d5-8a14145bebb0@apps_vw-dilab_com",
  VOLKSWAGEN_COMMERCIAL_VEHICLES: "9b58543e-1c15-4193-91d5-8a14145bebb0@apps_vw-dilab_com",
  AUDI: "cc29b87a-5e9a-4362-aecf-5adea6b01bbb@apps_vw-dilab_com",
  BENTLEY: "d38aac0f-3d89-4a63-8538-b75b31322c7b@apps_vw-dilab_com",
  SKODA: "3ea88bf9-1d4e-4a68-b3ad-4098c1f1d246@apps_vw-dilab_com",
  SEAT: "f85e5b69-e3b2-43aa-9c0d-1b7d0e0b576f@apps_vw-dilab_com",
  CUPRA: "f85e5b69-e3b2-43aa-9c0d-1b7d0e0b576f@apps_vw-dilab_com",
};
const DEFAULT_BRAND = "VOLKSWAGEN_PASSENGER_CARS";

const VEHICLES_PATH = "/proxy_api/consent/me/vehicles";
const RELATION_PATH = "/proxy_api/vum/v2/users/me/relations/{vin}";
const METADATA_PATH = "/proxy_api/euda-apim/datarequest/vehicles/{vin}/metadata/partial";
const LIST_PATH = "/proxy_api/euda-apim/datadelivery/vehicles/{vin}/{identifier}/list";
const DOWNLOAD_PATH = "/proxy_api/euda-apim/datadelivery/vehicles/{vin}/{identifier}/download";

const NO_CONTENT_SUFFIX = "_no_content_found.zip";

const USER_AGENT = `ioBroker.VW_Connect/${packageJson.version}`;

let _DICTIONARY = null;
function loadDictionary() {
  if (_DICTIONARY) return _DICTIONARY;
  try {
    let raw = fs.readFileSync(path.join(__dirname, "euDataActDictionary.json"), "utf-8");
    // Defensive: strip a UTF-8 BOM if the dictionary was edited on Windows
    // (Powershell's `Out-File` adds one and JSON.parse rejects it).
    if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
    _DICTIONARY = JSON.parse(raw);
  } catch {
    _DICTIONARY = {};
  }
  return _DICTIONARY;
}

// --- HTML / JS form parsing ------------------------------------------------

function parseFirstForm(html) {
  // Match any <form ...>, with or without an action attribute. Auth0's
  // universal-login page (/u/login) omits action entirely and the browser
  // falls back to the current URL — callers already resolve that via
  // `new URL(action || "", pageUrl)`.
  const formMatch = /<form\b([^>]*)>([\s\S]*?)<\/form>/i.exec(html);
  if (!formMatch) return { action: null, fields: {} };
  const attrs = formMatch[1];
  const actionAttr = /\baction=("[^"]*"|'[^']*'|[^\s>]+)/i.exec(attrs);
  const action = actionAttr ? actionAttr[1].replace(/^['"]|['"]$/g, "") : null;
  const inner = formMatch[2];
  const fields = {};
  const inputRe = /<input\b[^>]*>/gi;
  let m;
  while ((m = inputRe.exec(inner)) !== null) {
    const tag = m[0];
    const nameMatch = /\bname=("[^"]*"|'[^']*'|[^\s>]+)/i.exec(tag);
    if (!nameMatch) continue;
    const name = nameMatch[1].replace(/^['"]|['"]$/g, "");
    const valMatch = /\bvalue=("[^"]*"|'[^']*'|[^\s>]+)/i.exec(tag);
    fields[name] = valMatch ? valMatch[1].replace(/^['"]|['"]$/g, "") : "";
  }
  return { action, fields };
}

function extractTemplateModel(html) {
  // Identity portal carries hmac/relayState/email in window._IDK.templateModel.
  const idx = html.indexOf("templateModel");
  if (idx < 0) return null;
  const brace = html.indexOf("{", idx);
  if (brace < 0) return null;
  let depth = 0;
  for (let i = brace; i < html.length; i++) {
    const c = html[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) {
        try {
          return JSON.parse(html.substring(brace, i + 1));
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

function extractCsrf(html) {
  const m = /csrf_token\s*[:=]\s*['"]([^'"]+)['"]/.exec(html);
  return m ? m[1] : null;
}

/**
 * Classify an Auth0 flow-state landing URL into one of the known interstitial
 * pages the identity server interjects between the password POST and the OIDC
 * callback. Returns null when the URL is not such a page (login is done or at
 * a diagnosable failure).
 */
function classifyFlowState(landingUrl) {
  if (!URL.canParse(landingUrl)) return null;
  const path = new URL(landingUrl).pathname;
  if (/^\/v2\/login\/ui\/country\b/.test(path)) return { key: "country" };
  if (/^\/v2\/login\/ui\/terms-and-conditions\b/.test(path)) return { key: "terms-and-conditions" };
  if (/^\/v2\/login\/ui\/consent\b/.test(path) && !/\/marketing/.test(path)) return { key: "consent" };
  if (/^\/v2\/login\/ui\/marketing-consent\b/.test(path)) return { key: "marketing-consent" };
  return null;
}

/**
 * The /v2/login/ui/consent page inlines a window._IDK.Data.mandatoryScopes
 * array (e.g. ["profile", "cars"]). Return it as a comma-joined string, or
 * null when the page shape has changed.
 */
function extractConsentedScopes(html) {
  const m = /mandatoryScopes\s*:\s*(\[[^\]]*\])/i.exec(html || "");
  if (!m) return null;
  try {
    const arr = JSON.parse(m[1]);
    if (Array.isArray(arr) && arr.every((x) => typeof x === "string")) return arr.join(",");
  } catch { /* fall through */ }
  return null;
}

/**
 * Parse the window._IDK = { Data: {...} } JSON blob the SPA uses as its
 * initial data. Returns the Data object or null.
 */
function extractIdkData(html) {
  const m = /window\._IDK\s*=\s*(\{[\s\S]*?\});/.exec(html || "");
  if (!m) return null;
  try {
    const obj = JSON.parse(m[1]);
    return obj && obj.Data ? obj.Data : null;
  } catch { return null; }
}

/**
 * Build the body for the marketing-consent /skip endpoint from the page's
 * _IDK.Data. The SPA's "Not now" button posts per-channel values derived
 * from channelType: BOUND_TO_BASIC_AGREEMENT -> "true" (status quo via the
 * basic agreement, no new marketing consent), NOT_USED -> "not_used".
 */
function buildMarketingSkipBody(data) {
  const body = {};
  for (const ch of (data && data.channels) || []) {
    if (!ch || !ch.channelId) continue;
    body[`channel${ch.channelId}`] = ch.channelType === "NOT_USED" ? "not_used" : "true";
  }
  if (data.state) body.state = data.state;
  if (data.relayStateToken) body.relayState = data.relayStateToken;
  if (data.mdKey) body.mdKey = data.mdKey;
  if (data.mdLanguage) body.mdLanguage = data.mdLanguage;
  return body;
}

function loginFields(html) {
  const form = parseFirstForm(html);
  const fields = { ...form.fields };
  const model = extractTemplateModel(html) || {};
  for (const key of ["hmac", "relayState"]) {
    if (model[key]) fields[key] = model[key];
  }
  const email = (model.emailPasswordForm || {}).email;
  if (email && fields.email == null) fields.email = email;
  const csrf = extractCsrf(html);
  if (csrf && fields._csrf == null) fields._csrf = csrf;
  return { fields, action: form.action };
}

function loginErrorText(html) {
  const model = extractTemplateModel(html) || {};
  const err = model.error || model.errorCode;
  if (!err) return null;
  if (typeof err === "object") return err.text || err.errorCode || JSON.stringify(err);
  return String(err);
}

/**
 * VW Identity periodically re-interjects an OPTIONAL marketing-consent page
 * (path /signin-service/v1/consent/marketing/...) after an otherwise
 * successful login. It is NOT the one-time legal/data consent and must not
 * block the adapter: the page embeds a `callback` URL that completes the OAuth
 * flow WITHOUT consenting to marketing. Return that validated callback URL, or
 * null when `landingUrl` is not a marketing-consent page. Mirrors evcc's
 * vwidentity.MarketingConsentCallback.
 */
function marketingConsentCallback(landingUrl) {
  if (!URL.canParse(landingUrl)) return null;
  const u = new URL(landingUrl);
  if (!/\/consent\/marketing\//i.test(u.pathname)) return null;
  const callback = u.searchParams.get("callback");
  if (!callback || !URL.canParse(callback)) return null;
  const cb = new URL(callback);
  const validPath =
    cb.pathname === "/oidc/v1/oauth/client/callback" ||
    cb.pathname === "/oidc/v1/oauth/client/callback/success";
  if (cb.protocol !== "https:" || cb.host !== new URL(IDENTITY_BASE).host || !validPath) {
    return null;
  }
  // Normalize spaces in query values (e.g. scopes) so the request is valid.
  cb.search = cb.searchParams.toString();
  return cb.toString();
}

/**
 * Map a failed-login landing page (URL + HTML) to a user-actionable message.
 *
 * Identity portal surfaces the failure reason in three places:
 *   1. ?error=<code> on the landing URL (e.g. login.errors.password_invalid)
 *   2. window._IDK.templateModel.error in the body
 *   3. nothing at all — bare "back to signin-service" redirect
 *
 * Known error codes (observed in the wild):
 *   login.errors.password_invalid     - wrong password
 *   login.errors.email_invalid        - email not registered / typo
 *   login.error.throttled             - too many failed attempts, locked out
 *   login.errors.tenants.notAuthorized - account ineligible for this client
 *   login.errors.account_disabled     - account locked by VW
 */
function diagnoseLoginFailure(landing) {
  // Consent screen: the password was correct but the user has never logged
  // into the EU Data Act portal in a browser, so the IdP halts on its
  // "Allow / Deny" page. We do NOT script the Allow click — that is a
  // user-facing legal consent and must be performed in a real browser.
  if (
    /\/signin-service\/v1\/consent\//i.test(landing.url) ||
    /\bconsent-screen\b/i.test(landing.body || "")
  ) {
    return (
      "EU Data Act portal not yet authorised for this account: the VW Identity " +
      "consent screen is blocking the login. Open " +
      "https://eu-data-act.drivesomethinggreater.com/ in a browser, log in with " +
      "the same credentials, click Allow on the consent screen, and finish " +
      "the portal-side setup (vehicle linking + continuous data request)."
    );
  }
  const errCode = (() => {
    try {
      return new URL(landing.url).searchParams.get("error");
    } catch {
      return null;
    }
  })();
  const modelText = loginErrorText(landing.body);
  const code = errCode || modelText || "";

  if (/password_invalid/i.test(code)) {
    return "Login failed: password incorrect (login.errors.password_invalid).";
  }
  if (/email_invalid|user_id|identifier/i.test(code)) {
    return "Login failed: email not recognised by VW Identity (login.errors.email_invalid).";
  }
  if (/throttle|rate_limit|too_many/i.test(code)) {
    return "Login failed: too many failed attempts, account temporarily throttled by VW. " +
      "Wait ~30 min before retrying.";
  }
  if (/account_disabled|locked|blocked/i.test(code)) {
    return "Login failed: VW account is locked or disabled. Reset the password at " +
      "https://identity.vwgroup.io/ before retrying.";
  }
  if (/tenants?\.?notAuthorized|client_not_allowed/i.test(code)) {
    return "Login failed: this VW account is not entitled to use the EU Data Act portal. " +
      "Open https://eu-data-act.drivesomethinggreater.com/ in a browser and complete " +
      "first-time setup (terms, vehicle linking).";
  }
  if (code) {
    return `Login failed: ${code}`;
  }
  // Last resort: no recognised code. Surface as much as we safely can so the
  // failure is diagnosable straight from the error log (no debug level needed):
  // the landing HTTP status, a Retry-After header if the IdP throttled us, and
  // a sanitized snippet of the visible page text. HTML tags are stripped (which
  // also drops hidden-input token values) and any leftover long hex blob is
  // redacted, so no hmac/_csrf/relayState leaks into the log.
  const status = landing.status != null ? landing.status : "?";
  const retryAfter =
    landing.headers && (landing.headers["retry-after"] || landing.headers["Retry-After"]);
  const snippet = (() => {
    if (!landing.body) return "";
    return String(landing.body)
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/\b[A-Fa-f0-9]{32,}\b/g, "<redacted>")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 300);
  })();
  return (
    "Login failed (no error code reported by IdP). " +
    `HTTP ${status}${retryAfter ? `, Retry-After: ${retryAfter}` : ""}. ` +
    `Landing URL: ${landing.url}` +
    (snippet ? ` | page text: "${snippet}"` : "")
  );
}

// --- value parsing (mirrors data.py.parse_value) ---------------------------

const _DURATION_RE = /^(-?\d+(?:\.\d+)?)\s*s$/i;
const _NUMBER_RE = /^-?\d+(?:\.\d+)?$/;
const _ENUM_TOKEN_RE = /^[A-Z][A-Z0-9_]*$/;

function parseValue(raw, typeHint) {
  if (raw == null) return null;
  const s = String(raw).trim();
  if (s === "") return null;
  const hint = (typeHint || "").toLowerCase();

  if (hint === "boolean" || s.toLowerCase() === "true" || s.toLowerCase() === "false") {
    return s.toLowerCase() === "true";
  }
  // duration shorthand ("0s", "1800s") - strip suffix and treat as seconds.
  const dur = _DURATION_RE.exec(s);
  if (dur) return parseFloat(dur[1]);
  // Plain integers / floats. Number() rejects "12abc" / leading/trailing
  // whitespace / hex unlike parseFloat, so the regex pre-check is needed.
  if (_NUMBER_RE.test(s)) return Number(s);
  return s;
}

// --- ZIP helper (one-file central-directory-less inflate) ------------------

function unzipFirstJson(buf, name) {
  let off = 0;
  while (off + 30 <= buf.length) {
    const sig = buf.readUInt32LE(off);
    if (sig !== 0x04034b50) break;
    const flags = buf.readUInt16LE(off + 6);
    const method = buf.readUInt16LE(off + 8);
    const compSize = buf.readUInt32LE(off + 18);
    const nameLen = buf.readUInt16LE(off + 26);
    const extraLen = buf.readUInt16LE(off + 28);
    const fileName = buf.slice(off + 30, off + 30 + nameLen).toString("utf-8");
    const dataStart = off + 30 + nameLen + extraLen;
    let entrySize = compSize;
    if ((flags & 0x08) && compSize === 0) {
      let scan = dataStart;
      while (scan + 4 <= buf.length) {
        if (buf.readUInt32LE(scan) === 0x08074b50) break;
        scan++;
      }
      entrySize = scan - dataStart;
    }
    const compressed = buf.slice(dataStart, dataStart + entrySize);
    if (fileName.toLowerCase().endsWith(".json")) {
      let raw;
      if (method === 0) raw = compressed;
      else if (method === 8) raw = zlib.inflateRawSync(compressed);
      else throw new Error(`Unsupported zip method ${method} for ${fileName} in ${name}`);
      let text = raw.toString("utf-8");
      if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
      return { fileName, json: JSON.parse(text) };
    }
    off = dataStart + entrySize;
    if (flags & 0x08) {
      if (buf.readUInt32LE(off) === 0x08074b50) off += 16;
      else off += 12;
    }
  }
  throw new Error(`No JSON inside ${name}`);
}

// --- VIN extractor (proxy_api/consent/me/vehicles wraps loosely) -----------

function extractVins(payload) {
  const list = Array.isArray(payload) ? payload : payload && payload.vehicles;
  if (!Array.isArray(list)) return [];
  const seen = {};
  for (const v of list) {
    const vin = v && (v.vin || v.vehicleIdentificationNumber);
    if (typeof vin !== "string" || vin.length !== 17 || seen[vin]) continue;
    seen[vin] = {
      vin,
      // Portal returns nickName (camelCase) — older payload shapes used
      // nickname / vehicleNickname / modelName. Try them all in priority.
      nickname: v.nickName || v.vehicleNickname || v.nickname || v.modelName || undefined,
      licensePlate: v.licensePlate || undefined,
      imageLocation: v.imageLocation || undefined,
      role: v.role || undefined,
      enrollmentStatus: v.enrollmentStatus || undefined,
    };
  }
  return Object.values(seen);
}

// --- raw data points -> structured object (for json2iob) -------------------

// Field names that are monotonic non-decreasing — for these the largest
// numeric value across duplicates is the freshest reading. Mirrors the
// HA_VAG-EU-Data-Act fork's `monotonic` curated flag. Lagging report
// snapshots in the same dataset can otherwise make the odometer read low.
const MONOTONIC_FIELDS = new Set([
  "mileage.value",
  "mileage",
]);

// Field-name aliases — some car models (Cupra Terramar PHEV, older Passat
// GTE) ship semantically-equal data under different dataFieldNames. Map
// them to the canonical name so a state path stays the same across models.
// Ported from HA_VAG fork's _FIELD_ALIASES.
const FIELD_ALIASES = {
  remaining_climatisation_time: "remaining_climate_time",
  charging_plug1_connectionstate: "plug_state",
};

// Sentinel integer values the portal emits when a sensor has no current
// reading. Without filtering these reach the user-facing state as
// "Odometer: 4,294,967,295 km" or "remaining charging time: 65,535 min".
// Ported from HA_VAG fork's is_usable_reading (data.py:730-793).
const GENERIC_INT_SENTINELS = new Set([65535, 2147483647, 4294967295]);
// Field-specific sentinels: -1 from any of these "remaining charging time"
// variants means "unknown" rather than "0 minutes". List mirrors HA_VAG
// fork (data.py:747-750).
const MINUS_ONE_SENTINEL_FIELDS = new Set([
  "remaining_charging_time",
  "remaining_charging_time_to_complete",
  "battery_state_report.remaining_charging_time_complete",
  "battery_state_report.remaining_charging_time_bulk",
  "remaining_charging_time_target_soc",
]);
// tyre_pressure_* fields use 0/1 as protocol status codes (0 = invalid,
// 1 = warning), real bar pressures are always >1.5.
function isSentinelReading(value, fieldName) {
  if (value === null || value === undefined) return true;
  if (typeof value === "string" && value.trim() === "") return true;
  const num = typeof value === "number" ? value : parseFloat(value);
  if (!Number.isFinite(num)) return false;
  if (GENERIC_INT_SENTINELS.has(num)) return true;
  if (MINUS_ONE_SENTINEL_FIELDS.has(fieldName) && num === -1) return true;
  if (typeof fieldName === "string" && fieldName.includes("tyre_pressure") && (num === 0 || num === 1)) {
    return true;
  }
  return false;
}

// Field pairs to reconstruct when the primary is missing: a PHEV's
// combined cruising range often arrives empty while both per-engine
// components are populated. Sum them as a fallback. Portal value wins
// when present. Ported from HA_VAG sum_fallback_fields.
const SUM_FALLBACKS = [
  {
    target: "cruising_range_combined",
    components: ["cruising_range_primary_engine", "cruising_range_secondary_engine"],
  },
];

/**
 * Convert the flat `Data: [{key, dataFieldName, value}]` array into a nested
 * object keyed by the dotted dataFieldName, with values typed via the
 * dictionary.
 *
 * Tie-break across duplicates of the same dataFieldName:
 *   - sentinel readings (65535, etc.) are skipped if any usable value exists.
 *   - monotonic fields (e.g. mileage.value): pick the LARGEST numeric value.
 *     The portal mixes several report snapshots into one array; older
 *     snapshots lag the current odometer by a few km, so the max is the
 *     truest live reading.
 *   - everything else: pick the LAST occurrence in the ZIP (array order).
 *     Per the HA_VAG-EU-Data-Act analysis the portal bundles minute-level
 *     snapshots in array order, so the last duplicate is the best proxy for
 *     the freshest value. The earlier "smallest UUID" tie-break was stable
 *     but arbitrary and consistently picked stale values for mileage.
 */
function normalizeDataset(payload) {
  const dictionary = loadDictionary();
  const points = {};
  let seq = 0;
  for (const item of payload.Data || []) {
    if (!item || !item.key) continue;
    const meta = dictionary[item.key] || {};
    let fieldName = item.dataFieldName || meta.name || item.key;
    if (!fieldName) continue;
    if (FIELD_ALIASES[fieldName]) fieldName = FIELD_ALIASES[fieldName];
    const sequence = seq++;
    const itemIsSentinel = isSentinelReading(item.value, fieldName);
    if (!points[fieldName]) {
      points[fieldName] = { item, meta, sequence, sentinel: itemIsSentinel };
      continue;
    }
    const cur = points[fieldName];
    // Usability filter: a usable reading always beats a sentinel, regardless
    // of monotonic/last-occurrence semantics. A sentinel never overwrites a
    // good reading. Two-sentinel or two-good fall through to normal tie-break.
    if (cur.sentinel && !itemIsSentinel) {
      cur.item = item;
      cur.meta = meta;
      cur.sequence = sequence;
      cur.sentinel = false;
      continue;
    }
    if (!cur.sentinel && itemIsSentinel) continue;
    if (MONOTONIC_FIELDS.has(fieldName)) {
      // Largest numeric value wins; sequence is only a tie-breaker for
      // equal values.
      const a = parseFloat(item.value);
      const b = parseFloat(cur.item.value);
      const aNum = Number.isFinite(a);
      const bNum = Number.isFinite(b);
      let take = false;
      if (aNum && !bNum) take = true;
      else if (aNum && bNum && a > b) take = true;
      else if (aNum && bNum && a === b && sequence > cur.sequence) take = true;
      if (take) {
        cur.item = item;
        cur.meta = meta;
        cur.sequence = sequence;
        cur.sentinel = itemIsSentinel;
      }
    } else if (sequence > cur.sequence) {
      // Last-occurrence wins.
      cur.item = item;
      cur.meta = meta;
      cur.sequence = sequence;
      cur.sentinel = itemIsSentinel;
    }
  }

  const out = {};
  for (const fieldName of Object.keys(points)) {
    const { item, meta, sentinel } = points[fieldName];
    if (sentinel) {
      // Skip writing — the only occurrences in the dataset were sentinels.
      // Existing ioBroker state (if any) stays at its last known-good
      // value (json2iob doesn't deleteBeforeUpdate by default); a state
      // that was never written stays absent. Either way better than
      // overwriting with a 4-billion km odometer.
      continue;
    }
    let value = parseValue(item.value, meta.type);
    if ((meta.type || "").toLowerCase() === "enum" && typeof value === "number" && meta.description) {
      // Enum fields occasionally deliver the protobuf integer index instead
      // of the label; resolve via the comma-separated UPPER_SNAKE member list
      // documented in the data dictionary (PDF extraction inserts stray
      // spaces inside the tokens, hence the whitespace strip).
      const members = meta.description
        .split(",")
        .map((p) => p.replace(/\s+/g, ""))
        .filter((m) => _ENUM_TOKEN_RE.test(m));
      if (members.length >= 2 && value >= 0 && value < members.length) value = members[value];
    }
    setNested(out, fieldName, value);
  }

  // sum_fallback: PHEV combined range frequently arrives empty (or as a
  // sentinel) while both per-engine components are present. Reconstruct
  // so users don't see "unknown" for total range. Portal value wins when
  // present and usable; we only fill if the target is missing OR the
  // only occurrences were sentinels.
  for (const fallback of SUM_FALLBACKS) {
    const target = points[fallback.target];
    if (target && !target.sentinel) continue;
    let sum = 0;
    let any = false;
    for (const c of fallback.components) {
      const p = points[c];
      if (!p || p.sentinel) continue;
      const n = parseFloat(p.item.value);
      if (Number.isFinite(n)) {
        sum += n;
        any = true;
      }
    }
    if (any) setNested(out, fallback.target, sum);
  }

  out._meta = {
    vin: payload.vin || null,
    user_id: payload.user_id || null,
    points: (payload.Data || []).length,
  };
  return out;
}

function setNested(target, dottedName, value) {
  const parts = dottedName.split(".");
  let cur = target;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    // dictionary keys sometimes use "[*]" placeholder for array indices that
    // appear in actual datasets as e.g. "profiles.0". keep them as-is.
    const existing = cur[key];
    if (existing == null) {
      cur[key] = {};
    } else if (typeof existing !== "object") {
      // A previous dataFieldName wrote a primitive at this branch (e.g.
      // "timestamp" then later "timestamp.foo"). Don't drop the primitive on
      // the floor — preserve it as a `_value` leaf so json2iob still emits it.
      cur[key] = { _value: existing };
    }
    cur = cur[key];
  }
  const leaf = parts[parts.length - 1];
  // Symmetric defence: if the leaf slot already holds an object, the new
  // primitive becomes its `_value` instead of clobbering the subtree.
  if (cur[leaf] != null && typeof cur[leaf] === "object" && (typeof value !== "object" || value === null)) {
    cur[leaf]._value = value;
  } else {
    cur[leaf] = value;
  }
}

// --- client ----------------------------------------------------------------

function loginCompletionRedirect(status, sourceUrl, location) {
  if (![301, 302, 303, 307, 308].includes(status) || !location || !URL.canParse(sourceUrl)) return null;
  const source = new URL(sourceUrl);
  if (source.origin !== BASE_URL || source.pathname !== "/services/callbacklogin") return null;
  if (!URL.canParse(location, source)) return null;
  const target = new URL(location, source);
  if (
    target.origin !== BASE_URL ||
    target.username || target.password ||
    !/^\/(?:content\/euda\/)?[a-z]{2}\/[a-z]{2}\/user\.html$/.test(target.pathname)
  ) {
    return null;
  }
  return target;
}

class EuDataActClient {
  /**
   * @param {object} opts
   * @param {string} opts.email
   * @param {string} opts.password
   * @param {string} [opts.brand]     OIDC brand key, default "VOLKSWAGEN_PASSENGER_CARS".
   *                                  Other valid values: AUDI, SKODA, SEAT, CUPRA,
   *                                  BENTLEY, VOLKSWAGEN_COMMERCIAL_VEHICLES.
   *                                  Each brand uses a different OIDC client_id
   *                                  (verified live from the portal's brand selector).
   * @param {string} [opts.country]   default "de" (matches the portal UI default).
   * @param {string} [opts.language]  default "en" (matches the portal UI default).
   * @param {object} [opts.log]       ioBroker-like logger ({info,warn,error,debug})
   * @param {function} [opts.trace]   Optional per-request HTTP diagnostics (including redirects).
   * @param {number} [opts.timeout]   Optional HTTP timeout in milliseconds.
   */
  constructor(opts) {
    this.email = opts.email;
    this.password = opts.password;
    this.brand = opts.brand || DEFAULT_BRAND;
    this.country = opts.country || "de";
    this.language = opts.language || "en";
    this.log = opts.log || { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };
    this.trace = opts.trace;
    this.timeout = opts.timeout;
    this.jar = new tough.CookieJar();
    // Single injectable transport. Tests swap this._http.defaults.adapter to
    // route to a local fixture while keeping the logical https URLs (so our
    // redirect/cookie handling below behaves exactly as in production).
    this._http = axios.create();
    this._loggedIn = false;
    // Login serialization: multiple VINs can hit an expired session in the
    // same poll tick. _loginPromise coalesces concurrent logins onto a single
    // in-flight OIDC flow; _loginGen is bumped on each success so a caller
    // whose request failed before a concurrent login finished can skip its
    // own redundant login and just retry on the fresh session.
    this._loginPromise = null;
    this._loginGen = 0;
  }

  _state() {
    return `${this.country}__${this.language}__${this.brand}`;
  }

  async _req(opts) {
    // Manual redirect-following loop replacing request's engine. Keeps the
    // cookie jar (tough-cookie) and the per-redirect decision hook so the
    // login flow can stop before the heavy user.html page. Returns the same
    // shape callers consumed from request: { resp:{statusCode,request:{uri:{href}},headers}, body }.
    const maxHops = 20;
    let method = (opts.method || "GET").toUpperCase();
    let url = opts.url;
    // request's `form` option -> url-encoded body + content-type.
    let data;
    const baseHeaders = { "User-Agent": USER_AGENT, ...(opts.headers || {}) };
    if (opts.form) {
      data = new URLSearchParams(opts.form).toString();
      baseHeaders["Content-Type"] = "application/x-www-form-urlencoded";
    }
    const responseType = opts.encoding === null ? "arraybuffer" : "text";

    for (let hop = 0; ; hop++) {
      const headers = { ...baseHeaders };
      const cookie = this.jar.getCookieStringSync(url);
      if (cookie) headers.Cookie = cookie;
      const startedAt = Date.now();
      if (this.trace) this.trace({ method, url });
      let resp;
      try {
        resp = await this._http.request({
          method,
          url,
          data: method === "GET" || method === "HEAD" ? undefined : data,
          headers,
          responseType,
          timeout: this.timeout,
          maxRedirects: 0,
          decompress: true,
          validateStatus: () => true,
          transformResponse: [(x) => x],
        });
      } catch (err) {
        if (this.trace) this.trace({ method, url, errorCode: err.code || err.name });
        throw err;
      }
      const rawHeaders = resp.headers || {};
      const headersObj = typeof rawHeaders.toJSON === "function" ? rawHeaders.toJSON() : { ...rawHeaders };
      // Persist Set-Cookie against the logical (https) URL so Secure cookies behave.
      const setCookie = rawHeaders["set-cookie"];
      if (Array.isArray(setCookie)) {
        for (const c of setCookie) {
          try {
            this.jar.setCookieSync(c, url);
          } catch {
            /* ignore a malformed or cross-domain Set-Cookie */
          }
        }
      }
      if (this.trace) {
        this.trace({
          method,
          url,
          statusCode: resp.status,
          location: headersObj.location,
          elapsedMs: Date.now() - startedAt,
        });
      }
      const synthetic = { statusCode: resp.status, request: { uri: { href: url } }, headers: headersObj };
      const location = headersObj.location;
      if (resp.status >= 300 && resp.status < 400 && location && hop < maxHops) {
        // Mirror request: method/followAllRedirects policy gates first, then
        // an explicit followRedirect(resp) hook may veto (login stops here).
        let follow = method === "GET" || method === "HEAD" || !!opts.followAllRedirects;
        if (follow && typeof opts.followRedirect === "function") {
          follow = !!opts.followRedirect(synthetic);
        }
        if (follow) {
          url = new URL(location, url).toString();
          // 301/302/303 downgrade POST->GET and drop the body; 307/308 keep both.
          if (method !== "GET" && method !== "HEAD" && resp.status !== 307 && resp.status !== 308) {
            method = "GET";
            data = undefined;
            delete baseHeaders["Content-Type"];
          }
          continue;
        }
      }
      let body = resp.data;
      if (responseType === "arraybuffer") {
        body = Buffer.isBuffer(body) ? body : Buffer.from(body || []);
      } else if (body == null) {
        body = "";
      }
      return { resp: synthetic, body };
    }
  }

  async _getText(url, headers, followRedirect) {
    const startedAt = Date.now();
    const { resp, body } = await this._req({
      method: "GET",
      url,
      followRedirect,
      headers: { "User-Agent": USER_AGENT, ...(headers || {}) },
    });
    const text = String(body || "");
    this.log.debug(
      `[euDataAct] GET ${url} -> ${resp.statusCode} (${text.length}B, ${Date.now() - startedAt}ms)`,
    );
    return { status: resp.statusCode, url: resp.request.uri.href, body: text, headers: resp.headers };
  }

  async _postForm(url, form, headers, followRedirect) {
    const startedAt = Date.now();
    const { resp, body } = await this._req({
      method: "POST",
      url,
      form,
      followAllRedirects: true,
      followRedirect,
      headers: { "User-Agent": USER_AGENT, ...(headers || {}) },
    });
    const text = String(body || "");
    this.log.debug(
      `[euDataAct] POST ${url} -> ${resp.statusCode} (${text.length}B, ${Date.now() - startedAt}ms)`,
    );
    return { status: resp.statusCode, url: resp.request.uri.href, body: text, headers: resp.headers };
  }

  async _getBuffer(url, headers) {
    const startedAt = Date.now();
    const { resp, body } = await this._req({
      method: "GET",
      url,
      encoding: null,
      headers: { "User-Agent": USER_AGENT, ...(headers || {}) },
    });
    const size = Buffer.isBuffer(body) ? body.length : 0;
    this.log.debug(
      `[euDataAct] GET ${url} (binary) -> ${resp.statusCode} (${size}B, ${Date.now() - startedAt}ms)`,
    );
    return { status: resp.statusCode, url: resp.request.uri.href, body, headers: resp.headers };
  }

  buildAuthorizeUrl() {
    const clientId = BRAND_CLIENT_IDS[this.brand];
    if (!clientId) {
      throw new Error(
        `Unknown EU Data Act brand "${this.brand}". Valid brands: ${Object.keys(BRAND_CLIENT_IDS).join(", ")}`,
      );
    }
    const params = new URLSearchParams({
      client_id: clientId,
      response_type: "code",
      scope: OIDC_SCOPE,
      state: this._state(),
      redirect_uri: OIDC_REDIRECT_URI,
      prompt: "login",
    });
    return `${OIDC_AUTHORIZE_URL}?${params.toString()}`;
  }

  /**
   * Serialize concurrent logins. A login already in flight is always awaited
   * first, so a caller whose request failed on an older session joins it
   * instead of retrying too early. Only when no login is running and a newer
   * one has already completed since the caller observed `gen` is the login
   * skipped (its fresh session is reused).
   */
  async login(gen = this._loginGen) {
    if (this._loginPromise) return this._loginPromise;
    if (gen !== this._loginGen) return;
    this._loginPromise = this._doLogin()
      .then(() => {
        this._loginGen++;
      })
      .finally(() => {
        this._loginPromise = null;
      });
    return this._loginPromise;
  }

  /**
   * Run the full OIDC code flow. Cookies stored in this.jar are used for
   * subsequent proxy_api calls.
   */
  async _doLogin() {
    this._loggedIn = false;
    // 1. start OIDC at the IdP directly (the portal's redirect servlet 500s
    //    for non-browser clients).
    const authorizeUrl = this.buildAuthorizeUrl();
    this.log.debug("[euDataAct] step1: GET " + authorizeUrl);
    const signin = await this._getText(authorizeUrl);
    if (signin.status !== 200) {
      throw new Error(`Authorize returned HTTP ${signin.status}`);
    }

    // VW Identity now serves two different login flows depending on brand/
    // account: the classic 2-step signin-service (email -> password) and the
    // Auth0 universal-login (/u/login) that posts {state, username, password}
    // in a single step. Detect by landing path.
    const landing = /\/u\/login\b/i.test(new URL(signin.url).pathname)
      ? await this._loginAuth0(signin)
      : await this._loginClassic(signin);
    // VW periodically re-interjects an optional marketing-consent page after an
    // otherwise successful login. Skip it WITHOUT consenting by following the
    // callback URL it embeds, instead of failing the login (the recurring
    // re-consent would otherwise break every login). The legal/data consent
    // VW periodically re-interjects an optional marketing-consent page after an
    // otherwise successful login. Skip it WITHOUT consenting by following the
    // callback URL it embeds, instead of failing the login (the recurring
    // re-consent would otherwise break every login). The legal/data consent
    // (non-marketing) still requires a browser and is caught below.
    let settled = landing;
    const marketingCb = marketingConsentCallback(landing.url);
    if (marketingCb) {
      this.log.debug("[euDataAct] optional marketing-consent page encountered; skipping via callback");
      settled = await this._getText(marketingCb, { Referer: landing.url }, (response) =>
        !loginCompletionRedirect(response.statusCode, response.request.uri.href, response.headers.location),
      );
    }
    if (settled.status >= 400) {
      const err = loginErrorText(settled.body);
      throw new Error(err || `Login rejected (HTTP ${settled.status})`);
    }
    if (settled.url.includes("signin-service") || settled.url.includes("/error")) {
      throw new Error(diagnoseLoginFailure(settled));
    }
    const skippedPage = loginCompletionRedirect(settled.status, settled.url, settled.headers.location);
    if (
      new URL(settled.url).origin !== BASE_URL ||
      (!skippedPage && (settled.status < 200 || settled.status >= 300))
    ) {
      throw new Error("Login did not complete (ended at " + settled.url + ")");
    }
    const accessToken = this.jar.getCookiesSync(`${BASE_URL}${VEHICLES_PATH}`)
      .find((cookie) => cookie.key === "access_token" && cookie.value.trim());
    if (!accessToken) {
      throw new Error(
        "Login did not establish a usable access_token cookie for the portal API. " +
        "Check the portal login/setup in a browser; the user page was not requested as a fallback.",
      );
    }
    this._loggedIn = true;
    if (skippedPage) {
      this.log.debug(
        `[euDataAct] login OK, callback completed (HTTP ${settled.status}); ` +
        `redirect to ${skippedPage.origin}${skippedPage.pathname} intentionally skipped`,
      );
    } else {
      this.log.debug("[euDataAct] login OK, landed at " + settled.url);
    }
  }

  /**
   * Classic 2-step signin-service flow (hmac/_csrf/relayState in templateModel).
   * Returns the landing response after the authenticate POST, with
   * stop-before-user.html veto applied so the heavy final page is skipped.
   */
  async _loginClassic(signin) {
    let { fields, action } = loginFields(signin.body);
    if (!fields.hmac || !fields._csrf) {
      throw new Error("Could not parse signin form (missing hmac/_csrf) - portal layout may have changed");
    }
    fields.email = this.email;
    const identifierAction = new URL(action || "", signin.url).toString();
    const auth = await this._postForm(identifierAction, fields, { Referer: signin.url });
    this.log.debug(`[euDataAct] step2: status=${auth.status} url=${auth.url}`);

    ({ fields, action } = loginFields(auth.body));
    if (!fields.hmac || !fields._csrf) {
      const err = loginErrorText(auth.body);
      throw new Error(err || "Identity portal did not return password form (check email)");
    }
    fields.email = this.email;
    fields.password = this.password;
    const authenticateAction = action ? new URL(action, auth.url).toString() : auth.url.split("?", 1)[0];
    return this._postForm(authenticateAction, fields, { Referer: auth.url }, (response) =>
      !loginCompletionRedirect(response.statusCode, response.request.uri.href, response.headers.location),
    );
  }

  /**
   * Auth0 universal-login flow (single POST with {state, username, password}
   * against /u/login?state=...). Introduced for CUPRA/SEAT in late 2026.
   * Follows the subsequent OIDC redirect chain back to the portal with the
   * stop-before-user.html veto, so completion checks run on the final 3xx.
   */
  async _loginAuth0(signin) {
    const { fields, action } = loginFields(signin.body);
    const state = fields.state;
    if (!state) {
      const err = loginErrorText(signin.body);
      throw new Error(err || "Auth0 login page missing state - portal layout may have changed");
    }
    const postUrl = new URL(action || "", signin.url).toString();
    const body = { state, username: this.email, password: this.password };
    let resp = await this._postForm(postUrl, body, { Referer: signin.url }, (response) =>
      !loginCompletionRedirect(response.statusCode, response.request.uri.href, response.headers.location),
    );
    // The new Auth0 flow interjects per-account one-time or recurring
    // flow-state pages (/v2/login/ui/{country,terms-and-conditions,consent,
    // marketing-consent}) between the password POST and the OIDC callback.
    // Advance through them automatically: re-posting the embedded form with
    // decision=allow for the data-sharing flow pages, and routing marketing
    // to its /skip endpoint instead of consenting. One-shot per page type,
    // max 6 hops as a safety cap.
    const seen = new Set();
    for (let i = 0; i < 6; i++) {
      const next = classifyFlowState(resp.url);
      if (!next || seen.has(next.key)) break;
      seen.add(next.key);
      resp = await this._postFlowState(resp, next);
    }
    return resp;
  }

  /**
   * Post the embedded form of a /v2/login/ui/<page> response. For country/
   * terms-and-conditions/consent we send decision=allow (plus country code
   * or consentedScopes derived from the page HTML). For marketing-consent we
   * route to .../marketing-consent/skip which the SPA uses for "Not now",
   * carrying the channel defaults the page embeds so the backend records a
   * no-consent and moves on.
   */
  async _postFlowState(prev, kind) {
    let targetUrl;
    let body;
    if (kind.key === "marketing-consent") {
      // Marketing-consent is a React SPA that renders no <form>/<input>
      // into static HTML; its "Not now" POSTs to .../skip with values
      // derived from window._IDK.Data (channels + mdKey + mdLanguage).
      const data = extractIdkData(prev.body);
      if (!data) {
        throw new Error("marketing-consent page has no _IDK data - portal layout may have changed");
      }
      body = buildMarketingSkipBody(data);
      targetUrl = new URL("marketing-consent/skip", prev.url).toString();
    } else {
      const parsed = loginFields(prev.body);
      body = { ...parsed.fields, decision: "allow" };
      targetUrl = parsed.action ? new URL(parsed.action, prev.url).toString() : prev.url.split("?", 1)[0];
      if (kind.key === "country" && !body.countryOfResidence) {
        body.countryOfResidence = (this.country || "de").toUpperCase();
      }
      if (kind.key === "consent" && !body.consentedScopes) {
        body.consentedScopes = extractConsentedScopes(prev.body) || "profile,cars";
      }
    }
    this.log.debug(`[euDataAct] auth0 flow-state: posting ${kind.key} -> ${targetUrl}`);
    return this._postForm(targetUrl, body, { Referer: prev.url }, (response) =>
      !loginCompletionRedirect(response.statusCode, response.request.uri.href, response.headers.location),
    );
  }

  async _getJson(url, headers, _retried = false) {
    const gen = this._loginGen;
    const r = await this._getText(url, { Accept: "application/json", ...(headers || {}) });
    // Standard auth-failure: re-login + retry once.
    // AEM session expiry: the portal sits behind Adobe AEM, which on an
    // expired session returns HTTP 500 with an HTML error page (NOT JSON
    // and NOT a clean 401). Detect via "5xx + body starts with '<'" and
    // treat it as the same case. A genuine backend 5xx that returns JSON
    // (or empty body) still propagates immediately.
    const looksLikeAemHtml = r.status >= 500 && r.body && r.body.trimStart().startsWith("<");
    if ((r.status === 401 || r.status === 403 || looksLikeAemHtml) && !_retried) {
      if (looksLikeAemHtml) {
        // Info-level, not warn: a 500+HTML can be either AEM session expiry
        // (which re-login fixes) or a transient backend hiccup (which it
        // doesn't). The caller's 15-min backoff handles the retry strategy
        // either way; this log just announces what we're trying.
        this.log.info(
          `[euDataAct] HTTP ${r.status} with HTML body on ${url} — re-login + retry`,
        );
      }
      await this.login(gen);
      return this._getJson(url, headers, true);
    }
    if (r.status >= 400) {
      throw new Error(`GET ${url} -> HTTP ${r.status} body=${r.body.substring(0, 300)}`);
    }
    try {
      return JSON.parse(r.body);
    } catch (err) {
      throw new Error(`Invalid JSON from ${url}: ${err.message} body=${r.body.substring(0, 300)}`, {
        cause: err,
      });
    }
  }

  async ensureLogin() {
    if (!this._loggedIn) await this.login();
  }

  async listVehicles() {
    await this.ensureLogin();
    const payload = await this._getJson(`${BASE_URL}${VEHICLES_PATH}?viewPosition=FRONT_LEFT`);
    const vehicles = extractVins(payload);
    for (const v of vehicles) {
      try {
        const rel = await this._getJson(`${BASE_URL}${RELATION_PATH.replace("{vin}", v.vin)}`, {
          traceid: `vehicle-relation-fetch-${crypto.randomUUID()}`,
        });
        const nickname = (rel.relation || {}).vehicleNickname;
        if (nickname) v.nickname = nickname;
      } catch (err) {
        this.log.debug(`[euDataAct] relation lookup for ${v.vin} failed: ${err.message}`);
      }
    }
    return vehicles;
  }

  async getMetadata(vin) {
    await this.ensureLogin();
    return this._getJson(`${BASE_URL}${METADATA_PATH.replace("{vin}", vin)}`);
  }

  async listDatasets(vin, identifier) {
    await this.ensureLogin();
    const url = `${BASE_URL}${LIST_PATH.replace("{vin}", vin).replace("{identifier}", identifier)}`;
    const data = await this._getJson(url, { type: "partial" });
    return Array.isArray(data) ? data : data.files || [];
  }

  async downloadDataset(vin, identifier, name, _retried = false) {
    await this.ensureLogin();
    if (name.endsWith(NO_CONTENT_SUFFIX)) {
      throw new Error(`${name} contains no content`);
    }
    const url = `${BASE_URL}${DOWNLOAD_PATH.replace("{vin}", vin).replace("{identifier}", identifier)}`;
    const gen = this._loginGen;
    const r = await this._getBuffer(url, { filename: name, type: "partial" });
    // Same AEM-session-expiry detection as in _getJson: a 5xx with an HTML
    // body (response starts with '<') is the portal's way of saying the
    // session is gone. The download endpoint normally returns a binary ZIP
    // (which would NOT start with '<'), so this is unambiguous.
    const buf = Buffer.isBuffer(r.body) ? r.body : Buffer.from(r.body || "");
    const looksLikeAemHtml = r.status >= 500 && buf.length > 0 && buf[0] === 0x3c; // '<'
    if ((r.status === 401 || r.status === 403 || looksLikeAemHtml) && !_retried) {
      if (looksLikeAemHtml) {
        this.log.info(
          `[euDataAct] HTTP ${r.status} with HTML body on download — re-login + retry`,
        );
      }
      await this.login(gen);
      return this.downloadDataset(vin, identifier, name, true);
    }
    if (r.status >= 400) {
      throw new Error(`Download ${name} -> HTTP ${r.status}`);
    }
    const unzipped = unzipFirstJson(r.body, name);
    return { ...unzipped, byteSize: r.body.length };
  }
}

module.exports = {
  EuDataActClient,
  SUPPORTED_BRANDS: Object.keys(BRAND_CLIENT_IDS),
  normalizeDataset,
  parseValue,
  loadDictionary,
  // exported for tests
  _internal: { extractVins, loginFields, loginErrorText, unzipFirstJson, marketingConsentCallback, classifyFlowState, extractIdkData, extractConsentedScopes, buildMarketingSkipBody },
};
