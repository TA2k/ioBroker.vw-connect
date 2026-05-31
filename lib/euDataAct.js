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
const request = require("request");

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

const USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

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
  const formMatch = /<form\b[^>]*\baction=("[^"]*"|'[^']*'|[^\s>]+)[^>]*>([\s\S]*?)<\/form>/i.exec(html);
  if (!formMatch) return { action: null, fields: {} };
  const action = formMatch[1].replace(/^['"]|['"]$/g, "");
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
  // Last resort: include the URL so the user can paste it into a browser
  // and see what the portal is complaining about.
  return `Login failed (no error code reported by IdP). Landing URL: ${landing.url}`;
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

/**
 * Convert the flat `Data: [{key, dataFieldName, value}]` array into a nested
 * object keyed by the dotted dataFieldName, with values typed via the
 * dictionary. When the same field name appears multiple times (the portal
 * merges several report snapshots into one array), we keep the entry with the
 * smallest UUID — same arbitrary-but-stable choice as the HA reference, so a
 * sensor consistently tracks the same point across refreshes.
 */
function normalizeDataset(payload) {
  const dictionary = loadDictionary();
  const points = {};
  for (const item of payload.Data || []) {
    if (!item || !item.key) continue;
    const meta = dictionary[item.key] || {};
    const fieldName = item.dataFieldName || meta.name || item.key;
    if (!fieldName) continue;
    if (!points[fieldName]) {
      points[fieldName] = { keys: [item.key], item, meta };
      continue;
    }
    const cur = points[fieldName];
    cur.keys.push(item.key);
    if (item.key < cur.item.key) {
      cur.item = item;
      cur.meta = meta;
    }
  }

  const out = {};
  for (const fieldName of Object.keys(points)) {
    const { item, meta } = points[fieldName];
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
   */
  constructor(opts) {
    this.email = opts.email;
    this.password = opts.password;
    this.brand = opts.brand || DEFAULT_BRAND;
    this.country = opts.country || "de";
    this.language = opts.language || "en";
    this.log = opts.log || { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };
    this.jar = request.jar();
    this._loggedIn = false;
  }

  _state() {
    return `${this.country}__${this.language}__${this.brand}`;
  }

  _req(opts) {
    return new Promise((resolve, reject) => {
      request({ jar: this.jar, gzip: true, ...opts }, (err, resp, body) => {
        if (err) return reject(err);
        resolve({ resp, body });
      });
    });
  }

  async _getText(url, headers) {
    const startedAt = Date.now();
    const { resp, body } = await this._req({
      method: "GET",
      url,
      headers: { "User-Agent": USER_AGENT, ...(headers || {}) },
    });
    const text = String(body || "");
    this.log.debug(
      `[euDataAct] GET ${url} -> ${resp.statusCode} (${text.length}B, ${Date.now() - startedAt}ms)`,
    );
    return { status: resp.statusCode, url: resp.request.uri.href, body: text, headers: resp.headers };
  }

  async _postForm(url, form, headers) {
    const startedAt = Date.now();
    const { resp, body } = await this._req({
      method: "POST",
      url,
      form,
      followAllRedirects: true,
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
   * Run the full OIDC code flow. Cookies stored in this.jar are used for
   * subsequent proxy_api calls.
   */
  async login() {
    // 0. prime the portal session — sets the AEM cookies the callback needs.
    try {
      await this._getText(BASE_URL + "/");
    } catch (err) {
      this.log.debug("[euDataAct] priming GET failed (ignored): " + err.message);
    }

    // 1. start OIDC at the IdP directly (the portal's redirect servlet 500s
    //    for non-browser clients).
    const authorizeUrl = this.buildAuthorizeUrl();
    this.log.debug("[euDataAct] step1: GET " + authorizeUrl);
    const signin = await this._getText(authorizeUrl);
    if (signin.status !== 200) {
      throw new Error(`Authorize returned HTTP ${signin.status}`);
    }

    // 2. POST email (identifier step). Form fields come from HTML inputs
    //    plus the JS templateModel (hmac, _csrf, relayState).
    let { fields, action } = loginFields(signin.body);
    if (!fields.hmac || !fields._csrf) {
      throw new Error("Could not parse signin form (missing hmac/_csrf) - portal layout may have changed");
    }
    fields.email = this.email;
    const identifierAction = new URL(action || "", signin.url).toString();
    const auth = await this._postForm(identifierAction, fields, { Referer: signin.url });
    this.log.debug(`[euDataAct] step2: status=${auth.status} url=${auth.url}`);

    // 3. POST password (authenticate step).
    ({ fields, action } = loginFields(auth.body));
    if (!fields.hmac || !fields._csrf) {
      const err = loginErrorText(auth.body);
      throw new Error(err || "Identity portal did not return password form (check email)");
    }
    fields.email = this.email;
    fields.password = this.password;
    const authenticateAction = action ? new URL(action, auth.url).toString() : auth.url.split("?", 1)[0];
    const landing = await this._postForm(authenticateAction, fields, { Referer: auth.url });
    if (landing.status >= 400) {
      const err = loginErrorText(landing.body);
      throw new Error(err || `Login rejected (HTTP ${landing.status})`);
    }
    if (landing.url.includes("signin-service") || landing.url.includes("/error")) {
      throw new Error(diagnoseLoginFailure(landing));
    }
    if (new URL(landing.url).host !== new URL(BASE_URL).host) {
      throw new Error("Login did not complete (ended at " + landing.url + ")");
    }
    this._loggedIn = true;
    this.log.debug("[euDataAct] login OK, landed at " + landing.url);
  }

  async _getJson(url, headers, _retried = false) {
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
        this.log.warn(
          `[euDataAct] HTTP ${r.status} with HTML body on ${url} — treating as AEM session expiry, re-login + retry`,
        );
      }
      this._loggedIn = false;
      await this.login();
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
    const r = await this._getBuffer(url, { filename: name, type: "partial" });
    // Same AEM-session-expiry detection as in _getJson: a 5xx with an HTML
    // body (response starts with '<') is the portal's way of saying the
    // session is gone. The download endpoint normally returns a binary ZIP
    // (which would NOT start with '<'), so this is unambiguous.
    const buf = Buffer.isBuffer(r.body) ? r.body : Buffer.from(r.body || "");
    const looksLikeAemHtml = r.status >= 500 && buf.length > 0 && buf[0] === 0x3c; // '<'
    if ((r.status === 401 || r.status === 403 || looksLikeAemHtml) && !_retried) {
      if (looksLikeAemHtml) {
        this.log.warn(
          `[euDataAct] HTTP ${r.status} with HTML body on download — treating as AEM session expiry, re-login + retry`,
        );
      }
      this._loggedIn = false;
      await this.login();
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
  normalizeDataset,
  parseValue,
  loadDictionary,
  // exported for tests
  _internal: { extractVins, loginFields, loginErrorText, unzipFirstJson },
};
