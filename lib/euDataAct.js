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
const OIDC_CLIENT_ID = "9b58543e-1c15-4193-91d5-8a14145bebb0@apps_vw-dilab_com";
const OIDC_SCOPE = "openid cars profile";
const OIDC_REDIRECT_URI = BASE_URL + "/login";
const BRAND = "VOLKSWAGEN_PASSENGER_CARS";

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

// --- value parsing (mirrors data.py.parse_value) ---------------------------

const _DURATION_RE = /^(-?\d+(?:\.\d+)?)\s*s$/i;
const _INT_RE = /^-?\d+$/;
const _FLOAT_RE = /^-?\d+\.\d+$/;
const _ENUM_TOKEN_RE = /^[A-Z][A-Z0-9_]*$/;

function parseValue(raw, typeHint) {
  if (raw == null) return null;
  const s = String(raw).trim();
  if (s === "") return null;
  const hint = (typeHint || "").toLowerCase();

  if (hint === "boolean" || s.toLowerCase() === "true" || s.toLowerCase() === "false") {
    return s.toLowerCase() === "true";
  }
  if ((hint === "int" || hint === "integer") && _INT_RE.test(s)) return parseInt(s, 10);
  if (hint === "float") {
    const f = parseFloat(s);
    return Number.isFinite(f) ? f : s;
  }
  const dur = _DURATION_RE.exec(s);
  if (dur) return parseFloat(dur[1]);
  if (_INT_RE.test(s)) return parseInt(s, 10);
  if (_FLOAT_RE.test(s)) return parseFloat(s);
  return s;
}

function enumMembers(description) {
  if (!description) return [];
  const members = description
    .split(",")
    .map((p) => p.replace(/\s+/g, ""))
    .filter((m) => _ENUM_TOKEN_RE.test(m));
  return members.length >= 2 ? members : [];
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
  const vins = {};
  function walk(node) {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (node && typeof node === "object") {
      const vin = node.vin || node.vehicleIdentificationNumber;
      if (typeof vin === "string" && vin.length === 17) {
        if (!vins[vin]) vins[vin] = { vin };
        const nick = node.vehicleNickname || node.nickname || node.modelName;
        if (nick) vins[vin].nickname = nick;
      }
      for (const v of Object.values(node)) walk(v);
    }
  }
  walk(payload);
  return Object.values(vins);
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
    if ((meta.type || "").toLowerCase() === "enum" && typeof value === "number") {
      const members = enumMembers(meta.description);
      if (value >= 0 && value < members.length) value = members[value];
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
   * @param {string} [opts.country]   default "si"
   * @param {string} [opts.language]  default "sl"
   * @param {object} [opts.log]       ioBroker-like logger ({info,warn,error,debug})
   */
  constructor(opts) {
    this.email = opts.email;
    this.password = opts.password;
    this.country = opts.country || "si";
    this.language = opts.language || "sl";
    this.log = opts.log || { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };
    this.jar = request.jar();
    this._loggedIn = false;
  }

  _state() {
    return `${this.country}__${this.language}__${BRAND}`;
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
    const params = new URLSearchParams({
      client_id: OIDC_CLIENT_ID,
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
      throw new Error("Login failed - check email and password");
    }
    if (new URL(landing.url).host !== new URL(BASE_URL).host) {
      throw new Error("Login did not complete (ended at " + landing.url + ")");
    }
    this._loggedIn = true;
    this.log.debug("[euDataAct] login OK, landed at " + landing.url);
  }

  async _getJson(url, headers, _retried = false) {
    const r = await this._getText(url, { Accept: "application/json", ...(headers || {}) });
    if ((r.status === 401 || r.status === 403) && !_retried) {
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
    if ((r.status === 401 || r.status === 403) && !_retried) {
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

  /**
   * Convenience: download newest content dataset and return both the raw
   * payload and the structured object suitable for json2iob.
   */
  async getLatestStatus(vin, identifier) {
    const datasets = await this.listDatasets(vin, identifier);
    const contentDatasets = datasets.filter((d) => d && d.name && !d.name.endsWith(NO_CONTENT_SUFFIX));
    const newest = contentDatasets
      .slice()
      .sort((a, b) => String(b.createdOn || b.name).localeCompare(String(a.createdOn || a.name)))[0];
    this.log.debug(
      `[euDataAct] ${vin} list: ${datasets.length} datasets total, ${contentDatasets.length} with content`,
    );
    if (!newest) {
      const error = new Error("No content datasets available yet");
      error.code = "NO_CONTENT";
      throw error;
    }
    const { fileName, json, byteSize } = await this.downloadDataset(vin, identifier, newest.name);
    return {
      datasetName: newest.name,
      datasetCreatedOn: newest.createdOn || null,
      datasetCount: datasets.length,
      contentCount: contentDatasets.length,
      byteSize,
      fileName,
      raw: json,
      normalized: normalizeDataset(json),
    };
  }
}

module.exports = {
  EuDataActClient,
  normalizeDataset,
  parseValue,
  enumMembers,
  loadDictionary,
  // exported for tests
  _internal: { extractVins, loginFields, loginErrorText, unzipFirstJson },
};
