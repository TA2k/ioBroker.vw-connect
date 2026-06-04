"use strict";

/**
 * Tibber Data API client.
 *
 * Tibber is a commercial third party that has direct OAuth access to the
 * VW Group fleet API and exposes vehicle telemetry (SoC, range, plug,
 * charging) under their Data API. This client implements the auth-code +
 * PKCE OAuth2 flow, mirrors what evcc does in its Tibber vehicle plugin
 * (see PR evcc-io/evcc#30487), and reads the device endpoint.
 *
 *   docs:    https://data-api.tibber.com/docs/
 *   auth:    https://thewall.tibber.com/connect/authorize  (PKCE required)
 *   token:   https://thewall.tibber.com/connect/token
 *   data:    https://data-api.tibber.com/v1
 *
 * Tibber's authorize endpoint requires a `code_challenge` (S256 PKCE).
 * To keep the user setup simple and the URL pre-computable in the admin
 * UI, we use a FIXED verifier baked into the adapter. This is technically
 * weaker than per-flow random PKCE but is acceptable here:
 *   - the token endpoint also requires the client_secret, so a leaked
 *     verifier alone is not enough for an attacker.
 *   - rotating the verifier per flow would require a backend round-trip
 *     for the admin UI, which ioBroker config pages don't have.
 * Same trade-off as embedded mobile apps where the verifier is in the
 * APK.
 */

const https = require("https");
const { URLSearchParams } = require("url");

const TOKEN_URL = "https://thewall.tibber.com/connect/token";
const AUTH_URL = "https://thewall.tibber.com/connect/authorize";
const API_BASE = "https://data-api.tibber.com/v1";
// Adapter always uses http://localhost/ — that's the redirect URI users
// register in their Tibber OAuth client. Tibber matches it byte-exact
// (with trailing slash).
const REDIRECT_URI = "http://localhost/";
const SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "data-api-user-read",
  "data-api-homes-read",
  "data-api-vehicles-read",
  "data-api-chargers-read",
  "data-api-energy-systems-read",
  "data-api-thermostats-read",
  "data-api-inverters-read",
].join(" ");

// Fixed PKCE pair. Verifier is the secret known only to this adapter,
// challenge is the SHA-256 base64url hash that gets sent to Tibber's
// authorize endpoint. See module header for the rationale.
//
// IMPORTANT: PKCE_CHALLENGE is duplicated in admin/index_m.html (TIBBER_CHALLENGE
// in the inline script that builds the authorize URL for the user). If you
// change one, change the other or the OAuth flow silently fails with
// invalid_grant on the exchange step.
//   grep -rn 'Oey1jcnhbUa' lib/ admin/
const PKCE_VERIFIER = "9865PlBfOdFKw3itj8kQSAFA0oVs6AVX5oMo5tr7Nts11e9YUHx0_BJrTryw_D7C";
const PKCE_CHALLENGE = "Oey1jcnhbUa_fxI9A2NtdVrIk-QxD-9ARobHcVpOj7A";

// --- Tibber Data API capability ids (verbatim from evcc PR #30487) -------
const CAP_SOC = "storage.stateOfCharge";       // %
const CAP_TARGET_SOC = "storage.targetStateOfCharge"; // %
const CAP_RANGE = "range.remaining";           // distance, typically m
const CAP_CONNECTOR = "connector.status";      // connected/disconnected/unknown
const CAP_CHARGING = "charging.status";        // charging/idle/unknown

const KM_PER_MILE = 1.609344;

// --- HTTP helpers --------------------------------------------------------

function request(url, opts) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request(
      {
        method: opts.method || "GET",
        hostname: u.hostname,
        path: u.pathname + u.search,
        headers: opts.headers || {},
        // Don't hang forever on a stalled Tibber backend — a missing
        // timeout means we rely on the OS TCP timeout (often minutes).
        timeout: 30000,
      },
      (resp) => {
        let body = "";
        resp.on("data", (c) => (body += c));
        resp.on("end", () => resolve({ status: resp.statusCode, body }));
      },
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error(`Tibber request timed out after 30s: ${url}`));
    });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function postForm(url, params) {
  const r = await request(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams(params).toString(),
  });
  if (r.status !== 200) {
    throw new Error(`POST ${url} -> HTTP ${r.status} body=${r.body.slice(0, 300)}`);
  }
  try {
    return JSON.parse(r.body);
  } catch (err) {
    throw new Error(`Invalid JSON from ${url}: ${err.message}`, { cause: err });
  }
}

async function getJson(url, accessToken) {
  const r = await request(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });
  if (r.status === 401) {
    const e = new Error(`GET ${url} -> HTTP 401 (unauthorized)`);
    e.code = "UNAUTHORIZED";
    throw e;
  }
  if (r.status !== 200) {
    throw new Error(`GET ${url} -> HTTP ${r.status} body=${r.body.slice(0, 300)}`);
  }
  try {
    return JSON.parse(r.body);
  } catch (err) {
    throw new Error(`Invalid JSON from ${url}: ${err.message}`, { cause: err });
  }
}

// --- public helpers ------------------------------------------------------

function buildAuthorizeUrl(clientId) {
  const p = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    state: "iobroker",
    code_challenge: PKCE_CHALLENGE,
    code_challenge_method: "S256",
  });
  return `${AUTH_URL}?${p.toString()}`;
}

/**
 * Exchange an authorization code (from the browser-redirect URL) for
 * access_token + refresh_token. Caller is responsible for persisting the
 * refresh_token (Tibber rotates it on every refresh).
 */
async function exchangeCode(clientId, clientSecret, code) {
  return postForm(TOKEN_URL, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    client_secret: clientSecret,
    code_verifier: PKCE_VERIFIER,
  });
}

/**
 * Refresh tokens. Returns {access_token, refresh_token, expires_in, ...}.
 * The new refresh_token replaces the old one (which Tibber invalidates).
 */
async function refreshTokens(clientId, clientSecret, refreshToken) {
  return postForm(TOKEN_URL, {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
  });
}

// --- API surface ---------------------------------------------------------

class TibberClient {
  /**
   * @param {object} opts
   * @param {string} opts.clientId
   * @param {string} opts.clientSecret
   * @param {string} opts.refreshToken      Persisted across restarts.
   * @param {function} opts.onRefreshToken  Called with the NEW refresh_token
   *                                        every time refreshTokens is called.
   *                                        Must persist it durably.
   * @param {object} [opts.log]
   */
  constructor(opts) {
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret;
    this.refreshToken = opts.refreshToken;
    this.onRefreshToken = opts.onRefreshToken || (() => {});
    this.log = opts.log || { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };
    this._accessToken = null;
    this._accessExpiresAt = 0;
  }

  /**
   * Returns a valid access token, refreshing if needed. Persists the new
   * refresh_token via the onRefreshToken callback.
   */
  async _accessTokenFresh() {
    // 60s safety margin so we don't issue a request just as the token
    // expires.
    if (this._accessToken && Date.now() < this._accessExpiresAt - 60000) {
      return this._accessToken;
    }
    if (!this.refreshToken) {
      throw new Error("Tibber: no refresh token available — run the OAuth flow first");
    }
    const tokens = await refreshTokens(this.clientId, this.clientSecret, this.refreshToken);
    if (!tokens.access_token || !tokens.refresh_token) {
      throw new Error(`Tibber refresh response missing tokens: ${JSON.stringify(tokens)}`);
    }
    this._accessToken = tokens.access_token;
    this._accessExpiresAt = Date.now() + (tokens.expires_in || 3600) * 1000;
    this.refreshToken = tokens.refresh_token;
    try {
      await this.onRefreshToken(tokens.refresh_token);
    } catch (err) {
      this.log.warn(`Tibber: refresh-token persistence failed: ${err.message || err}`);
    }
    this.log.debug(
      `[tibber] refreshed access token, expires in ${tokens.expires_in}s, rotated refresh token`,
    );
    return this._accessToken;
  }

  async _get(path) {
    const token = await this._accessTokenFresh();
    try {
      return await getJson(`${API_BASE}${path}`, token);
    } catch (err) {
      // 401 means our cached access token went stale unexpectedly. Force
      // a refresh + retry once.
      if (err && err.code === "UNAUTHORIZED") {
        this._accessToken = null;
        this._accessExpiresAt = 0;
        const token2 = await this._accessTokenFresh();
        return getJson(`${API_BASE}${path}`, token2);
      }
      throw err;
    }
  }

  async listHomes() {
    const r = await this._get("/homes");
    return Array.isArray(r) ? r : (r && Array.isArray(r.homes)) ? r.homes : [];
  }

  async listDevices(homeId) {
    const r = await this._get(`/homes/${encodeURIComponent(homeId)}/devices`);
    return Array.isArray(r) ? r : (r && Array.isArray(r.devices)) ? r.devices : [];
  }

  async getDevice(homeId, deviceId) {
    return this._get(`/homes/${encodeURIComponent(homeId)}/devices/${encodeURIComponent(deviceId)}`);
  }

  /**
   * Walk all homes and return de-duplicated devices (vehicles only when the
   * external_id has a vendor:vin shape, others ignored). Mirrors
   * vehicle/tibber/api.go in evcc.
   */
  async listVehicles() {
    const homes = await this.listHomes();
    const seen = new Set();
    const out = [];
    for (const h of homes) {
      let devices;
      try {
        devices = await this.listDevices(h.id);
      } catch (err) {
        this.log.warn(`[tibber] listDevices(${h.id}) failed: ${err.message || err}`);
        continue;
      }
      for (const d of devices) {
        const key = d.id || d.externalId || d.external_id;
        if (!key || seen.has(key)) continue;
        seen.add(key);
        out.push({ ...d, homeId: h.id, homeName: h.name || h.displayName });
      }
    }
    return out;
  }
}

// --- capability extraction (mirrors evcc tibber/api.go) ------------------

function _findCap(detail, id) {
  const caps = (detail && (detail.capabilities || detail.Capabilities)) || [];
  for (const c of caps) {
    if (c.id === id || c.ID === id) return c;
  }
  return null;
}

function _capNumber(detail, id) {
  const c = _findCap(detail, id);
  if (!c) return null;
  const v = c.value !== undefined ? c.value : c.Value;
  if (v === null || v === undefined) return null;
  const n = typeof v === "number" ? v : parseFloat(v);
  return Number.isFinite(n) ? n : null;
}

function _capString(detail, id) {
  const c = _findCap(detail, id);
  if (!c) return null;
  const v = c.value !== undefined ? c.value : c.Value;
  return typeof v === "string" ? v : null;
}

function _capUnit(detail, id) {
  const c = _findCap(detail, id);
  if (!c) return null;
  return c.unit || c.Unit || null;
}

/**
 * Convert a raw Tibber device-detail response into a flat object suitable
 * for json2iob, with extras (range_km, plug/charging strings) the user
 * actually wants.
 */
function normalizeDevice(detail) {
  const out = {
    id: detail.id || null,
    externalId: detail.externalId || detail.external_id || null,
    homeId: detail.homeId || null,
    homeName: detail.homeName || null,
    info: detail.info || detail.Info || {},
    soc: _capNumber(detail, CAP_SOC),
    targetSoc: _capNumber(detail, CAP_TARGET_SOC),
    plugStatus: _capString(detail, CAP_CONNECTOR),
    chargingStatus: _capString(detail, CAP_CHARGING),
  };
  // Range: API delivers in meters (default), miles or km depending on unit.
  // evcc normalises to km.
  const rRaw = _capNumber(detail, CAP_RANGE);
  if (rRaw !== null) {
    const unit = (_capUnit(detail, CAP_RANGE) || "").toLowerCase();
    if (unit === "m") out.rangeKm = rRaw / 1000;
    else if (unit === "mi" || unit === "mile" || unit === "miles") out.rangeKm = rRaw * KM_PER_MILE;
    else if (unit === "km" || unit === "kilometre" || unit === "kilometres") out.rangeKm = rRaw;
    else out.rangeKm = rRaw / 1000; // assume m as default per evcc comment
  } else {
    out.rangeKm = null;
  }
  // Pass through every capability raw too (under "capabilities") so users
  // who want exotic fields don't have to fork the adapter.
  const rawCaps = {};
  for (const c of detail.capabilities || detail.Capabilities || []) {
    const id = c.id || c.ID;
    if (!id) continue;
    rawCaps[id.replace(/\./g, "_")] = c.value !== undefined ? c.value : c.Value;
  }
  out.capabilities = rawCaps;
  return out;
}

/**
 * Extract a usable, ioBroker-safe identifier from the Tibber device's
 * external_id. Format observed in the wild is "vendor:VIN" (e.g.
 * "tesla:5YJSA1E26MF1234567"); we strip the optional "vendor:" prefix.
 *
 * Returns the bare VIN (or whatever the external_id was after the
 * colon), with characters that ioBroker rejects in object IDs replaced
 * with underscores. Returns null if there's nothing usable so the
 * caller falls back to the device UUID.
 */
function vinFromDevice(d) {
  const ext = d.externalId || d.external_id || "";
  if (!ext) return null;
  const sep = ext.indexOf(":");
  const candidate = (sep >= 0 ? ext.slice(sep + 1) : ext).trim();
  if (!candidate) return null;
  // ioBroker forbids ".", "*", "?", "[", "]", whitespace and a few more
  // in object IDs. Be conservative — keep alnum + dash + underscore.
  return candidate.replace(/[^A-Za-z0-9_-]+/g, "_");
}

module.exports = {
  TibberClient,
  buildAuthorizeUrl,
  exchangeCode,
  refreshTokens,
  normalizeDevice,
  vinFromDevice,
  REDIRECT_URI,
  SCOPES,
  PKCE_CHALLENGE,
  // for tests only
  _internal: { request, postForm, getJson },
};
