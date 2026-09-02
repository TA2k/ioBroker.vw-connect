"use strict";

/**
 * Škoda official Public API client + API-key management.
 *
 * Škoda introduced an official gateway (https://public.api.connect.skoda-auto.cz)
 * authenticated with a per-vehicle X-API-Key. Keys can be created in the MyŠkoda
 * app OR minted programmatically on the mysmob BFF with an existing MyŠkoda
 * login token (POST /api/v2/public-api-keys). The minted key secret is returned
 * exactly once, so the caller must persist it.
 *
 * This module wraps both:
 *   - key management on the mysmob BFF (listKeys / mintKey), using the Bearer
 *     access token the adapter already holds from the classic skodae login, and
 *   - the public API itself (getStatus / command), using the X-API-Key.
 *
 * Rate limit is 20 requests/hour per key. Every response carries RateLimit-*
 * and (on 429/503) Retry-After; the client tracks a per-VIN self-block so the
 * caller can skip polling instead of burning quota. The X-API-Key-Expires-At
 * header lets the caller renew keys before they lapse.
 *
 * Endpoints/shapes verified against the OpenAPI spec (.docu/newskoda/
 * myskoda-public-api.yaml) and the HA reference (skoda_official.py). The mint
 * endpoint was reached live (GET /api/v2/public-api-keys -> 200 {maxKeys:5});
 * the POST mint + public read shapes come from the reference and the MyŠkoda
 * 8.16 APK.
 */

const axios = require("axios");

const PUBLIC_BASE = "https://public.api.connect.skoda-auto.cz/api/v1";
const MYSMOB_BASE = "https://mysmob.api.connect.skoda-auto.cz";
// Spoof the app UA in case key management is gated on a minimum app version.
const KEYGEN_UA = "MySkoda/Android/8.16.0/260821007";
const KEY_NAME = "ioBroker vw-connect";

const NOOP_LOG = { info() {}, warn() {}, error() {}, debug() {} };

class SkodaPublicApi {
  /**
   * @param {object} [opts]
   * @param {object} [opts.log] logger with debug/info/warn/error
   */
  constructor(opts = {}) {
    this.log = opts.log || NOOP_LOG;
    // per-VIN self-block until epoch ms; poll callers check overRateLimit(vin)
    this._blockedUntil = {};
    // per-VIN key expiry (epoch ms) from X-API-Key-Expires-At
    this.keyExpiresAt = {};
  }

  /**
   * @param {string} vin
   * @returns {boolean} true while the VIN is rate-limit self-blocked
   */
  overRateLimit(vin) {
    return Date.now() < (this._blockedUntil[(vin || "").toUpperCase()] || 0);
  }

  /**
   * Read the current public-API key inventory (max 5/VIN, per-VIN keysRemaining).
   * No key secrets are returned here.
   *
   * @param {string} bearer mysmob access token
   * @returns {Promise<object>} {maxKeys, vehicleKeys:[{vin, keysRemaining}]}
   */
  async listKeys(bearer) {
    const res = await axios({
      method: "get",
      url: MYSMOB_BASE + "/api/v2/public-api-keys",
      headers: {
        accept: "application/json",
        "user-agent": KEYGEN_UA,
        authorization: "Bearer " + bearer,
      },
    });
    return res.data;
  }

  /**
   * Mint a public API key bound to one VIN. The `key` secret is returned only
   * here — persist it. Returns null on failure (gated / quota / not owned).
   *
   * @param {string} bearer mysmob access token
   * @param {string} vin
   * @returns {Promise<{id: string, key: string, name: string, validUntil: string}|null>}
   */
  async mintKey(bearer, vin) {
    try {
      const res = await axios({
        method: "post",
        url: MYSMOB_BASE + "/api/v2/public-api-keys",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "user-agent": KEYGEN_UA,
          authorization: "Bearer " + bearer,
        },
        data: { name: KEY_NAME, vin: vin },
      });
      if (res.data && res.data.key) {
        return res.data;
      }
      this.log.warn("Skoda API key mint returned no key for " + vin);
      return null;
    } catch (error) {
      const status = error.response && error.response.status;
      this.log.warn(
        "Skoda API key mint failed for " + vin + ": HTTP " + status + " " +
          JSON.stringify((error.response && error.response.data) || error.message),
      );
      return null;
    }
  }

  /**
   * GET the full vehicle state from the public API.
   *
   * @param {string} vin
   * @param {string} key X-API-Key bound to this VIN
   * @returns {Promise<{ok: boolean, status: number, data: object|null, expired: boolean, rateLimited: boolean}>}
   */
  async getStatus(vin, key) {
    try {
      const res = await axios({
        method: "get",
        url: PUBLIC_BASE + "/vehicles/" + vin,
        headers: { accept: "application/json", "x-api-key": key, "user-agent": "ioBroker.vw-connect" },
      });
      this._noteRateLimit(vin, res);
      // VehicleResponse wraps the vehicle; errors[] describes omitted parts.
      const data = (res.data && (res.data.vehicle || res.data)) || null;
      const errors = (res.data && res.data.errors) || [];
      if (errors.length) {
        this.log.debug("Skoda public API partial data for " + vin + ": " + JSON.stringify(errors));
      }
      return { ok: true, status: res.status, data, expired: false, rateLimited: false };
    } catch (error) {
      return this._handleError(vin, error, "getStatus");
    }
  }

  /**
   * Send a remote command (POST). Success on 2xx.
   *
   * @param {string} vin
   * @param {string} key X-API-Key
   * @param {string} path e.g. "charging/start", "air-conditioning/start"
   * @param {object} [body] optional JSON body (target temperature, spin, …)
   * @returns {Promise<{ok: boolean, status: number, expired: boolean, rateLimited: boolean}>}
   */
  async command(vin, key, path, body) {
    try {
      const res = await axios({
        method: "post",
        url: PUBLIC_BASE + "/vehicles/" + vin + "/" + path,
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "x-api-key": key,
          "user-agent": "ioBroker.vw-connect",
        },
        data: body || {},
      });
      this._noteRateLimit(vin, res);
      return { ok: true, status: res.status, expired: false, rateLimited: false };
    } catch (error) {
      const r = this._handleError(vin, error, "command " + path);
      return { ok: false, status: r.status, expired: r.expired, rateLimited: r.rateLimited };
    }
  }

  // --- internals -----------------------------------------------------------

  _noteRateLimit(vin, res) {
    const h = (res && res.headers) || {};
    const v = (vin || "").toUpperCase();
    const exp = h["x-api-key-expires-at"];
    if (exp) {
      const t = Date.parse(exp);
      if (!Number.isNaN(t)) this.keyExpiresAt[v] = t;
    }
    const remaining = parseInt(h["ratelimit-remaining"], 10);
    const reset = parseInt(h["ratelimit-reset"], 10);
    // When the window is exhausted, self-block until it resets so we never
    // exceed the 20/hour quota.
    if (remaining === 0 && !Number.isNaN(reset)) {
      this._blockedUntil[v] = Date.now() + reset * 1000;
    }
  }

  _handleError(vin, error, where) {
    const v = (vin || "").toUpperCase();
    const resp = error.response;
    const status = (resp && resp.status) || 0;
    // honor Retry-After on 429/503
    const retryAfter = resp && resp.headers && parseInt(resp.headers["retry-after"], 10);
    if ((status === 429 || status === 503) && !Number.isNaN(retryAfter)) {
      this._blockedUntil[v] = Date.now() + retryAfter * 1000;
    } else if (status === 429) {
      // no header -> back off a conservative 5 min
      this._blockedUntil[v] = Date.now() + 5 * 60 * 1000;
    }
    const problem = (resp && resp.data && resp.data.type) || "";
    const expired = status === 401 && /api-key-expired/.test(problem);
    if (status === 401) {
      this.log.debug("Skoda public API " + where + " 401 for " + vin + " (" + (problem || "unauthorized") + ")");
    } else if (status !== 429) {
      this.log.debug(
        "Skoda public API " + where + " failed for " + vin + ": HTTP " + status + " " +
          JSON.stringify((resp && resp.data) || error.message),
      );
    }
    return { ok: false, status, data: null, expired, rateLimited: status === 429 };
  }
}

module.exports = SkodaPublicApi;
