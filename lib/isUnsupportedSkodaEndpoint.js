"use strict";

/**
 * Detect endpoint responses which mean that a service is not available for the
 * vehicle, rather than a temporary backend outage.
 *
 * @param {{path: string, postfix: string}} endpoint API endpoint descriptor
 * @param {number} statusCode HTTP response status
 * @param {unknown} responseData HTTP response body
 * @returns {boolean} whether the endpoint should be ignored until adapter restart
 */
function isUnsupportedSkodaEndpoint(endpoint, statusCode, responseData) {
  // 400 (e.g. "Request data validation failed") means the endpoint is not
  // usable for this vehicle / URL shape. Client error, never transient, so
  // stop polling it until restart instead of spamming the log.
  if (statusCode === 400) {
    return true;
  }

  if (statusCode !== 500 || !JSON.stringify(responseData).includes("Internal server error")) {
    return false;
  }

  return (
    (endpoint.path === "fueling/sessions" && endpoint.postfix === "/latest") ||
    (endpoint.path === "charging" && endpoint.postfix === "/settings")
  );
}

module.exports = isUnsupportedSkodaEndpoint;
