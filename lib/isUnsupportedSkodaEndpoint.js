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
  if (statusCode === 400 && endpoint.path.startsWith("fueling/")) {
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
