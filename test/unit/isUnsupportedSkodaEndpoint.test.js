"use strict";

const { expect } = require("chai");
const isUnsupportedSkodaEndpoint = require("../../lib/isUnsupportedSkodaEndpoint");

describe("isUnsupportedSkodaEndpoint", () => {
  it("caches validation errors for unsupported fueling endpoints", () => {
    expect(
      isUnsupportedSkodaEndpoint({ path: "fueling/sessions", postfix: "/state" }, 400, {
        message: "Validation failed",
      }),
    ).to.equal(true);
  });

  it("caches the observed internal error for fueling latest", () => {
    expect(
      isUnsupportedSkodaEndpoint({ path: "fueling/sessions", postfix: "/latest" }, 500, "Internal server error"),
    ).to.equal(true);
  });

  it("caches the observed internal error for charging settings", () => {
    expect(
      isUnsupportedSkodaEndpoint({ path: "charging", postfix: "/settings" }, 500, "Internal server error"),
    ).to.equal(true);
  });

  it("keeps temporary server failures visible for other endpoints", () => {
    expect(
      isUnsupportedSkodaEndpoint({ path: "charging", postfix: "" }, 500, "Internal server error"),
    ).to.equal(false);
  });

  it("does not hide authentication or rate-limit errors", () => {
    const endpoint = { path: "fueling/sessions", postfix: "" };
    expect(isUnsupportedSkodaEndpoint(endpoint, 401, "Unauthorized")).to.equal(false);
    expect(isUnsupportedSkodaEndpoint(endpoint, 429, "Too many requests")).to.equal(false);
  });
});
