"use strict";

const assert = require("node:assert/strict");
const Json2iob = require("json2iob");
const { normalizeDataset } = require("../../lib/euDataAct");

const sourceTime = "2026-11-17T22:46:12.000Z";
const sourceTimestamp = 1794955572000;

function reading(dataFieldName, value, timestampUtc = sourceTime) {
  return { key: "test-field", dataFieldName, value, timestampUtc };
}

describe("EU Data Act source timestamps", () => {
  it("keeps the source time of an unchanged value across different packages", () => {
    for (const createdOn of ["2026-11-19T14:42:00Z", "2026-11-19T14:57:00Z"]) {
      const result = normalizeDataset({
        createdOn,
        Data: [reading("state_of_charge", "82")],
      });
      assert.equal(result.state_of_charge, 82);
      assert.equal(result._timestamps.state_of_charge, sourceTimestamp);
    }
  });

  it("pairs nested and aliased fields with their own source timestamps", () => {
    const result = normalizeDataset({ Data: [
      reading("battery_state_report.soc", "82"),
      reading("charging_plug1_connectionstate", "connected", "2026-11-18T02:00:00+01:00"),
    ] });
    assert.equal(result.battery_state_report.soc, 82);
    assert.equal(result._timestamps.battery_state_report.soc, sourceTimestamp);
    assert.equal(result.plug_state, "connected");
    assert.equal(result._timestamps.plug_state, Date.parse("2026-11-18T01:00:00.000Z"));
  });

  for (const invalid of [undefined, null, "", "invalid-date", 1794955572000]) {
    it(`marks a ${String(invalid)} source timestamp as unknown`, () => {
      const point = { ...reading("state_of_charge", "82"), timestampUtc: invalid };
      const result = normalizeDataset({ Data: [point] });
      assert.equal(result.state_of_charge, 82);
      assert.equal(result._timestamps.state_of_charge, 0);
    });
  }

  it("uses the timestamp of the selected duplicate and monotonic reading", () => {
    const result = normalizeDataset({ Data: [
      reading("state_of_charge", "90", "2026-11-18T10:00:00Z"),
      reading("state_of_charge", "82"),
      reading("mileage.value", "20000"),
      reading("mileage.value", "19990", "2026-11-18T10:00:00Z"),
    ] });
    assert.equal(result.state_of_charge, 82);
    assert.equal(result._timestamps.state_of_charge, sourceTimestamp);
    assert.equal(result.mileage.value, 20000);
    assert.equal(result._timestamps.mileage.value, sourceTimestamp);
  });

  it("keeps usable value/timestamp pairs when duplicate sentinels occur", () => {
    const result = normalizeDataset({ Data: [
      reading("state_of_charge", "65535"),
      reading("state_of_charge", "82"),
      reading("state_of_charge", "65535", "2026-11-18T10:00:00Z"),
      reading("remaining_charging_time", "-1"),
    ] });
    assert.equal(result.state_of_charge, 82);
    assert.equal(result._timestamps.state_of_charge, sourceTimestamp);
    assert.equal(result.remaining_charging_time, undefined);
    assert.equal(result._timestamps.remaining_charging_time, undefined);
  });

  it("marks the source time of a reconstructed range as unknown", () => {
    const result = normalizeDataset({ Data: [
      reading("cruising_range_combined", "65535"),
      reading("cruising_range_primary_engine", "100"),
      reading("cruising_range_secondary_engine", "200"),
    ] });
    assert.equal(result.cruising_range_combined, 300);
    assert.equal(result._timestamps.cruising_range_combined, 0);
  });

  it("mirrors value paths when a field is both a primitive and a parent", () => {
    for (const Data of [
      [reading("mileage", "20000"), reading("mileage.value", "20000")],
      [reading("mileage.value", "20000"), reading("mileage", "20000")],
    ]) {
      const result = normalizeDataset({ Data });
      assert.deepEqual(result.mileage, { _value: 20000, value: 20000 });
      assert.deepEqual(result._timestamps.mileage, { _value: sourceTimestamp, value: sourceTimestamp });
    }
  });

  it("publishes read-only timestamps and clears unknown times through json2iob", async () => {
    const states = {};
    const objects = {};
    const adapter = {
      log: { debug() {}, error(message) { throw new Error(message); } },
      async extendObjectAsync(id, object) { objects[id] = object; },
      async setStateAsync(id, value, ack) { states[id] = { value, ack }; },
    };
    const importer = new Json2iob(adapter);
    const base = "TESTVIN.statuseudata";
    const valueStates = { charging_state: { charging: "Charging" } };
    const publish = async (point) => {
      const { _timestamps, ...values } = normalizeDataset({ Data: [point] });
      await importer.parse(base, values, { forceIndex: true, states: valueStates });
      await importer.parse(`${base}._timestamps`, _timestamps, { forceIndex: true });
    };

    await publish(reading("charging_state", "charging"));
    assert.deepEqual(states[`${base}._timestamps.charging_state`], { value: sourceTimestamp, ack: true });
    assert.equal(objects[`${base}._timestamps.charging_state`].common.type, "number");
    assert.ok(!objects[`${base}._timestamps.charging_state`].common.write);
    assert.equal(objects[`${base}._timestamps.charging_state`].common.states, undefined);
    assert.deepEqual(valueStates.charging_state, { charging: "Charging" });

    await publish({ ...reading("charging_state", "charging"), timestampUtc: null });
    assert.deepEqual(states[`${base}._timestamps.charging_state`], { value: 0, ack: true });
    assert.deepEqual(states[`${base}.charging_state`], { value: "charging", ack: true });

    await publish(reading("charging_state", "65535"));
    assert.deepEqual(states[`${base}._timestamps.charging_state`], { value: 0, ack: true });
    assert.deepEqual(states[`${base}.charging_state`], { value: "charging", ack: true });
  });
});
