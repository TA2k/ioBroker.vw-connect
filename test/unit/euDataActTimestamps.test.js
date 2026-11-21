"use strict";

const assert = require("node:assert/strict");
const Json2iob = require("json2iob");
const createEuDataActImporter = require("../../lib/euDataActImporter");
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

  function fixture(beforeExtend = async (_id) => {}) {
    const states = {};
    const objects = {};
    const writes = [];
    const adapter = {
      log: { debug() {}, error(message) { throw new Error(message); } },
      async extendObjectAsync(id, object) {
        objects[id] = object;
        await beforeExtend(id);
      },
      async delObjectAsync() {},
      async setStateAsync(id, value, ack) {
        const state = typeof value === "object" && value !== null ? { ...value } : { val: value, ack, ts: Date.now() };
        states[id] = state;
        writes.push({ id, state });
      },
    };
    const importer = createEuDataActImporter(adapter);
    const publish = (Data, base = "TESTVIN.statuseudata", options = {}) => {
      const { _timestamps, ...values } = normalizeDataset({ Data });
      const payload = { ...values, _dataset_created_on: "2026-11-19T14:42:00Z" };
      return importer.parse(base, payload, _timestamps, { forceIndex: true, ...options });
    };
    return { states, objects, writes, adapter, publish };
  }

  it("writes val and source ts together, with the original value metadata", async () => {
    const { states, objects, writes, publish } = fixture();
    const base = "TESTVIN.statuseudata";
    const valueStates = { charging_state: { charging: "Charging" } };
    await publish([reading("charging_state", "charging")], base, {
      states: valueStates,
      descriptions: { charging_state: "Charging status" },
    });
    assert.deepEqual(states[`${base}.charging_state`], { val: "charging", ack: true, ts: sourceTimestamp });
    assert.equal(objects[`${base}.charging_state`].common.name, "Charging status");
    assert.equal(objects[`${base}.charging_state`].common.type, "string");
    assert.ok(!objects[`${base}.charging_state`].common.write);
    assert.deepEqual(objects[`${base}.charging_state`].common.states, valueStates.charging_state);
    assert.equal(writes.filter(({ id }) => id === `${base}.charging_state`).length, 1);
    assert.equal(Object.keys(states).some((id) => id.includes("._timestamps")), false);
    assert.ok(states[`${base}._dataset_created_on`].ts > sourceTimestamp);
    assert.equal(states[`${base}._dataset_created_on`].val, "2026-11-19T14:42:00Z");
    assert.ok(states[`${base}._meta.points`].ts > sourceTimestamp);
  });

  it("keeps an old ts on repeated imports and advances ts for a new measurement with the same value", async () => {
    const { states, writes, publish } = fixture();
    const id = "TESTVIN.statuseudata.state_of_charge";
    await publish([reading("state_of_charge", "82")]);
    await publish([reading("state_of_charge", "82")]);
    assert.deepEqual(writes.filter((write) => write.id === id).map((write) => write.state.ts), [sourceTimestamp, sourceTimestamp]);
    const nextSourceTime = "2026-11-18T10:00:00Z";
    await publish([reading("state_of_charge", "82", nextSourceTime)]);
    assert.deepEqual(states[id], { val: 82, ack: true, ts: Date.parse(nextSourceTime) });
    assert.equal(Object.keys(states[id]).includes("lc"), false);
  });

  it("writes ts zero for unknown or reconstructed measurement times and recovers on a valid reading", async () => {
    const { states, publish } = fixture();
    const id = "TESTVIN.statuseudata.state_of_charge";
    await publish([reading("state_of_charge", "82")]);
    for (const timestampUtc of [undefined, null, "", "invalid-date"]) {
      await publish([{ ...reading("state_of_charge", "85"), timestampUtc }]);
      assert.deepEqual(states[id], { val: 85, ack: true, ts: 0 });
    }
    await publish([
      reading("cruising_range_primary_engine", "100"),
      reading("cruising_range_secondary_engine", "200"),
    ]);
    assert.deepEqual(states["TESTVIN.statuseudata.cruising_range_combined"], { val: 300, ack: true, ts: 0 });
    await publish([reading("state_of_charge", "82")]);
    assert.deepEqual(states[id], { val: 82, ack: true, ts: sourceTimestamp });
  });

  it("retains the complete previous state when the next dataset only contains sentinels", async () => {
    const { states, writes, publish } = fixture();
    const id = "TESTVIN.statuseudata.state_of_charge";
    await publish([reading("state_of_charge", "82")]);
    await publish([reading("state_of_charge", "65535", "2026-11-18T10:00:00Z")]);
    assert.deepEqual(states[id], { val: 82, ack: true, ts: sourceTimestamp });
    assert.equal(writes.filter((write) => write.id === id).length, 1);
  });

  it("sets native ts on nested, aliased, colliding and sanitized state paths", async () => {
    const { states, publish } = fixture();
    await publish([
      reading("battery_state_report.soc", "82"),
      reading("charging_plug1_connectionstate", "connected"),
      reading("mileage", "20000"),
      reading("mileage.value", "20000"),
      reading("profiles[*].enabled", "true"),
    ]);
    for (const path of ["battery_state_report.soc", "plug_state", "mileage._value", "mileage.value", "profiles_.enabled"]) {
      assert.equal(states[`TESTVIN.statuseudata.${path}`].ts, sourceTimestamp);
    }
    assert.equal(states["TESTVIN.statuseudata.battery_state_report.soc"].val, 82);
    assert.equal(states["TESTVIN.statuseudata.profiles_.enabled"].val, true);
  });

  it("isolates timestamps of overlapping imports and leaves other importers untouched", async () => {
    let releaseFirst = () => {};
    let firstStarted = () => {};
    const gate = new Promise((resolve) => { releaseFirst = () => resolve(undefined); });
    const started = new Promise((resolve) => { firstStarted = () => resolve(undefined); });
    const { states, adapter, publish } = fixture(async (id) => {
      if (id === "FIRST.statuseudata.state_of_charge") {
        firstStarted();
        await gate;
      }
    });
    const first = publish([reading("state_of_charge", "82")], "FIRST.statuseudata");
    await started;
    const otherTime = "2026-11-18T10:00:00Z";
    await publish([reading("state_of_charge", "90", otherTime)], "SECOND.statuseudata");
    const ordinaryImporter = new Json2iob(adapter);
    await ordinaryImporter.parse("OTHER.status", { state_of_charge: 95 });
    releaseFirst();
    await first;
    assert.deepEqual(states["FIRST.statuseudata.state_of_charge"], { val: 82, ack: true, ts: sourceTimestamp });
    assert.deepEqual(states["SECOND.statuseudata.state_of_charge"], { val: 90, ack: true, ts: Date.parse(otherTime) });
    assert.equal(states["OTHER.status.state_of_charge"].val, 95);
    assert.ok(states["OTHER.status.state_of_charge"].ts > sourceTimestamp);
  });
});
