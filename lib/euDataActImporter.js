"use strict";

const { AsyncLocalStorage } = require("node:async_hooks");
const Json2iob = require("json2iob");

/**
 * Keep json2iob's object creation and enrichment, but publish vehicle readings
 * with their original measurement time in state.ts. Each parse has its own
 * timestamp map, including when vehicle imports overlap.
 *
 * @param {any} adapter ioBroker adapter instance.
 */
function createEuDataActImporter(adapter) {
  const context = new AsyncLocalStorage();
  const forbiddenChars = adapter.FORBIDDEN_CHARS ||
    new RegExp(String.raw`[^._\-/ :!#$%&()+=@^{}|~\p{Ll}\p{Lu}\p{Nd}]+`, "gu");
  const normalizeId = (id) => id.replace(forbiddenChars, "_");

  const write = (method) => (id, value, ack) => {
    const timestamps = context.getStore();
    const key = normalizeId(id);
    if (timestamps && timestamps.has(key)) {
      // One write for both val and ts; never publish an intermediate import ts.
      // An explicit zero marks a missing/invalid/reconstructed measurement time.
      return adapter[method](id, { val: value, ack, ts: timestamps.get(key) });
    }
    // Package metadata and _meta retain their normal ioBroker publication time.
    return adapter[method](id, value, ack);
  };

  const importer = new Json2iob({
    log: adapter.log,
    FORBIDDEN_CHARS: forbiddenChars,
    extendObjectAsync: adapter.extendObjectAsync.bind(adapter),
    delObjectAsync: adapter.delObjectAsync.bind(adapter),
    setStateAsync: write("setStateAsync"),
    setStateChangedAsync: write("setStateChangedAsync"),
  });

  return {
    parse(path, values, sourceTimestamps, options) {
      const timestamps = new Map();
      const collect = (node, prefix) => {
        for (const [key, value] of Object.entries(node)) {
          const id = `${prefix}.${key}`;
          if (value !== null && typeof value === "object") {
            collect(value, id);
          } else {
            timestamps.set(normalizeId(id), value);
          }
        }
      };
      collect(sourceTimestamps, path);
      return context.run(timestamps, () => importer.parse(path, values, options));
    },
  };
}

module.exports = createEuDataActImporter;
