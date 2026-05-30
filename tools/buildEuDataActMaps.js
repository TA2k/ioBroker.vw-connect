"use strict";
/**
 * Regenerate lib/euDataActDescriptions.json + lib/euDataActStates.json from
 * lib/euDataActDictionary.json.
 *
 * Both output files are formatted for json2iob's parse() options:
 *
 *   descriptions = { <leaf>: "Friendly description string" }
 *   states       = { <leaf>: { "RAW_ENUM_VALUE": "Pretty Label", ... } }
 *
 * Where <leaf> is the last segment of the dotted dataFieldName from the EU
 * Data Act portal (e.g. "soc" for "battery_state_report.soc"). When several
 * UUIDs in the dictionary share the same leaf, we keep the longest
 * (non-overlapping) description and merge their enum members.
 *
 * Enum labels strip the prefix shared by all members of a leaf
 * ("WINDOW_HEATING_STATE_OFF" -> "Off") then title-case the remainder.
 *
 * Run:
 *   node tools/buildEuDataActMaps.js
 *
 * The dictionary file is rebuilt from the EU Data Act PDF by the upstream
 * Python tool (.docu/hass-vw-eu-data-act/tools/parse_dictionary.py); this
 * Node script ONLY derives the json2iob enrichment maps.
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const DICT_PATH = path.join(ROOT, "lib", "euDataActDictionary.json");
const DESC_OUT = path.join(ROOT, "lib", "euDataActDescriptions.json");
const STATES_OUT = path.join(ROOT, "lib", "euDataActStates.json");

const ENUM_TOKEN_RE = /^[A-Z][A-Z0-9_]*$/;

function parseEnumMembers(description) {
  if (!description) return [];
  const members = description
    .split(",")
    .map((p) => p.replace(/\s+/g, ""))
    .filter((m) => ENUM_TOKEN_RE.test(m));
  return members.length >= 2 ? members : [];
}

function pretty(suffix) {
  return suffix
    .split("_")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(" ");
}

function commonPrefix(strings) {
  if (strings.length < 2) return "";
  const first = strings[0];
  let i = 0;
  while (i < first.length && strings.every((s) => s[i] === first[i])) i++;
  while (i > 0 && first[i - 1] !== "_") i--;
  return first.slice(0, i);
}

function sortDeep(obj) {
  return Object.keys(obj)
    .sort()
    .reduce((acc, k) => {
      acc[k] = obj[k];
      return acc;
    }, {});
}

function build() {
  let raw = fs.readFileSync(DICT_PATH, "utf-8");
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
  const dict = JSON.parse(raw);

  const descriptions = {};
  const stateMembers = {}; // leaf -> Set<member>

  for (const [, meta] of Object.entries(dict)) {
    if (!meta.name) continue;
    const leaf = meta.name.split(".").pop();
    if (!leaf) continue;

    if (meta.description) {
      const desc = meta.description.replace(/\s+/g, " ").trim();
      if (desc) {
        const existing = descriptions[leaf];
        if (!existing || (desc.length > existing.length && !desc.startsWith(existing))) {
          descriptions[leaf] = desc;
        }
      }
    }

    if ((meta.type || "").toLowerCase() === "enum") {
      const members = parseEnumMembers(meta.description);
      if (!members.length) continue;
      if (!stateMembers[leaf]) stateMembers[leaf] = new Set();
      for (const m of members) stateMembers[leaf].add(m);
    }
  }

  const states = {};
  for (const [leaf, set] of Object.entries(stateMembers)) {
    const members = [...set].sort();
    const prefix = commonPrefix(members);
    const map = {};
    for (const m of members) {
      let suffix = m.slice(prefix.length).replace(/^_+/, "");
      if (!suffix) suffix = m;
      map[m] = pretty(suffix);
    }
    states[leaf] = sortDeep(map);
  }

  const sortedDesc = sortDeep(descriptions);
  const sortedStates = sortDeep(states);

  fs.writeFileSync(DESC_OUT, JSON.stringify(sortedDesc, null, 1) + "\n", "utf-8");
  fs.writeFileSync(STATES_OUT, JSON.stringify(sortedStates, null, 1) + "\n", "utf-8");

  console.log(`descriptions:  ${Object.keys(sortedDesc).length} leafs -> ${path.relative(ROOT, DESC_OUT)}`);
  console.log(`states:        ${Object.keys(sortedStates).length} enum leafs -> ${path.relative(ROOT, STATES_OUT)}`);
}

build();
