import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  buildOverviewCards,
  defaultOverviewCardOrder,
  overviewCardDefinitions
} from "../src/overviewLayout.ts";
import { readStyles } from "./read-styles.mjs";

const view = await readFile(
  new URL("../src/views/OverviewView.vue", import.meta.url),
  "utf8"
);
const styles = await readStyles();
const cards = buildOverviewCards(defaultOverviewCardOrder);

assert.deepEqual(
  overviewCardDefinitions.map(({ key, baseSpan }) => [key, baseSpan]),
  [
    ["status", 6],
    ["proxy", 6],
    ["speed", 6],
    ["traffic", 6],
    ["dns", 12],
    ["tun", 6],
    ["policy", 6]
  ]
);
assert.deepEqual(cards.map(({ span }) => span), [6, 6, 6, 6, 12, 6, 6]);
assert.match(view, /:style="\{ '--overview-card-span': card\.span \}"/);
assert.doesNotMatch(view, /gridColumn/);
assert.match(
  styles,
  /\.overview-card\s*\{[^}]*grid-column:\s*span var\(--overview-card-span\)/s
);
assert.match(
  styles,
  /@media \(max-width:\s*980px\)[\s\S]*?\.overview-card\s*\{\s*grid-column:\s*1 \/ -1;/
);

console.log("overview layout tests passed");
