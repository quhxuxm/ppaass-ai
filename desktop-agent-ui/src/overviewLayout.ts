import type { OverviewCardDefinition, OverviewCardKey, OverviewCardView } from "./types";

const overviewLayoutKey = "ppaass-agent-ui:overview-card-order:v1";

export const overviewCardDefinitions: OverviewCardDefinition[] = [
  { key: "status", baseSpan: 6 },
  { key: "proxy", baseSpan: 6 },
  { key: "egress", baseSpan: 6 },
  { key: "speed", baseSpan: 6 },
  { key: "traffic", baseSpan: 6 },
  { key: "dns", baseSpan: 6 },
  { key: "tun", baseSpan: 6 },
  { key: "policy", baseSpan: 6 }
];

export const defaultOverviewCardOrder = overviewCardDefinitions.map((card) => card.key);
export const overviewCardByKey = new Map(overviewCardDefinitions.map((card) => [card.key, card]));

export function readOverviewCardOrder() {
  try {
    const raw = localStorage.getItem(overviewLayoutKey);
    return normalizeOverviewCardOrder(raw ? JSON.parse(raw) : []);
  } catch {
    return [...defaultOverviewCardOrder];
  }
}

export function saveOverviewCardOrder(order: OverviewCardKey[]) {
  localStorage.setItem(overviewLayoutKey, JSON.stringify(order));
}

export function normalizeOverviewCardOrder(value: unknown): OverviewCardKey[] {
  const order: OverviewCardKey[] = [];
  const known = new Set(defaultOverviewCardOrder);
  const rawItems = Array.isArray(value) ? value : [];

  for (const item of rawItems) {
    if (typeof item !== "string") {
      continue;
    }
    const key = item as OverviewCardKey;
    if (known.has(key) && !order.includes(key)) {
      order.push(key);
    }
  }

  for (const key of defaultOverviewCardOrder) {
    if (!order.includes(key)) {
      order.push(key);
    }
  }

  return order;
}

export function buildOverviewCards(order: OverviewCardKey[]): OverviewCardView[] {
  const cards = normalizeOverviewCardOrder(order).map((key) => ({
    ...(overviewCardByKey.get(key) ?? overviewCardDefinitions[0]),
    span: overviewCardByKey.get(key)?.baseSpan ?? 12
  }));
  const result: OverviewCardView[] = [];
  let row: OverviewCardView[] = [];
  let rowSpan = 0;

  const flushRow = () => {
    if (!row.length) {
      return;
    }
    row[row.length - 1].span += 12 - rowSpan;
    result.push(...row);
    row = [];
    rowSpan = 0;
  };

  for (const card of cards) {
    if (rowSpan > 0 && rowSpan + card.baseSpan > 12) {
      if (row.length === 1) {
        result.push({ ...row[0], span: 6 }, { ...card, span: 6 });
        row = [];
        rowSpan = 0;
        continue;
      }
      flushRow();
    }
    row.push(card);
    rowSpan += card.baseSpan;
    if (rowSpan === 12) {
      flushRow();
    }
  }

  flushRow();
  return result;
}
