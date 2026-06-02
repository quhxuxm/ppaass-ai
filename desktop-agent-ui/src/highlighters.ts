import type { HighlightedLogLine, HighlightedTomlLine, LogToken, LogTokenKind, TomlToken, TomlTokenKind } from "./types";

export function tokenizeLogLine(line: string): HighlightedLogLine {
  const level = line.match(/\b(TRACE|DEBUG|INFO|WARN|ERROR)\b/)?.[1]?.toLowerCase() ?? null;
  const pattern =
    /(\d{4}-\d{2}-\d{2}T[^\s]+|\b(?:TRACE|DEBUG|INFO|WARN|ERROR)\b|ThreadId\([^)]+\)|\b[a-zA-Z_][\w:.-]*(?:\.rs)?:\d+:\d+:|\b[a-zA-Z_][\w.-]*=|"(?:[^"\\]|\\.)*"|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\b\d+(?:\.\d+)?\b)/g;
  const tokens: LogToken[] = [];
  let cursor = 0;

  for (const match of line.matchAll(pattern)) {
    const value = match[0];
    const index = match.index ?? 0;
    if (index > cursor) {
      tokens.push({ value: line.slice(cursor, index), kind: "plain" });
    }
    tokens.push({ value, kind: logTokenKind(value) });
    cursor = index + value.length;
  }

  if (cursor < line.length) {
    tokens.push({ value: line.slice(cursor), kind: "plain" });
  }

  return { raw: line, level, tokens: tokens.length ? tokens : [{ value: line, kind: "plain" }] };
}

export function tokenizeToml(raw: string): HighlightedTomlLine[] {
  return raw.split("\n").map((line) => ({ raw: line, tokens: tokenizeTomlLine(line) }));
}

function logTokenKind(value: string): LogTokenKind {
  if (/^\d{4}-\d{2}-\d{2}T/.test(value)) {
    return "timestamp";
  }
  if (/^(TRACE|DEBUG|INFO|WARN|ERROR)$/.test(value)) {
    return `level-${value.toLowerCase()}` as LogTokenKind;
  }
  if (/^ThreadId\(/.test(value)) {
    return "thread";
  }
  if (/\.rs:\d+:\d+:$/.test(value) || /^[a-zA-Z_][\w:.-]+:$/.test(value)) {
    return "target";
  }
  if (/^[a-zA-Z_][\w.-]*=$/.test(value)) {
    return "field";
  }
  if (/^"/.test(value)) {
    return "string";
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(value)) {
    return "address";
  }
  if (/^\d/.test(value)) {
    return "number";
  }
  return "plain";
}

function tokenizeTomlLine(line: string): TomlToken[] {
  if (!line) {
    return [{ value: "", kind: "plain" }];
  }

  const commentIndex = findTomlDelimiter(line, "#");
  const code = commentIndex >= 0 ? line.slice(0, commentIndex) : line;
  const comment = commentIndex >= 0 ? line.slice(commentIndex) : "";
  const tokens: TomlToken[] = [];
  const sectionMatch = code.match(/^(\s*)(\[\[?)([^\]]+)(\]\]?)(\s*)$/);

  if (sectionMatch) {
    pushTomlToken(tokens, sectionMatch[1], "plain");
    pushTomlToken(tokens, `${sectionMatch[2]}${sectionMatch[3]}${sectionMatch[4]}`, "section");
    pushTomlToken(tokens, sectionMatch[5], "plain");
    pushTomlToken(tokens, comment, "comment");
    return tokens.length ? tokens : [{ value: line, kind: "plain" }];
  }

  const equalsIndex = findTomlDelimiter(code, "=");
  if (equalsIndex >= 0) {
    tokenizeTomlKey(code.slice(0, equalsIndex), tokens);
    pushTomlToken(tokens, "=", "equals");
    tokenizeTomlValue(code.slice(equalsIndex + 1), tokens);
  } else {
    tokenizeTomlValue(code, tokens);
  }

  pushTomlToken(tokens, comment, "comment");
  return tokens.length ? tokens : [{ value: line, kind: "plain" }];
}

function tokenizeTomlKey(keyPart: string, tokens: TomlToken[]) {
  const keyMatch = keyPart.match(/^(\s*)(.*?)(\s*)$/);
  if (!keyMatch) {
    pushTomlToken(tokens, keyPart, "plain");
    return;
  }
  pushTomlToken(tokens, keyMatch[1], "plain");
  pushTomlToken(tokens, keyMatch[2], "key");
  pushTomlToken(tokens, keyMatch[3], "plain");
}

function tokenizeTomlValue(value: string, tokens: TomlToken[]) {
  let cursor = 0;
  while (cursor < value.length) {
    const rest = value.slice(cursor);
    const whitespace = rest.match(/^\s+/)?.[0];
    if (whitespace) {
      pushTomlToken(tokens, whitespace, "plain");
      cursor += whitespace.length;
      continue;
    }

    const char = value[cursor];
    if (char === "\"" || char === "'") {
      const stringEnd = findTomlStringEnd(value, cursor, char);
      pushTomlToken(tokens, value.slice(cursor, stringEnd), "string");
      cursor = stringEnd;
      continue;
    }

    const word = rest.match(/^(true|false)\b/)?.[0];
    if (word) {
      pushTomlToken(tokens, word, "boolean");
      cursor += word.length;
      continue;
    }

    const date = rest.match(/^\d{4}-\d{2}-\d{2}(?:[Tt ][0-9:.+-Zz]+)?/)?.[0];
    if (date) {
      pushTomlToken(tokens, date, "date");
      cursor += date.length;
      continue;
    }

    const number = rest.match(/^[+-]?(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?)/)?.[0];
    if (number) {
      pushTomlToken(tokens, number, "number");
      cursor += number.length;
      continue;
    }

    if ("[]{}.,=".includes(char)) {
      pushTomlToken(tokens, char, "punctuation");
      cursor += 1;
      continue;
    }

    pushTomlToken(tokens, char, "plain");
    cursor += 1;
  }
}

function findTomlDelimiter(line: string, delimiter: string) {
  let quote: string | null = null;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quote) {
      if (quote === "\"" && char === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (char === quote && !escaped) {
        quote = null;
      }
      escaped = false;
      continue;
    }
    if (char === "\"" || char === "'") {
      quote = char;
      continue;
    }
    if (char === delimiter) {
      return index;
    }
  }
  return -1;
}

function findTomlStringEnd(value: string, start: number, quote: string) {
  let escaped = false;
  for (let index = start + 1; index < value.length; index += 1) {
    const char = value[index];
    if (quote === "\"" && char === "\\" && !escaped) {
      escaped = true;
      continue;
    }
    if (char === quote && !escaped) {
      return index + 1;
    }
    escaped = false;
  }
  return value.length;
}

function pushTomlToken(tokens: TomlToken[], value: string, kind: TomlTokenKind) {
  if (value) {
    tokens.push({ value, kind });
  }
}
