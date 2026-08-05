function isIntegerInputTarget(
  target: EventTarget | null
): target is HTMLInputElement {
  return (
    target instanceof HTMLInputElement &&
    Boolean(target.closest(".p-inputnumber"))
  );
}

function digitsOnly(value: string) {
  return value.replace(/\D+/g, "");
}

export function guardIntegerBeforeInput(event: InputEvent) {
  const target = event.target;
  if (
    isIntegerInputTarget(target) &&
    event.data &&
    !/^\d+$/.test(event.data)
  ) {
    event.preventDefault();
  }
}

export function guardIntegerPaste(event: ClipboardEvent) {
  const target = event.target;
  if (!isIntegerInputTarget(target)) {
    return;
  }
  const text = event.clipboardData?.getData("text") ?? "";
  const digits = digitsOnly(text);
  if (digits === text) {
    return;
  }
  event.preventDefault();
  if (!digits) {
    return;
  }
  const start = target.selectionStart ?? target.value.length;
  const end = target.selectionEnd ?? target.value.length;
  target.setRangeText(digits, start, end, "end");
  target.dispatchEvent(new Event("input", { bubbles: true }));
}

export function sanitizeIntegerInput(event: Event) {
  const target = event.target;
  if (!isIntegerInputTarget(target)) {
    return;
  }
  const sanitized = digitsOnly(target.value);
  if (sanitized === target.value) {
    return;
  }
  const caret = target.selectionStart ?? sanitized.length;
  const beforeCaret = target.value.slice(0, caret);
  const removedBeforeCaret =
    beforeCaret.length - digitsOnly(beforeCaret).length;
  const nextCaret = Math.max(0, caret - removedBeforeCaret);
  target.value = sanitized;
  target.setSelectionRange(nextCaret, nextCaret);
  target.dispatchEvent(new Event("input", { bubbles: true }));
}
