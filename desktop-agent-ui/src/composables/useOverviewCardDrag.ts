import { computed, onBeforeUnmount, ref } from "vue";
import { shortPath } from "../formatters";
import {
  buildOverviewCards,
  normalizeOverviewCardOrder,
  overviewCardByKey,
  readOverviewCardOrder,
  saveOverviewCardOrder
} from "../overviewLayout";
import type {
  AgentState,
  OverviewCardKey,
  OverviewDragGhost
} from "../types";

export function useOverviewCardDrag(props: { agent: AgentState }) {
  const overviewCardOrder = ref(readOverviewCardOrder());
  const draggingOverviewCard = ref<OverviewCardKey | null>(null);
  const dragOverOverviewCard = ref<OverviewCardKey | null>(null);
  const overviewDragGhost = ref<OverviewDragGhost | null>(null);
  const overviewCards = computed(() =>
    buildOverviewCards(overviewCardOrder.value)
  );

  onBeforeUnmount(resetOverviewMouseDrag);

  function overviewCardTitle(key: OverviewCardKey) {
    const titles: Record<OverviewCardKey, string> = {
      status: "运行状态",
      proxy: "HTTP / SOCKS5",
      speed: "实时网速",
      traffic: "今日流量",
      dns: "代理 DNS",
      tun: "TUN",
      policy: "共享策略"
    };
    return titles[key];
  }

  function overviewCardSubtitle(key: OverviewCardKey) {
    if (key === "status") {
      return props.agent.binary_path
        ? shortPath(props.agent.binary_path)
        : "桌面代理";
    }
    return "";
  }

  function onOverviewMouseDown(event: MouseEvent, key: OverviewCardKey) {
    if (event.button !== 0) return;
    if (
      event.target instanceof Element &&
      event.target.closest(
        "input, textarea, select, a, button:not(.overview-drag-handle)"
      )
    ) {
      return;
    }
    event.preventDefault();
    document.body.classList.add("overview-dragging");
    draggingOverviewCard.value = key;
    dragOverOverviewCard.value = null;
    const cardElement =
      event.currentTarget instanceof HTMLElement
        ? event.currentTarget
        : document.querySelector<HTMLElement>(
            `[data-overview-card="${key}"]`
          );
    const cardBox = cardElement?.getBoundingClientRect();
    if (cardBox) {
      overviewDragGhost.value = {
        x: cardBox.left,
        y: cardBox.top,
        width: cardBox.width,
        height: cardBox.height,
        offsetX: event.clientX - cardBox.left,
        offsetY: event.clientY - cardBox.top
      };
    }
    window.addEventListener("mousemove", onOverviewMouseMove);
    window.addEventListener("mouseup", onOverviewMouseUp, { once: true });
  }

  function onOverviewMouseMove(event: MouseEvent) {
    if (!draggingOverviewCard.value) return;
    if (overviewDragGhost.value) {
      overviewDragGhost.value.x =
        event.clientX - overviewDragGhost.value.offsetX;
      overviewDragGhost.value.y =
        event.clientY - overviewDragGhost.value.offsetY;
    }
    const targetKey = overviewCardKeyFromPoint(event.clientX, event.clientY);
    if (!targetKey || targetKey === draggingOverviewCard.value) {
      dragOverOverviewCard.value = null;
      return;
    }
    dragOverOverviewCard.value = targetKey;
    moveOverviewCard(
      draggingOverviewCard.value,
      targetKey,
      overviewDropPlacement(event.clientX, event.clientY, targetKey)
    );
  }

  function onOverviewMouseUp(event: MouseEvent) {
    const source = draggingOverviewCard.value;
    const target = overviewCardKeyFromPoint(event.clientX, event.clientY);
    if (source && target && source !== target) {
      moveOverviewCard(
        source,
        target,
        overviewDropPlacement(event.clientX, event.clientY, target)
      );
    }
    resetOverviewMouseDrag();
  }

  function overviewCardKeyFromPoint(x: number, y: number) {
    const element = document.elementFromPoint(x, y);
    const card =
      element instanceof Element
        ? element.closest<HTMLElement>("[data-overview-card]")
        : null;
    const key = card?.dataset.overviewCard as OverviewCardKey | undefined;
    return key && overviewCardByKey.has(key) ? key : null;
  }

  function overviewDropPlacement(
    x: number,
    y: number,
    targetKey: OverviewCardKey
  ): "before" | "after" {
    const target = document.querySelector<HTMLElement>(
      `[data-overview-card="${targetKey}"]`
    );
    if (!target) return "before";
    const box = target.getBoundingClientRect();
    return y > box.top + box.height / 2 ||
      x > box.left + box.width / 2
      ? "after"
      : "before";
  }

  function resetOverviewMouseDrag() {
    window.removeEventListener("mousemove", onOverviewMouseMove);
    window.removeEventListener("mouseup", onOverviewMouseUp);
    document.body.classList.remove("overview-dragging");
    draggingOverviewCard.value = null;
    dragOverOverviewCard.value = null;
    overviewDragGhost.value = null;
  }

  function moveOverviewCard(
    source: OverviewCardKey,
    target: OverviewCardKey,
    placement: "before" | "after"
  ) {
    const next = [...overviewCardOrder.value];
    const sourceIndex = next.indexOf(source);
    if (sourceIndex === -1) return;
    next.splice(sourceIndex, 1);
    const targetIndex = next.indexOf(target);
    if (targetIndex === -1) return;
    next.splice(
      placement === "after" ? targetIndex + 1 : targetIndex,
      0,
      source
    );
    overviewCardOrder.value = normalizeOverviewCardOrder(next);
    saveOverviewCardOrder(overviewCardOrder.value);
  }

  return {
    overviewCards,
    draggingOverviewCard,
    dragOverOverviewCard,
    overviewDragGhost,
    overviewCardTitle,
    overviewCardSubtitle,
    onOverviewMouseDown
  };
}
