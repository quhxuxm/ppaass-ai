import type { ComputedRef } from "vue";
import { computed } from "vue";
import { delay, getErrorMessage } from "../../formatters";
import { fallbackAgentState } from "../../fallbacks";
import type { AgentState, DirectRuleGroup } from "../../types";
import type { DesktopAgentModel } from "./model";
import { latestAgentLog } from "./model";
import { invokeOrFallback } from "./platform";

interface DirectRuleDependencies {
  ensureConfigEditable: (notify?: boolean) => boolean;
  persistConfig: () => Promise<void>;
  refreshAgentState: () => Promise<void>;
  showToast: (kind: "success" | "error" | "info", message: string) => void;
  updateDirectRules: (rules: string[], allowWhileRunning?: boolean) => void;
}

export function createDirectRuleController(
  model: DesktopAgentModel,
  dependencies: DirectRuleDependencies
) {
  const { state } = model;
  const directRuleGroups: ComputedRef<DirectRuleGroup[]> = computed(() =>
    buildDirectRuleGroups(model.summary.value.direct_rules)
  );

  function addDirectRules(rules: string[]) {
    if (!state.config || !dependencies.ensureConfigEditable()) {
      return;
    }
    dependencies.updateDirectRules(
      normalizeRules([...state.config.summary.direct_rules, ...rules])
    );
    state.ruleDraft = "";
    dependencies.showToast("success", "规则已更新");
  }

  function addDraftRules() {
    if (dependencies.ensureConfigEditable()) {
      addDirectRules(parseRuleInput(state.ruleDraft));
    }
  }

  function removeDirectRule(index: number) {
    if (
      !state.config ||
      !Number.isInteger(index) ||
      !dependencies.ensureConfigEditable()
    ) {
      return;
    }
    const next = normalizeRules(state.config.summary.direct_rules).filter(
      (_, current) => current !== index
    );
    dependencies.updateDirectRules(next);
  }

  async function addDirectRulesAndRestart(rules: string[]) {
    if (!state.config) {
      return;
    }
    const nextRules = normalizeRules([
      ...state.config.summary.direct_rules,
      ...rules
    ]);
    await applyDirectRulesAndRestart(nextRules, {
      unchanged: "所选 DNS 没有可添加的直连规则",
      saved: "直连规则已添加并保存",
      restarted: "直连规则已添加，Agent 已重启"
    });
  }

  async function removeDirectRulesAndRestart(rules: string[]) {
    if (!state.config) {
      return;
    }
    const removeRuleKeys = new Set(
      normalizeRules(rules).map((rule) => rule.toLowerCase())
    );
    const nextRules = normalizeRules(
      state.config.summary.direct_rules
    ).filter((rule) => !removeRuleKeys.has(rule.toLowerCase()));
    await applyDirectRulesAndRestart(nextRules, {
      unchanged: "所选 DNS 没有可移出的直连规则",
      saved: "直连规则已移出并保存",
      restarted: "直连规则已移出，Agent 已重启"
    });
  }

  async function applyDirectRulesAndRestart(
    nextRules: string[],
    messages: { unchanged: string; saved: string; restarted: string }
  ) {
    if (!state.config) {
      return;
    }
    if (state.busy) {
      dependencies.showToast("info", "正在处理其他操作");
      return;
    }
    const currentRules = normalizeRules(state.config.summary.direct_rules);
    const normalizedNextRules = normalizeRules(nextRules);
    if (
      normalizedNextRules.length === currentRules.length &&
      normalizedNextRules.every(
        (rule, index) =>
          rule.toLowerCase() === currentRules[index]?.toLowerCase()
      )
    ) {
      dependencies.showToast("info", messages.unchanged);
      return;
    }

    const wasRunning = state.agent.running;
    try {
      state.busy = true;
      dependencies.updateDirectRules(normalizedNextRules, true);
      await dependencies.persistConfig();
      if (!wasRunning) {
        dependencies.showToast("success", messages.saved);
        return;
      }
      state.agent = await invokeOrFallback<AgentState>(
        "stop_agent",
        {},
        () => ({
          ...fallbackAgentState(),
          running: false,
          pid: null,
          config_path: state.config?.path
        })
      );
      if (state.agent.running) {
        throw new Error("直连规则已保存，但 Agent 停止失败");
      }
      state.agent = await invokeOrFallback<AgentState>(
        "start_agent",
        { configPath: state.config.path },
        () => ({
          ...fallbackAgentState(),
          running: true,
          managed: true,
          pid: 4242,
          config_path: state.config?.path
        })
      );
      await delay(1800);
      await dependencies.refreshAgentState();
      if (!state.agent.running) {
        throw new Error(
          latestAgentLog(model) ?? "直连规则已保存，但 Agent 重启失败"
        );
      }
      dependencies.showToast("success", messages.restarted);
    } catch (error) {
      await dependencies.refreshAgentState();
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  return {
    addDirectRules,
    addDirectRulesAndRestart,
    addDraftRules,
    directRuleGroups,
    removeDirectRule,
    removeDirectRulesAndRestart
  };
}

export function normalizeRules(rules: string[]) {
  const seen = new Set<string>();
  return rules
    .map((rule) => rule.trim())
    .filter(Boolean)
    .filter((rule) => {
      const key = rule.toLowerCase();
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
}

function parseRuleInput(value: string) {
  return value.split(/[\s,，;；]+/);
}

function buildDirectRuleGroups(rules: string[]) {
  const groups: DirectRuleGroup[] = [
    {
      key: "wildcard",
      label: "通配符",
      icon: "asterisk",
      modes: ["HTTP/SOCKS5", "TUN + DNS 缓存"],
      items: []
    },
    {
      key: "network",
      label: "IP / CIDR",
      icon: "hash",
      modes: ["TUN", "已解析 IP 目标"],
      items: []
    },
    {
      key: "domain",
      label: "域名",
      icon: "globe",
      modes: ["HTTP/SOCKS5", "TUN + DNS 缓存"],
      items: []
    },
    {
      key: "other",
      label: "其他",
      icon: "ellipsis",
      modes: ["按规则内容匹配"],
      items: []
    }
  ];
  const byKey = new Map(groups.map((group) => [group.key, group]));
  rules.forEach((rule, index) => {
    byKey.get(ruleGroupKey(rule))?.items.push({ rule, index });
  });
  return groups;
}

function ruleGroupKey(rule: string) {
  const normalized = rule.trim().toLowerCase();
  if (normalized.includes("*")) {
    return "wildcard";
  }
  if (isNetworkRule(normalized)) {
    return "network";
  }
  if (/^[a-z0-9._-]+(\.[a-z0-9._-]+)*$/i.test(normalized)) {
    return "domain";
  }
  return "other";
}

function isNetworkRule(rule: string) {
  return (
    /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(rule) ||
    /^([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}(\/\d{1,3})?$/i.test(rule)
  );
}
