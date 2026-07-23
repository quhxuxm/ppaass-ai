import { getDomain } from "tldts";

export function domainToDirectRule(domain: string) {
  const normalized = domain.trim().replace(/\.$/, "").toLowerCase();
  const firstDot = normalized.indexOf(".");
  if (firstDot <= 0) {
    return normalized;
  }

  const parent = normalized.slice(firstDot + 1);
  // A wildcard must never target a public suffix such as *.com or *.co.uk.
  return getDomain(parent, { allowPrivateDomains: true }) ? `*.${parent}` : normalized;
}

export function domainsToDirectRules(domains: string[]) {
  const rules = domains.map(domainToDirectRule);
  return [...new Set(rules.filter(Boolean))];
}

export function directRuleCoversDomain(rule: string, domain: string) {
  const normalizedRule = rule.trim().toLowerCase();
  const normalizedDomain = domain.trim().replace(/\.$/, "").toLowerCase();
  if (normalizedRule === normalizedDomain) {
    return true;
  }
  if (!normalizedRule.startsWith("*.")) {
    return false;
  }
  const suffix = normalizedRule.slice(2);
  return normalizedDomain !== suffix && normalizedDomain.endsWith(`.${suffix}`);
}
