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

export function domainsAndAddressesToDirectRules(domains: string[], addresses: string[]) {
  const rules = domainsToDirectRules(domains);
  for (const value of addresses) {
    const address = value.trim();
    if (isIpAddress(address) && !rules.includes(address)) {
      rules.push(address);
    }
  }
  return rules;
}

export function selectedDomainsToNewDirectRules(
  selectedDomains: string[],
  addresses: string[],
  existingRules: string[]
) {
  const domains = [
    ...new Map(
      selectedDomains
        .map((domain) => domain.trim().replace(/\.$/, ""))
        .filter(Boolean)
        .map((domain) => [domain.toLowerCase(), domain] as const)
    ).values()
  ].filter(
    (domain) => !existingRules.some((rule) => directRuleCoversDomain(rule, domain))
  );
  const existingRuleKeys = new Set(
    existingRules.map((rule) => rule.trim().toLowerCase())
  );

  return domainsAndAddressesToDirectRules(domains, addresses).filter(
    (rule) => !existingRuleKeys.has(rule.trim().toLowerCase())
  );
}

export function isIpAddress(value: string) {
  const candidate = value.trim();
  if (candidate.includes(":")) {
    try {
      return new URL(`http://[${candidate}]/`).hostname.length > 2;
    } catch {
      return false;
    }
  }

  const octets = candidate.split(".");
  return (
    octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
  );
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

export function directRulesMatchingDomainsAndAddresses(
  existingRules: string[],
  domains: string[],
  addresses: string[]
) {
  const normalizedDomains = domains
    .map((domain) => domain.trim().replace(/\.$/, ""))
    .filter(Boolean);
  const addressKeys = new Set(
    addresses
      .map((address) => address.trim())
      .filter(isIpAddress)
      .map((address) => address.toLowerCase())
  );

  return existingRules.filter((rule) => {
    const normalizedRule = rule.trim().toLowerCase();
    return (
      addressKeys.has(normalizedRule) ||
      normalizedDomains.some((domain) => directRuleCoversDomain(rule, domain))
    );
  });
}
