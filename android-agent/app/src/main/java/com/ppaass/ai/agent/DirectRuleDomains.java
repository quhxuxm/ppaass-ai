package com.ppaass.ai.agent;

import com.google.common.net.InternetDomainName;
import com.google.common.net.InetAddresses;

import java.util.*;

final class DirectRuleDomains {
    private DirectRuleDomains() {
    }

    static String toDirectRule(String domain) {
        String normalized = normalizeDomain(domain);
        int firstDot = normalized.indexOf('.');
        if (firstDot <= 0) {
            return normalized;
        }

        String parent = normalized.substring(firstDot + 1);
        return isPublicSuffix(parent) ? normalized : "*." + parent;
    }

    static List<String> toDirectRules(Collection<String> domains) {
        LinkedHashSet<String> rules = new LinkedHashSet<>();
        for (String domain : domains) {
            String rule = toDirectRule(domain);
            if (!rule.isEmpty()) {
                rules.add(rule);
            }
        }
        return new ArrayList<>(rules);
    }

    static List<String> toDirectRules(Collection<String> domains, Collection<String> addresses) {
        LinkedHashSet<String> rules = new LinkedHashSet<>(toDirectRules(domains));
        for (String value : addresses) {
            String address = normalizeAddress(value);
            if (!address.isEmpty()) {
                rules.add(address);
            }
        }
        return new ArrayList<>(rules);
    }

    static boolean ruleCoversDomain(String rule, String domain) {
        String normalizedRule = rule == null ? "" : rule.trim().toLowerCase(Locale.US);
        String normalizedDomain = normalizeDomain(domain);
        if (normalizedRule.equals(normalizedDomain)) {
            return true;
        }
        if (!normalizedRule.startsWith("*.")) {
            return false;
        }
        String suffix = normalizedRule.substring(2);
        return !normalizedDomain.equals(suffix) && normalizedDomain.endsWith("." + suffix);
    }

    static List<String> directRulesMatchingDomainsAndAddresses(
            Collection<String> existingRules,
            Collection<String> domains,
            Collection<String> addresses) {
        List<String> normalizedDomains = new ArrayList<>();
        for (String domain : domains) {
            String normalized = normalizeDomain(domain);
            if (!normalized.isEmpty()) {
                normalizedDomains.add(normalized);
            }
        }

        HashSet<String> addressKeys = new HashSet<>();
        for (String value : addresses) {
            String address = normalizeAddress(value);
            if (!address.isEmpty()) {
                addressKeys.add(address);
            }
        }

        List<String> matches = new ArrayList<>();
        for (String rule : existingRules) {
            String normalizedRuleAddress = normalizeAddress(rule);
            boolean matchesAddress = !normalizedRuleAddress.isEmpty()
                    && addressKeys.contains(normalizedRuleAddress);
            boolean matchesDomain = false;
            for (String domain : normalizedDomains) {
                if (ruleCoversDomain(rule, domain)) {
                    matchesDomain = true;
                    break;
                }
            }
            if (matchesAddress || matchesDomain) {
                matches.add(rule);
            }
        }
        return matches;
    }

    private static String normalizeDomain(String domain) {
        String normalized = domain == null ? "" : domain.trim().toLowerCase(Locale.US);
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static String normalizeAddress(String value) {
        String address = value == null ? "" : value.trim();
        if (address.isEmpty()) {
            return "";
        }
        try {
            return InetAddresses.toAddrString(InetAddresses.forString(address));
        } catch (IllegalArgumentException ignored) {
            return "";
        }
    }

    private static boolean isPublicSuffix(String domain) {
        try {
            InternetDomainName name = InternetDomainName.from(domain);
            return !name.hasPublicSuffix() || name.isPublicSuffix();
        } catch (IllegalArgumentException ignored) {
            return true;
        }
    }
}
