package com.ppaass.ai.agent;

import com.google.common.net.InternetDomainName;

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

    private static String normalizeDomain(String domain) {
        String normalized = domain == null ? "" : domain.trim().toLowerCase(Locale.US);
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
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
