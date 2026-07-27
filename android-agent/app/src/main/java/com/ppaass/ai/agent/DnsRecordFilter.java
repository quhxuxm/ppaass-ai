package com.ppaass.ai.agent;

import java.util.Collection;
import java.util.Locale;

/** Pure-Java matching rules shared by the programmatically built DNS panel and unit tests. */
final class DnsRecordFilter {
    private DnsRecordFilter() {
    }

    static boolean matches(
            String filter,
            String query,
            Collection<String> answers,
            String client,
            String upstream,
            String resolver,
            String recordType,
            String status,
            long durationMs,
            boolean direct) {
        String normalizedFilter = safe(filter).trim().toLowerCase(Locale.US);
        if (normalizedFilter.isEmpty()) {
            return true;
        }

        String normalizedStatus = safe(status).toUpperCase(Locale.US);
        String normalizedResolver = safe(resolver).toLowerCase(Locale.US);
        StringBuilder searchable = new StringBuilder()
                .append(safe(query)).append(' ')
                .append(safe(client)).append(' ')
                .append(safe(upstream)).append(' ')
                .append(normalizedResolver).append(' ')
                .append(safe(recordType)).append(' ')
                .append(normalizedStatus).append(' ')
                .append(statusAliases(normalizedStatus)).append(' ')
                .append(resolverAliases(normalizedResolver)).append(' ')
                .append(durationMs).append(" ms");
        if (answers != null) {
            for (String answer : answers) {
                searchable.append(' ').append(safe(answer));
            }
        }
        if (direct) {
            searchable.append(" 已直连 direct");
        }

        String searchableText = searchable.toString().toLowerCase(Locale.US);
        for (String term : normalizedFilter.split("\\s+")) {
            if (!searchableText.contains(term)) {
                return false;
            }
        }
        return true;
    }

    private static String statusAliases(String status) {
        switch (status) {
            case "NOERROR":
                return "成功 success";
            case "NXDOMAIN":
                return "不存在 not found";
            case "TIMEOUT":
                return "超时 解析超时 timeout timed out";
            case "SERVFAIL":
                return "失败 failure failed";
            default:
                return "";
        }
    }

    private static String resolverAliases(String resolver) {
        switch (resolver) {
            case "agent-cache":
                return "缓存命中 cache hit";
            case "agent-direct":
                return "直连解析 direct resolution";
            case "system":
                return "系统 dns system";
            case "":
            case "agent":
                return "代理 dns proxy dns agent";
            default:
                return "";
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
