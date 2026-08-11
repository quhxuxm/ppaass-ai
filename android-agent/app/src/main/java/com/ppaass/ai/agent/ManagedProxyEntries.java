package com.ppaass.ai.agent;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class ManagedProxyEntries {
    static final String PREF_ENTRIES = "managed_selectable_proxy_entries";
    static final String PREF_SELECTED_ID = "managed_selected_proxy_entry_id";
    private static final int MAX_ENTRIES = 10_000;

    private ManagedProxyEntries() {
    }

    static Selection require(
            List<AgentAuthDtos.ProxyEntry> values,
            String selectedId,
            boolean allowed) throws AgentAuthClient.AuthException {
        if (!allowed) {
            if (values != null || selectedId != null) {
                throw invalidResponse();
            }
            return Selection.empty();
        }
        if (values == null || values.size() > MAX_ENTRIES) {
            throw invalidResponse();
        }
        ArrayList<Entry> entries = new ArrayList<>(values.size());
        Set<String> ids = new HashSet<>();
        for (AgentAuthDtos.ProxyEntry value : values) {
            if (value == null) {
                throw invalidResponse();
            }
            String id = requiredText(value.proxy_entry_id, 128);
            String name = requiredText(value.label, 128);
            String description = requiredText(value.description, 256);
            String iconKey = requiredText(value.icon_key, 128);
            String address = ManagedProxyAddresses.normalize(
                    List.of(value.address)).get(0);
            if (!ids.add(id)) {
                throw invalidResponse();
            }
            entries.add(new Entry(
                    id,
                    name,
                    description,
                    iconKey,
                    address,
                    Boolean.TRUE.equals(value.online)));
        }
        if (selectedId != null && !ids.contains(selectedId)) {
            throw invalidResponse();
        }
        return new Selection(entries, selectedId == null ? "" : selectedId);
    }

    static String serialize(List<Entry> entries) {
        JSONArray array = new JSONArray();
        for (Entry entry : entries) {
            try {
                array.put(new JSONObject()
                        .put("id", entry.id)
                        .put("name", entry.name)
                        .put("description", entry.description)
                        .put("icon_key", entry.iconKey)
                        .put("address", entry.address)
                        .put("online", entry.online));
            } catch (JSONException impossible) {
                return "[]";
            }
        }
        return array.toString();
    }

    static Selection load(Context context) {
        SharedPreferences preferences = preferences(context);
        try {
            String encoded = preferences.getString(PREF_ENTRIES, "");
            String selectedId = preferences.getString(PREF_SELECTED_ID, "");
            if (encoded == null || encoded.isEmpty()) {
                return Selection.empty();
            }
            JSONArray array = new JSONArray(encoded);
            ArrayList<Entry> entries = new ArrayList<>(array.length());
            for (int index = 0; index < array.length(); index++) {
                JSONObject value = array.getJSONObject(index);
                entries.add(new Entry(
                        value.getString("id"),
                        value.getString("name"),
                        value.getString("description"),
                        value.getString("icon_key"),
                        value.getString("address"),
                        value.optBoolean("online", false)));
            }
            return new Selection(entries, selectedId == null ? "" : selectedId);
        } catch (ClassCastException | JSONException error) {
            return Selection.empty();
        }
    }

    private static String requiredText(String value, int maximum)
            throws AgentAuthClient.AuthException {
        if (value == null || value.isEmpty() || value.length() > maximum
                || value.chars().anyMatch(Character::isISOControl)) {
            throw invalidResponse();
        }
        return value;
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(
                ManagedCredentials.PREFERENCES_NAME,
                Context.MODE_PRIVATE);
    }

    private static AgentAuthClient.AuthException invalidResponse() {
        return new AgentAuthClient.AuthException(
                "Proxy Registry 返回的 Proxy Entry 列表无效");
    }

    static final class Selection {
        final List<Entry> entries;
        final String selectedId;

        Selection(List<Entry> entries, String selectedId) {
            this.entries = Collections.unmodifiableList(new ArrayList<>(entries));
            this.selectedId = selectedId;
        }

        static Selection empty() {
            return new Selection(Collections.emptyList(), "");
        }
    }

    static final class Entry {
        final String id;
        final String name;
        final String description;
        final String iconKey;
        final String address;
        final boolean online;

        Entry(
                String id,
                String name,
                String description,
                String iconKey,
                String address,
                boolean online) {
            this.id = id;
            this.name = name;
            this.description = description;
            this.iconKey = iconKey;
            this.address = address;
            this.online = online;
        }
    }
}
