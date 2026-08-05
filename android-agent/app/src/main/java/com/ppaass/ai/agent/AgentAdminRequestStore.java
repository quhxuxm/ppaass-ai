package com.ppaass.ai.agent;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class AgentAdminRequestStore {
    static final String PREF_REVISION = "admin_key_request_revision";
    private static final String PREF_OWNER = "admin_key_request_owner";
    private static final String PREF_PENDING_IDS = "admin_key_request_ids";
    private static final String PREF_PENDING_COUNT = "admin_key_request_count";

    private static String memoryOwner = "";
    private static List<AgentAdminModels.KeyRequest> memoryRequests =
            Collections.emptyList();

    private AgentAdminRequestStore() {
    }

    static synchronized Update replace(
            Context context,
            String owner,
            List<AgentAdminModels.KeyRequest> requests) {
        String normalizedOwner = owner == null ? "" : owner.trim();
        List<AgentAdminModels.KeyRequest> copy =
                Collections.unmodifiableList(new ArrayList<>(requests));
        Set<String> currentIds = requestIds(copy);
        SharedPreferences preferences = preferences(context);
        String previousOwner = readString(preferences, PREF_OWNER);
        Set<String> previousIds = readStringSet(preferences, PREF_PENDING_IDS);
        Set<String> newIds = newlyPendingIds(
                previousOwner,
                previousIds,
                normalizedOwner,
                currentIds);
        boolean changed = !normalizedOwner.equals(previousOwner)
                || !currentIds.equals(previousIds)
                || preferences.getInt(PREF_PENDING_COUNT, 0) != copy.size();

        memoryOwner = normalizedOwner;
        memoryRequests = copy;
        if (changed) {
            preferences.edit()
                    .putString(PREF_OWNER, normalizedOwner)
                    .putStringSet(PREF_PENDING_IDS, currentIds)
                    .putInt(PREF_PENDING_COUNT, copy.size())
                    .putInt(PREF_REVISION, nextRevision(preferences))
                    .commit();
        }
        return new Update(copy.size(), newIds, changed);
    }

    static synchronized void prepare(
            Context context,
            String owner,
            boolean administrator) {
        String normalizedOwner = owner == null ? "" : owner.trim();
        if (!administrator
                || normalizedOwner.isEmpty()
                || !normalizedOwner.equals(readString(
                preferences(context),
                PREF_OWNER))) {
            clear(context);
        }
    }

    static synchronized void clear(Context context) {
        SharedPreferences preferences = preferences(context);
        boolean changed = preferences.contains(PREF_OWNER)
                || preferences.contains(PREF_PENDING_IDS)
                || preferences.contains(PREF_PENDING_COUNT);
        memoryOwner = "";
        memoryRequests = Collections.emptyList();
        if (changed) {
            preferences.edit()
                    .remove(PREF_OWNER)
                    .remove(PREF_PENDING_IDS)
                    .remove(PREF_PENDING_COUNT)
                    .putInt(PREF_REVISION, nextRevision(preferences))
                    .commit();
        }
    }

    static synchronized List<AgentAdminModels.KeyRequest> currentRequests(
            String owner) {
        return memoryOwner.equals(owner) ? memoryRequests : Collections.emptyList();
    }

    static int pendingCount(Context context) {
        return Math.max(0, preferences(context).getInt(PREF_PENDING_COUNT, 0));
    }

    static Set<String> newlyPendingIds(
            String previousOwner,
            Set<String> previousIds,
            String currentOwner,
            Set<String> currentIds) {
        LinkedHashSet<String> result = new LinkedHashSet<>(currentIds);
        if (currentOwner != null && currentOwner.equals(previousOwner)) {
            result.removeAll(previousIds);
        }
        return Collections.unmodifiableSet(result);
    }

    private static Set<String> requestIds(
            List<AgentAdminModels.KeyRequest> requests) {
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        for (AgentAdminModels.KeyRequest request : requests) {
            ids.add(request.id);
        }
        return ids;
    }

    private static Set<String> readStringSet(
            SharedPreferences preferences,
            String key) {
        try {
            Set<String> stored = preferences.getStringSet(key, Collections.emptySet());
            return stored == null ? Collections.emptySet() : new HashSet<>(stored);
        } catch (ClassCastException error) {
            return Collections.emptySet();
        }
    }

    private static String readString(
            SharedPreferences preferences,
            String key) {
        try {
            String value = preferences.getString(key, "");
            return value == null ? "" : value;
        } catch (ClassCastException error) {
            return "";
        }
    }

    private static int nextRevision(SharedPreferences preferences) {
        int revision = preferences.getInt(PREF_REVISION, 0);
        return revision == Integer.MAX_VALUE ? 1 : revision + 1;
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(
                ManagedCredentials.PREFERENCES_NAME,
                Context.MODE_PRIVATE);
    }

    static final class Update {
        final int pendingCount;
        final Set<String> newRequestIds;
        final boolean changed;

        Update(
                int pendingCount,
                Set<String> newRequestIds,
                boolean changed) {
            this.pendingCount = pendingCount;
            this.newRequestIds = newRequestIds;
            this.changed = changed;
        }

        boolean hasNewRequests() {
            return !newRequestIds.isEmpty();
        }

        boolean changed() {
            return changed;
        }
    }
}
