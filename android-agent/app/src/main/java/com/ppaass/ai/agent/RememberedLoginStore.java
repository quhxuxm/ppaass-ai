package com.ppaass.ai.agent;

import android.content.Context;
import android.content.SharedPreferences;

final class RememberedLoginStore {
    private static final String PREFERENCES_NAME = "ppaass_agent_login";
    private static final String PREF_USERNAME = "username";
    private static final String PREF_PASSWORD = "password";

    private RememberedLoginStore() {
    }

    static Login load(Context context) {
        SharedPreferences preferences =
                context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE);
        String username = preferences.getString(PREF_USERNAME, "");
        String password = preferences.getString(PREF_PASSWORD, "");
        if (username == null || username.trim().isEmpty()
                || password == null || password.length() < 8) {
            return null;
        }
        return new Login(username, password);
    }

    static boolean save(Context context, String username, String password) {
        return context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(PREF_USERNAME, username.trim())
                .putString(PREF_PASSWORD, password)
                .commit();
    }

    static boolean clear(Context context) {
        return context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit();
    }

    static final class Login {
        final String username;
        final String password;

        Login(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }
}
