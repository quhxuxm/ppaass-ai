package com.ppaass.ai.agent;

import android.graphics.drawable.Drawable;

final class AppEntry {
    final String label;
    final String packageName;
    final boolean systemApp;
    final Drawable icon;

    AppEntry(String label, String packageName, boolean systemApp, Drawable icon) {
        this.label = label;
        this.packageName = packageName;
        this.systemApp = systemApp;
        this.icon = icon;
    }
}
