package com.ppaass.ai.agent;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.Base64;

final class AgentProfileAvatar {
    private static final int MAX_BYTES = 1024 * 1024;

    private AgentProfileAvatar() {
    }

    static Bitmap decode(String dataUrl) {
        if (dataUrl == null || dataUrl.isEmpty()) {
            return null;
        }
        int comma = dataUrl.indexOf(',');
        if (comma <= 0 || comma + 1 >= dataUrl.length()) {
            return null;
        }
        String prefix = dataUrl.substring(0, comma);
        if (!("data:image/png;base64".equals(prefix)
                || "data:image/jpeg;base64".equals(prefix)
                || "data:image/webp;base64".equals(prefix))) {
            return null;
        }
        try {
            byte[] bytes = Base64.decode(
                    dataUrl.substring(comma + 1),
                    Base64.DEFAULT);
            if (bytes.length == 0 || bytes.length > MAX_BYTES) {
                return null;
            }
            BitmapFactory.Options bounds = new BitmapFactory.Options();
            bounds.inJustDecodeBounds = true;
            BitmapFactory.decodeByteArray(bytes, 0, bytes.length, bounds);
            if (bounds.outWidth < 1
                    || bounds.outHeight < 1
                    || bounds.outWidth > 64
                    || bounds.outHeight > 64) {
                return null;
            }
            return BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
        } catch (IllegalArgumentException error) {
            return null;
        }
    }
}
