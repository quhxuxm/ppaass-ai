package com.ppaass.ai.agent;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class UiLanguageTest {
    @Test
    public void keepsChineseWhenChineseIsSelected() {
        assertEquals("今日流量", UiLanguage.translate("zh-CN", "今日流量"));
    }

    @Test
    public void translatesStaticAndDynamicUiText() {
        assertEquals("Today's traffic", UiLanguage.translate("en", "今日流量"));
        assertEquals("Download", UiLanguage.translate("en", "下载"));
        assertEquals("Upload", UiLanguage.translate("en", "上传"));
        assertEquals("Selected 3 items", UiLanguage.translate("en", "已选 3 条"));
        assertFalse(UiLanguage.translate("en", "VPN 运行中 · 模拟 GEO 启动中")
                .matches(".*[\\u4e00-\\u9fff].*"));
    }
}
