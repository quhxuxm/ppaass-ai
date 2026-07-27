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
        assertEquals(
                "Showing 2 / 8 items",
                UiLanguage.translate("en", "显示 2 / 8 条"));
        assertEquals(
                "Selected 2 · to add 1 items · to remove 3 items",
                UiLanguage.translate("en", "已选 2 · 待添加 1 条 · 待移出 3 条"));
        assertEquals(
                "Remove and restart",
                UiLanguage.translate("en", "移出并重启"));
        assertEquals(
                "Client → Agent / target",
                UiLanguage.translate("en", "Client → Agent / 目标"));
        assertEquals(
                "TCP / HTTP proxy / HTTP",
                UiLanguage.translate("en", "TCP / HTTP 代理 / HTTP"));
        assertEquals(
                "Client to Agent or target, packet 7，TCP / SOCKS5 proxy",
                UiLanguage.translate("en", "Client 到 Agent 或目标，数据包 7，TCP / SOCKS5 代理"));
        assertEquals(
                "●  Enabled; waiting for VPN or HTTP / SOCKS5 proxy",
                UiLanguage.translate("en", "●  已开启，等待 VPN 或 HTTP / SOCKS5 代理"));
        assertEquals(
                "Failed to clear capture: disk unavailable",
                UiLanguage.translate("en", "清空抓包失败：disk unavailable"));
        assertEquals(
                "Plaintext capture results",
                UiLanguage.translate("en", "明文抓包结果"));
        assertEquals(
                "Search IP, port, protocol, or preview content",
                UiLanguage.translate("en", "搜索 IP、端口、协议或预览内容"));
        assertEquals(
                "Packet size: largest first",
                UiLanguage.translate("en", "包大小：大到小"));
        assertEquals(
                "Filters apply immediately · content search covers only the payload preview",
                UiLanguage.translate("en", "筛选立即应用 · 内容搜索仅覆盖 Payload 预览"));
        assertEquals(
                "This permanently deletes all current capture records. If capture is enabled, recording will continue.",
                UiLanguage.translate(
                        "en",
                        "将永久删除当前全部抓包记录。抓包若已开启，清空后会继续记录。"));
        assertEquals(
                "Total 1250 packets · showing latest 500 packets · PCAP 24 MB · tap for details",
                UiLanguage.translate(
                        "en",
                        "共 1250 包 · 显示最近 500 包 · PCAP 24 MB · 点击查看详情"));
        assertEquals(
                "Payload Hex (first 512 / total 10000 bytes)",
                UiLanguage.translate(
                        "en",
                        "Payload Hex（预览前 512 / 共 10000 字节）"));
        assertEquals(
                "api.example.com, already in direct rules; tap to select for removal",
                UiLanguage.translate(
                        "en",
                        "api.example.com，已在直连规则中，点击选择后可移出"));
        assertFalse(UiLanguage.translate("en", "VPN 运行中 · 模拟 GEO 启动中")
                .matches(".*[\\u4e00-\\u9fff].*"));
    }
}
