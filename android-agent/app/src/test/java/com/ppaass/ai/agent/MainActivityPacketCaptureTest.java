package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class MainActivityPacketCaptureTest {
    @Test
    public void shortViewportKeepsMinimumPacketListHeight() {
        assertEquals(
                360,
                MainActivityPacketCapture.calculateCaptureListHeightPx(
                        800,
                        620,
                        12,
                        360));
    }

    @Test
    public void tallViewportUsesAllRemainingPacketListHeight() {
        assertEquals(
                788,
                MainActivityPacketCapture.calculateCaptureListHeightPx(
                        1400,
                        600,
                        12,
                        360));
    }

    @Test
    public void payloadPreviewIsBoundedAndBackwardsCompatible() {
        assertEquals(
                4096,
                MainActivityPacketCapture.boundedPayloadPreviewLength(
                        10_000,
                        -1,
                        10_000));
        assertEquals(
                512,
                MainActivityPacketCapture.boundedPayloadPreviewLength(
                        10_000,
                        512,
                        512));
        assertTrue(MainActivityPacketCapture.payloadPreviewIsTruncated(
                10_000,
                10_000,
                4096,
                false));
        assertFalse(MainActivityPacketCapture.payloadPreviewIsTruncated(
                512,
                512,
                512,
                false));
        assertEquals(
                "预览前 512 / 共 10000 字节",
                MainActivityPacketCapture.payloadPreviewSummary(512, 10_000));
        assertEquals(
                "abc",
                MainActivityPacketCapture.truncatePayloadText("abcdef", 3));
        assertEquals(
                "00 11 22",
                MainActivityPacketCapture.truncatePayloadHex("00 11 22 33", 3));
    }

    @Test
    public void minimumPacketSizeIncludesTheExactBoundary() {
        assertTrue(MainActivityPacketCapture.packetMeetsMinimumSize(1024, 1024d));
        assertFalse(MainActivityPacketCapture.packetMeetsMinimumSize(1023, 1024d));
        assertTrue(MainActivityPacketCapture.packetMeetsMinimumSize(0, 0d));
        assertTrue(MainActivityPacketCapture.packetMeetsMinimumSize(1, Double.NaN));
    }

    @Test
    public void captureOperationsRequireLiveReadyIdleUi() {
        assertTrue(MainActivityPacketCapture.captureOperationCanStart(false, false, true));
        assertFalse(MainActivityPacketCapture.captureOperationCanStart(true, false, true));
        assertFalse(MainActivityPacketCapture.captureOperationCanStart(false, true, true));
        assertFalse(MainActivityPacketCapture.captureOperationCanStart(false, false, false));
    }

    @Test
    public void captureFailureDetailUsesMessageThenExceptionType() {
        assertEquals(
                "disk unavailable",
                MainActivityPacketCapture.captureFailureDetail(
                        new IllegalStateException("  disk unavailable  ")));
        assertEquals(
                "IllegalArgumentException",
                MainActivityPacketCapture.captureFailureDetail(
                        new IllegalArgumentException()));
        assertEquals(
                "未知错误",
                MainActivityPacketCapture.captureFailureDetail(null));
    }
}
