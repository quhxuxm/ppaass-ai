package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class MockGeoConfigTest {
    @Test
    public void presetSelectionUsesStableCoordinates() {
        MockGeoConfig.Selection selection = MockGeoConfig.selectionForInput(
                "tokyo",
                "0",
                "0",
                "12.5");

        assertTrue(selection.enabled());
        assertEquals("tokyo", selection.mode);
        assertEquals("东京", selection.label);
        assertEquals("东京", selection.summary());
        assertEquals(35.6762, selection.latitude, 0.000001);
        assertEquals(139.6503, selection.longitude, 0.000001);
        assertEquals(12.5f, selection.accuracyMeters, 0.0001f);
    }

    @Test
    public void floridaPresetUsesStateCenterCoordinates() {
        MockGeoConfig.Selection selection = MockGeoConfig.selectionForInput(
                "florida",
                "0",
                "0",
                "8");

        assertTrue(selection.enabled());
        assertEquals("佛罗里达", selection.label);
        assertEquals(27.994402, selection.latitude, 0.000001);
        assertEquals(-81.760254, selection.longitude, 0.000001);
    }

    @Test
    public void customSelectionParsesSignedCoordinates() {
        MockGeoConfig.Selection selection = MockGeoConfig.selectionForInput(
                MockGeoConfig.MODE_CUSTOM,
                "-33.8688",
                "151.2093",
                "8");

        assertTrue(selection.enabled());
        assertEquals(-33.8688, selection.latitude, 0.000001);
        assertEquals(151.2093, selection.longitude, 0.000001);
        assertEquals("自定义", selection.label);
    }

    @Test
    public void offSelectionIgnoresCoordinateInput() {
        MockGeoConfig.Selection selection = MockGeoConfig.selectionForInput(
                MockGeoConfig.MODE_OFF,
                "invalid",
                "invalid",
                "invalid");

        assertFalse(selection.enabled());
        assertEquals("未选择地点", selection.summary());
    }

    @Test
    public void invalidCoordinateRangesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> MockGeoConfig.parseLatitude("90.1"));
        assertThrows(IllegalArgumentException.class, () -> MockGeoConfig.parseLongitude("-180.1"));
        assertThrows(IllegalArgumentException.class, () -> MockGeoConfig.parseLatitude("NaN"));
        assertThrows(IllegalArgumentException.class, () -> MockGeoConfig.parseLongitude("Infinity"));
    }

    @Test
    public void invalidAccuracyIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> MockGeoConfig.parseAccuracy("0"));
        assertThrows(IllegalArgumentException.class, () -> MockGeoConfig.parseAccuracy("-1"));
        assertThrows(IllegalArgumentException.class, () -> MockGeoConfig.parseAccuracy("10001"));
        assertThrows(IllegalArgumentException.class, () -> MockGeoConfig.parseAccuracy("NaN"));
    }

    @Test
    public void optionIndexRoundTripsEveryMode() {
        String[] labels = MockGeoConfig.optionLabels();
        for (int index = 0; index < labels.length; index++) {
            String mode = MockGeoConfig.modeForOptionIndex(index);
            assertEquals(index, MockGeoConfig.optionIndexForMode(mode));
        }
    }

    @Test
    public void unknownPersistedModeFallsBackToOff() {
        assertEquals(MockGeoConfig.MODE_OFF, MockGeoConfig.normalizeMode("not-a-real-geo"));
        assertEquals(MockGeoConfig.MODE_OFF, MockGeoConfig.normalizeMode(null));
    }
}
