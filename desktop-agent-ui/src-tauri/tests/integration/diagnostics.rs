use std::time::Duration;

use desktop_agent_ui::diagnostics::quic_attempt_timeout;

#[test]
fn auto_quic_probe_covers_native_udp_fallback_deadline() {
    let timeout = quic_attempt_timeout("auto", 20);
    assert!(timeout * 3 >= Duration::from_secs(26));
}

#[test]
fn non_auto_quic_probe_keeps_short_timeout() {
    assert_eq!(quic_attempt_timeout("udp", 20), Duration::from_secs(3));
    assert_eq!(quic_attempt_timeout("tcp", 20), Duration::from_secs(3));
}
