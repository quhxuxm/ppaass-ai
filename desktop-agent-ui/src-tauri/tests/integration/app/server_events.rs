use desktop_agent_ui::app::next_reconnect_delay;

#[test]
fn reconnect_backoff_is_bounded() {
    let mut delay = 1;
    for _ in 0..20 {
        delay = next_reconnect_delay(delay);
    }
    assert_eq!(delay, 60);
}
