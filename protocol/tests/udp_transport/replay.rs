use super::*;

#[test]
fn accepts_out_of_order_and_rejects_duplicate_and_too_old() {
    let mut replay = ReplayWindow::new();
    assert!(replay.commit(10_000));
    assert!(replay.commit(9_998));
    assert!(replay.commit(9_999));
    assert!(!replay.may_accept(9_999));
    assert!(!replay.commit(9_999));

    assert!(replay.commit(10_000 - (UDP_REPLAY_WINDOW_SIZE as u64 - 1)));
    assert!(!replay.may_accept(10_000 - UDP_REPLAY_WINDOW_SIZE as u64));
}

#[test]
fn large_forward_jump_clears_old_bits() {
    let mut replay = ReplayWindow::new();
    assert!(replay.commit(1));
    assert!(replay.commit(10_000));
    assert!(!replay.may_accept(1));
    assert!(replay.may_accept(9_999));

    assert!(replay.commit(u64::MAX));
    assert!(!replay.may_accept(0));
}
