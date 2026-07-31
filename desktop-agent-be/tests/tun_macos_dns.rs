#![cfg(target_os = "macos")]

use desktop_agent_be::tun_handler::route::macos_dns::pf_token_already_released;

#[test]
fn stale_pf_enable_token_release_is_idempotent() {
    assert!(pf_token_already_released(
        "pfctl: DIOCSTOPREF: Invalid argument"
    ));
    assert!(pf_token_already_released("token not found"));
    assert!(!pf_token_already_released("permission denied"));
}
