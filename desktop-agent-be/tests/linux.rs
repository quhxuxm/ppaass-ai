#![cfg(target_os = "linux")]

use desktop_agent_be::linux::validate_tun_capabilities;

#[test]
fn accepts_network_capabilities_for_an_unprivileged_user() {
    let status = "Name:\tdesktop-agent\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000003000\n";
    assert!(validate_tun_capabilities(status).is_ok());
    assert!(validate_tun_capabilities("CapEff:\tffffffffffffffff\n").is_ok());
}

#[test]
fn rejects_missing_capabilities_even_for_root() {
    for capabilities in ["0", "1000", "2000", "4000"] {
        let status = format!("Uid:\t0\t0\t0\t0\nCapEff:\t{capabilities}\n");
        let error = validate_tun_capabilities(&status).unwrap_err();
        assert!(error.contains("CAP_NET_ADMIN"));
        assert!(error.contains("CAP_NET_RAW"));
    }
}

#[test]
fn permitted_or_malformed_capabilities_do_not_authorize_tun() {
    for status in [
        "",
        "CapPrm:\t0000000000003000\n",
        "CapEff:\tinvalid\n",
        "CapEff:\t10000000000000000\n",
    ] {
        assert!(validate_tun_capabilities(status).is_err());
    }
}
