use clap::Parser;
use desktop_agent_be::cli::CliArgs;

#[test]
fn product_cli_rejects_public_proxy_address_arguments() {
    assert!(
        CliArgs::try_parse_from(["desktop-agent", "--proxy", "proxy.example.com:443"]).is_err()
    );
    assert!(
        CliArgs::try_parse_from([
            "desktop-agent",
            "--managed-proxy-address",
            "proxy.example.com:443"
        ])
        .is_err()
    );
}
