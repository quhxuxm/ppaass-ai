use proxy_registry::{
    MAX_AUDIT_REASON_CHARS, MAX_KEY_REQUEST_MESSAGE_CHARS, MAX_KEY_REQUEST_REJECTION_REASON_CHARS,
    ValidationError, normalize_audit_reason, normalize_key_request_message,
    normalize_key_request_rejection_reason, normalize_permissions, normalize_username,
    parse_expires_at,
};

#[test]
fn username_validation_matches_proxy_path_rules() {
    assert_eq!(normalize_username(" alice ").unwrap(), "alice");
    assert_eq!(
        normalize_username("../alice").unwrap_err(),
        ValidationError::InvalidUsername
    );
    assert_eq!(
        normalize_username("alice/bob").unwrap_err(),
        ValidationError::InvalidUsername
    );
}

#[test]
fn parses_rfc3339_and_unix_expirations() {
    assert_eq!(
        parse_expires_at("alice", "2030-01-01T00:00:00Z").unwrap(),
        1_893_456_000
    );
    assert_eq!(
        parse_expires_at("alice", "1893456000").unwrap(),
        1_893_456_000
    );
}

#[test]
fn permissions_are_validated_sorted_and_deduplicated() {
    assert_eq!(
        normalize_permissions(&[
            "proxy.connect.udp".to_string(),
            "proxy.connect.tcp".to_string(),
            "proxy.connect.udp".to_string(),
        ])
        .unwrap(),
        ["proxy.connect.tcp", "proxy.connect.udp"]
    );
    assert!(matches!(
        normalize_permissions(&["Proxy.Connect".to_string()]).unwrap_err(),
        ValidationError::InvalidPermission(_)
    ));
}

#[test]
fn key_request_message_is_trimmed_and_bounded() {
    assert_eq!(
        normalize_key_request_message(Some("  请尽快审批\n谢谢  ".to_string())).unwrap(),
        Some("请尽快审批\n谢谢".to_string())
    );
    assert_eq!(
        normalize_key_request_message(Some(" \n\t ".to_string())).unwrap(),
        None
    );
    assert_eq!(
        normalize_key_request_message(Some("好".repeat(MAX_KEY_REQUEST_MESSAGE_CHARS + 1)))
            .unwrap_err(),
        ValidationError::KeyRequestMessageTooLong
    );
}

#[test]
fn key_request_rejection_reason_is_trimmed_and_bounded() {
    assert_eq!(
        normalize_key_request_rejection_reason(Some("  请补充用途说明后重新申请。  ".to_string()))
            .unwrap(),
        Some("请补充用途说明后重新申请。".to_string())
    );
    assert_eq!(
        normalize_key_request_rejection_reason(Some(" \n ".to_string())).unwrap(),
        None
    );
    assert_eq!(
        normalize_key_request_rejection_reason(Some(
            "拒".repeat(MAX_KEY_REQUEST_REJECTION_REASON_CHARS + 1)
        ))
        .unwrap_err(),
        ValidationError::KeyRequestRejectionReasonTooLong
    );
}

#[test]
fn audit_reason_is_required_trimmed_and_bounded() {
    assert_eq!(
        normalize_audit_reason("  已核实本次操作  ").unwrap(),
        "已核实本次操作"
    );
    assert_eq!(
        normalize_audit_reason(" \n ").unwrap_err(),
        ValidationError::EmptyAuditReason
    );
    assert_eq!(
        normalize_audit_reason(&"因".repeat(MAX_AUDIT_REASON_CHARS + 1)).unwrap_err(),
        ValidationError::AuditReasonTooLong
    );
}
