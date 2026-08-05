use proxy_control_protocol::{
    AUTHORIZATION_SNAPSHOT_PATH, AuthorizationSnapshot, AuthorizationSnapshotQuery,
    AuthorizationSnapshotResponse, CONTROL_PROTOCOL_VERSION, DEFAULT_AUTHORIZATION_SNAPSHOT_LIMIT,
    ENTRY_REGISTRATION_PATH, EntryRegistrationRequest, EntryRegistrationResponse,
    MAX_ADVERTISED_ADDRESS_BYTES, MAX_AUTHORIZATION_SNAPSHOT_ENTRIES,
    MAX_AUTHORIZATION_SNAPSHOT_LIMIT, MAX_ENTRY_VERSION_BYTES,
};

#[test]
fn entry_registration_contract_is_versioned_and_stable() {
    assert_eq!(CONTROL_PROTOCOL_VERSION, 4);
    assert_eq!(ENTRY_REGISTRATION_PATH, "/control/v1/entries/register");
    assert_eq!(MAX_ENTRY_VERSION_BYTES, 64);
    assert_eq!(MAX_ADVERTISED_ADDRESS_BYTES, 512);

    let request = EntryRegistrationRequest {
        entry_id: "entry-production-01".to_string(),
        version: "1.2.3".to_string(),
        protocol_version: CONTROL_PROTOCOL_VERSION,
        advertised_address: "proxy.example.com:443".to_string(),
    };
    let request_json = serde_json::to_value(&request).unwrap();
    assert_eq!(request_json["entry_id"], "entry-production-01");
    assert_eq!(request_json["version"], "1.2.3");
    assert_eq!(request_json["protocol_version"], 4);
    assert_eq!(request_json["advertised_address"], "proxy.example.com:443");

    let response_json = serde_json::json!({
        "registry_instance_id": "registry-1",
        "protocol_version": 4,
        "received_at": 1_785_490_000_i64,
    });
    let response: EntryRegistrationResponse = serde_json::from_value(response_json).unwrap();
    assert_eq!(response.registry_instance_id, "registry-1");
    assert_eq!(response.protocol_version, CONTROL_PROTOCOL_VERSION);
    assert_eq!(response.received_at, 1_785_490_000);
}

#[test]
fn authorization_snapshot_page_contract_contains_public_authorizations_and_revision() {
    assert_eq!(
        AUTHORIZATION_SNAPSHOT_PATH,
        "/control/v1/authorizations/snapshot"
    );
    assert_eq!(DEFAULT_AUTHORIZATION_SNAPSHOT_LIMIT, 256);
    assert_eq!(MAX_AUTHORIZATION_SNAPSHOT_LIMIT, 256);
    assert_eq!(MAX_AUTHORIZATION_SNAPSHOT_ENTRIES, 100_000);

    let query = AuthorizationSnapshotQuery {
        after_username: Some("alice".to_string()),
        revision: Some(42),
        limit: Some(128),
    };
    let query_json = serde_json::to_value(&query).unwrap();
    assert_eq!(query_json["after_username"], "alice");
    assert_eq!(query_json["revision"], 42);
    assert_eq!(query_json["limit"], 128);

    let response = AuthorizationSnapshotResponse {
        authorizations: vec![AuthorizationSnapshot {
            username: "alice".to_string(),
            public_key_pem: "public-key".to_string(),
            permissions: vec!["example.com:443".to_string()],
            enabled: true,
            key_version: 2,
            expires_at: Some(1_785_490_000),
        }],
        revision: 42,
        next_cursor: Some("alice".to_string()),
    };
    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["revision"], 42);
    assert_eq!(json["authorizations"][0]["username"], "alice");
    assert_eq!(json["authorizations"][0]["key_version"], 2);
    assert_eq!(json["authorizations"][0]["expires_at"], 1_785_490_000_i64);
    assert_eq!(json["next_cursor"], "alice");
}
