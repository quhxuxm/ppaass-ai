use proxy_control_protocol::{
    CONTROL_PROTOCOL_VERSION, ENTRY_REGISTRATION_PATH, EntryRegistrationRequest,
    EntryRegistrationResponse, MAX_ADVERTISED_ADDRESS_BYTES, MAX_ENTRY_VERSION_BYTES,
};

#[test]
fn entry_registration_contract_is_versioned_and_stable() {
    assert_eq!(CONTROL_PROTOCOL_VERSION, 3);
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
    assert_eq!(request_json["protocol_version"], 3);
    assert_eq!(request_json["advertised_address"], "proxy.example.com:443");

    let response_json = serde_json::json!({
        "registry_instance_id": "registry-1",
        "protocol_version": 3,
        "received_at": 1_785_490_000_i64,
    });
    let response: EntryRegistrationResponse = serde_json::from_value(response_json).unwrap();
    assert_eq!(response.registry_instance_id, "registry-1");
    assert_eq!(response.protocol_version, CONTROL_PROTOCOL_VERSION);
    assert_eq!(response.received_at, 1_785_490_000);
}
