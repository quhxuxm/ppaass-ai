use super::common::*;

fn heartbeat(entry_id: &str, address: &str, received_at: i64) -> ProxyEntryRegistration {
    ProxyEntryRegistration {
        entry_id: entry_id.to_string(),
        version: "1.2.3".to_string(),
        advertised_address: address.to_string(),
        received_at,
    }
}

#[tokio::test]
async fn admin_proxy_catalog_exposes_registered_entry_online_state() {
    let (_directory, store, _sessions, _handoffs, _keys, app) = test_app_with_components().await;
    let timestamp = current_timestamp();
    store
        .register_proxy_entry(heartbeat("entry-online", "online.example:443", timestamp))
        .await
        .unwrap();
    store
        .register_proxy_entry(heartbeat(
            "entry-offline",
            "offline.example:443",
            timestamp - 91,
        ))
        .await
        .unwrap();

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/proxy-addresses")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let (cookie, _csrf) = login_admin(&app).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/proxy-addresses")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let entries = body["proxy_addresses"].as_array().unwrap();
    let online = entries
        .iter()
        .find(|entry| entry["entry_id"] == "entry-online")
        .unwrap();
    assert_eq!(online["entry_version"], "1.2.3");
    assert_eq!(online["entry_online"], true);
    assert_eq!(online["address"], "online.example:443");
    let offline = entries
        .iter()
        .find(|entry| entry["entry_id"] == "entry-offline")
        .unwrap();
    assert_eq!(offline["entry_online"], false);
}
