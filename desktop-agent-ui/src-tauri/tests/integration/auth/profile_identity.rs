use desktop_agent_ui::auth::{validated_avatar_url, validated_display_name};

#[test]
fn profile_identity_is_bounded() {
    assert_eq!(
        validated_display_name(Some(" 昵称 ".to_string())).unwrap(),
        Some("昵称".to_string())
    );
    assert!(validated_display_name(Some("超过六个中文字".to_string())).is_err());
    assert!(validated_avatar_url(Some("https://example.com/a.png".to_string())).is_err());
}
