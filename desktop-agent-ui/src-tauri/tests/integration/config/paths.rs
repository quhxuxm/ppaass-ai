use std::fs;

use desktop_agent_ui::config::locate_config_path_in;

#[test]
fn runtime_search_only_accepts_root_agent_config() {
    let directory = tempfile::tempdir().unwrap();
    let template_dir = directory.path().join("config");
    fs::create_dir(&template_dir).unwrap();
    fs::write(
        template_dir.join("agent.toml"),
        "listen_addr = \"127.0.0.1:1\"\n",
    )
    .unwrap();

    assert!(locate_config_path_in([directory.path().to_path_buf()]).is_none());

    let runtime_path = directory.path().join("agent.toml");
    fs::write(&runtime_path, "listen_addr = \"127.0.0.1:1\"\n").unwrap();
    assert_eq!(
        locate_config_path_in([directory.path().to_path_buf()]),
        Some(runtime_path)
    );
}
