use poe_hook_deploy::*;

fn fake_build(dir: &std::path::Path) {
    std::fs::write(dir.join(LOADER_BUILD_NAME), b"loader").unwrap();
    std::fs::write(dir.join(CORE_DLL), b"core").unwrap();
}

#[test]
fn deploy_then_revert_restores_the_game_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let game = tmp.path().join("game");
    let dlls = tmp.path().join("dlls");
    let dumps = tmp.path().join("dumps");
    std::fs::create_dir_all(&game).unwrap();
    std::fs::create_dir_all(&dlls).unwrap();
    fake_build(&dlls);
    std::fs::write(game.join(GATEWAY_FILE), b"original").unwrap();

    let opts = DeployOptions {
        game_dir: game.clone(),
        dll_dir: dlls,
        mode: Mode::Private,
        gateway: Some(GatewayEntry {
            region: "Europe".into(),
            display_name: "Local".into(),
            host: "127.0.0.1".into(),
            port: 20481,
        }),
        position_sync_port: Some(20482),
        dump_dir: Some(dumps),
        login_mode: LoginMode::Standalone,
        trusted_servers: vec![
            "192.168.1.20:20481".into(),
            "192.168.1.20:6112".into(),
            "192.168.1.20:6112".into(),
        ],
    };
    let report = deploy(&opts).unwrap();
    assert_eq!(
        report.gateway.as_deref(),
        Some("Europe;Local;127.0.0.1:20481;127.0.0.1;false")
    );
    assert_eq!(std::fs::read(game.join(LOADER_DLL)).unwrap(), b"loader");
    assert_eq!(std::fs::read(game.join(CORE_DLL)).unwrap(), b"core");
    assert_eq!(
        std::fs::read(backup_path(&game.join(GATEWAY_FILE))).unwrap(),
        b"original"
    );
    assert_eq!(
        std::fs::read_to_string(game.join(STEAM_APPID_FILE)).unwrap(),
        STEAM_APPID
    );
    let cfg = std::fs::read_to_string(game.join(HOOK_CONFIG)).unwrap();
    assert!(cfg.contains("mode = \"private\""));
    assert!(cfg.contains("position_sync_port = 20482"));
    assert!(cfg.contains("dump_dir = '"));
    assert!(cfg.contains("login_mode = \"standalone\""));
    assert!(cfg.contains("trusted_servers = [\"192.168.1.20:20481\", \"192.168.1.20:6112\"]"));
    assert_eq!(report.trusted_servers.len(), 2);
    let table = toml_parses(&cfg);
    assert_eq!(table["login_mode"].as_str(), Some("standalone"));
    assert_eq!(table["trusted_servers"].as_array().unwrap().len(), 2);

    // A second deploy keeps the pristine backup and the user's config edits.
    std::fs::write(
        game.join(HOOK_CONFIG),
        cfg.replace("level = \"debug\"", "level = \"info\""),
    )
    .unwrap();
    deploy(&opts).unwrap();
    assert_eq!(
        std::fs::read(backup_path(&game.join(GATEWAY_FILE))).unwrap(),
        b"original"
    );
    assert!(
        std::fs::read_to_string(game.join(HOOK_CONFIG))
            .unwrap()
            .contains("level = \"info\"")
    );

    // Official mode puts the original list back and says so in the config.
    let official = DeployOptions {
        mode: Mode::Official,
        ..opts
    };
    deploy(&official).unwrap();
    assert_eq!(std::fs::read(game.join(GATEWAY_FILE)).unwrap(), b"original");
    let cfg = std::fs::read_to_string(game.join(HOOK_CONFIG)).unwrap();
    assert!(cfg.contains("mode = \"official\""));
    assert!(cfg.contains("login_mode = \"steam\""));
    assert!(cfg.contains("trusted_servers = []"));
    assert!(!cfg.contains("192.168.1.20"));
    let table = toml_parses(&cfg);
    assert_eq!(table["trusted_servers"].as_array().unwrap().len(), 0);

    revert(&game).unwrap();
    assert_eq!(std::fs::read(game.join(GATEWAY_FILE)).unwrap(), b"original");
    assert!(!backup_path(&game.join(GATEWAY_FILE)).exists());
    for name in [LOADER_DLL, CORE_DLL, HOOK_CONFIG, STEAM_APPID_FILE] {
        assert!(!game.join(name).exists(), "{name} still there");
    }
}

#[test]
fn deploy_core_replaces_only_the_core() {
    let tmp = tempfile::tempdir().unwrap();
    let game = tmp.path().join("game");
    let dlls = tmp.path().join("dlls");
    std::fs::create_dir_all(&game).unwrap();
    std::fs::create_dir_all(&dlls).unwrap();
    fake_build(&dlls);
    let target = deploy_core(&game, &dlls).unwrap();
    assert_eq!(target, game.join(CORE_DLL));
    assert!(!game.join(LOADER_DLL).exists());
}

/// The built-in template plus our edits must stay valid TOML.
fn toml_parses(text: &str) -> toml::Table {
    text.parse::<toml::Table>().expect("valid TOML")
}

#[test]
fn default_template_has_the_keys_we_set() {
    assert!(DEFAULT_HOOK_CONFIG.contains("mode = "));
    assert!(DEFAULT_HOOK_CONFIG.contains("[features]"));
    assert!(DEFAULT_HOOK_CONFIG.contains("login_mode = "));
    assert!(DEFAULT_HOOK_CONFIG.contains("trusted_servers = "));
}

#[test]
fn private_deploy_can_switch_back_to_the_steam_login() {
    let tmp = tempfile::tempdir().unwrap();
    let game = tmp.path().join("game");
    let dlls = tmp.path().join("dlls");
    std::fs::create_dir_all(&game).unwrap();
    std::fs::create_dir_all(&dlls).unwrap();
    fake_build(&dlls);
    let opts = DeployOptions {
        game_dir: game.clone(),
        dll_dir: dlls,
        mode: Mode::Private,
        gateway: None,
        position_sync_port: None,
        dump_dir: None,
        login_mode: LoginMode::Steam,
        trusted_servers: vec!["not an address:1".into()],
    };
    let report = deploy(&opts).unwrap();
    assert_eq!(report.warnings.len(), 1);
    let cfg = std::fs::read_to_string(game.join(HOOK_CONFIG)).unwrap();
    assert!(cfg.contains("login_mode = \"steam\""));
    assert!(cfg.contains("trusted_servers = []"));
    // A hand-edited list is replaced by the deploy's, like `mode`.
    toml_parses(&cfg);
}
