use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use std::process::Command;
#[test]
fn missing_native_permit_seed_refuses_before_database_or_listener_binding() {
    let root = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let database = root.path().join("authority.sqlite3");
    let config = root.path().join("permit-key.json");
    let public = SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes();
    std::fs::write(&config,serde_json::json!({"issuer_ref":"pumgye","key_epoch":1,"public_key":STANDARD.encode(public),"seed_env":"OWNED_PERMIT_SEED"}).to_string()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pumgye"))
        .args([
            "--listen",
            &listener.local_addr().unwrap().to_string(),
            "--database",
            database.to_str().unwrap(),
            "--permit-key",
            config.to_str().unwrap(),
        ])
        .env("PUMGYE_ADMIN_TOKEN", "owned-admin-credential-32-bytes-long")
        .env(
            "PUMGYE_DECISION_TOKEN",
            "owned-decision-credential-32-bytes-long",
        )
        .env_remove("OWNED_PERMIT_SEED")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("native permit signing resources unavailable")
    );
    assert!(!database.exists());
}
