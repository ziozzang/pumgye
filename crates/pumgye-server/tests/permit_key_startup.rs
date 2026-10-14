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

#[test]
fn invalid_authentication_trust_refuses_before_database_or_listener_binding() {
    let root = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let database = root.path().join("authority.sqlite3");
    let config = root.path().join("trust.json");
    std::fs::write(&config, r#"{"entries":[]}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pumgye"))
        .args([
            "--listen",
            &listener.local_addr().unwrap().to_string(),
            "--database",
            database.to_str().unwrap(),
            "--authentication-trust",
            config.to_str().unwrap(),
        ])
        .env("PUMGYE_ADMIN_TOKEN", "owned-admin-credential-32-bytes-long")
        .env(
            "PUMGYE_DECISION_TOKEN",
            "owned-decision-credential-32-bytes-long",
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("native authentication trust unavailable")
    );
    assert!(!database.exists());
}

#[test]
fn native_startup_persists_removal_and_refuses_retired_keys_before_binding() {
    let root = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let database = root.path().join("authority.sqlite3");
    let initial = root.path().join("initial.json");
    let config = root.path().join("trust.json");
    std::fs::write(
        &initial,
        r#"{"revision":1,"policy":{"version":1,"information_classes":["public"],"services":{}}}"#,
    )
    .unwrap();
    let write = |epoch, seed| {
        let public = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        std::fs::write(&config, serde_json::json!({"entries":[{"issuer_ref":"hopae","key_epoch":epoch,"identity_epoch":"owned1","service":"orders","audience":"orders-api","minimum_revision":1,"public_key":STANDARD.encode(public)}]}).to_string()).unwrap();
    };
    let run = |trust: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pumgye"));
        command.args([
            "--listen",
            &listener.local_addr().unwrap().to_string(),
            "--database",
            database.to_str().unwrap(),
            "--policy",
            initial.to_str().unwrap(),
        ]);
        if trust {
            command.args(["--authentication-trust", config.to_str().unwrap()]);
        }
        let output = command
            .env("PUMGYE_ADMIN_TOKEN", "owned-admin-credential-32-bytes-long")
            .env(
                "PUMGYE_DECISION_TOKEN",
                "owned-decision-credential-32-bytes-long",
            )
            .output()
            .unwrap();
        assert!(!output.status.success());
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    write(1, 7);
    assert!(!run(true).contains("receipt key retirement or rotation refused"));
    assert!(database.exists());
    assert!(!run(false).contains("receipt key retirement or rotation refused"));
    write(2, 7);
    assert!(run(true).contains("receipt key retirement or rotation refused"));
    write(2, 8);
    assert!(!run(true).contains("receipt key retirement or rotation refused"));
    let connection = rusqlite::Connection::open(&database).unwrap();
    let stored: String = connection
        .query_row("SELECT document FROM receipt_keys", [], |row| row.get(0))
        .unwrap();
    let registry = hopae_grpc::receipt_keys::Registry::decode(&stored, 1).unwrap();
    assert_eq!(registry.revision(), 3);
}

#[test]
fn missing_live_validation_credential_refuses_before_database_or_binding() {
    let root = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let database = root.path().join("authority.sqlite3");
    let trust = root.path().join("trust.json");
    let live = root.path().join("live.json");
    let public = SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes();
    std::fs::write(&trust, serde_json::json!({"entries":[{"issuer_ref":"hopae","key_epoch":1,"identity_epoch":"owned","service":"orders","audience":"orders-api","minimum_revision":1,"public_key":STANDARD.encode(public)}]}).to_string()).unwrap();
    std::fs::write(&live, serde_json::json!({"issuer_ref":"hopae","address":"https://127.0.0.1:1","server_name":"hopae.example.test","ca":"absent-ca","certificate":"absent-certificate","key":"absent-key","token_env":"OWNED_LIVE_CALLER"}).to_string()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pumgye"))
        .args([
            "--listen",
            &listener.local_addr().unwrap().to_string(),
            "--database",
            database.to_str().unwrap(),
            "--authentication-trust",
            trust.to_str().unwrap(),
            "--authentication-live",
            live.to_str().unwrap(),
        ])
        .env("PUMGYE_ADMIN_TOKEN", "owned-admin-credential-32-bytes-long")
        .env(
            "PUMGYE_DECISION_TOKEN",
            "owned-decision-credential-32-bytes-long",
        )
        .env_remove("OWNED_LIVE_CALLER")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("native live authentication resources unavailable")
    );
    assert!(!database.exists());
}
