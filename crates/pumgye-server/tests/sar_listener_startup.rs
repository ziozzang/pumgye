#[cfg(target_os = "linux")]
#[test]
fn actual_binary_preflight_and_persistent_mtls_listener_use_native_publication() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sar_cli_fixture.py");
    let output = std::process::Command::new("python3")
        .arg(fixture)
        .arg(env!("CARGO_BIN_EXE_pumgye"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("PASS: actual binary"));
}
