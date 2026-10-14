fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/decision.proto");
    let output = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    std::fs::write(output.join("gateway.proto"), hopae_grpc::GATEWAY_PROTO)?;
    tonic_prost_build::configure()
        .extern_path(".hangang.hopae.v1", "::hopae_grpc::v1")
        .compile_protos(
            &[std::path::Path::new("proto/decision.proto")],
            &[std::path::Path::new("proto"), &output],
        )?;
    Ok(())
}
