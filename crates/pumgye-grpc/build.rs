fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/decision.proto");
    tonic_prost_build::compile_protos("proto/decision.proto")?;
    Ok(())
}
