//! Reference-only owning permit key configuration; never accepts inline seeds.
use crate::permit::Signer;
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use std::{io::Read, path::Path};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub public_key: String,
    pub seed_env: String,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
impl Configuration {
    pub fn load(&self, resolve: &dyn Fn(&str) -> Option<String>) -> Result<Signer, Refused> {
        if self.issuer_ref.is_empty()
            || self.issuer_ref.len() > 128
            || !self
                .issuer_ref
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || !(1..=9_007_199_254_740_991).contains(&self.key_epoch)
            || self.seed_env.is_empty()
            || self.seed_env.len() > 128
            || !self
                .seed_env
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || self.public_key.len() != 44
        {
            return Err(Refused);
        }
        let mut public = [0; 32];
        if STANDARD
            .decode_slice(&self.public_key, &mut public)
            .map_err(|_| Refused)?
            != 32
        {
            return Err(Refused);
        }
        if VerifyingKey::from_bytes(&public)
            .map_err(|_| Refused)?
            .is_weak()
        {
            return Err(Refused);
        }
        let encoded = Zeroizing::new(resolve(&self.seed_env).ok_or(Refused)?);
        if encoded.len() != 44 {
            return Err(Refused);
        }
        let mut seed = Zeroizing::new([0; 32]);
        if STANDARD
            .decode_slice(encoded.as_bytes(), seed.as_mut())
            .map_err(|_| Refused)?
            != 32
        {
            return Err(Refused);
        }
        let key = SigningKey::from_bytes(&seed);
        if key.verifying_key().to_bytes() != public {
            return Err(Refused);
        }
        Signer::new(self.issuer_ref.clone(), self.key_epoch, key).map_err(|_| Refused)
    }
}
pub fn load(path: &Path, resolve: &dyn Fn(&str) -> Option<String>) -> Result<Signer, Refused> {
    let file = std::fs::File::open(path).map_err(|_| Refused)?;
    if !file.metadata().map_err(|_| Refused)?.is_file() {
        return Err(Refused);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Refused)?;
    if bytes.len() > 16 * 1024 {
        return Err(Refused);
    }
    let config: Configuration = serde_json::from_slice(&bytes).map_err(|_| Refused)?;
    config.load(resolve)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configuration() -> Configuration {
        let key = SigningKey::from_bytes(&[11; 32]);
        Configuration {
            issuer_ref: "pumgye".into(),
            key_epoch: 1,
            public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            seed_env: "OWNED_PERMIT_SEED".into(),
        }
    }
    #[test]
    fn resources_require_exact_declared_seed_and_public_identity() {
        let config = configuration();
        assert!(config.load(&|_| Some(STANDARD.encode([11; 32]))).is_ok());
        assert!(config.load(&|_| None).is_err());
        assert!(config.load(&|_| Some(STANDARD.encode([12; 32]))).is_err());
        for value in ["".to_string(), "invalid".to_string(), "A".repeat(100_000)] {
            assert!(config.load(&|_| Some(value.clone())).is_err());
        }
        let mut invalid = configuration();
        invalid.key_epoch = 0;
        assert!(
            invalid
                .load(&|_| panic!("invalid public config cannot resolve secrets"))
                .is_err()
        );
        invalid = configuration();
        invalid.key_epoch = 9_007_199_254_740_992;
        assert!(
            invalid
                .load(&|_| panic!("invalid epoch cannot resolve secrets"))
                .is_err()
        );
        invalid = configuration();
        invalid.public_key = STANDARD.encode([0; 32]);
        assert!(
            invalid
                .load(&|_| panic!("weak public identity cannot resolve secrets"))
                .is_err()
        );
        invalid = configuration();
        invalid.seed_env = "bad reference".into();
        assert!(
            invalid
                .load(&|_| panic!("invalid reference cannot resolve secrets"))
                .is_err()
        );
    }
    #[test]
    fn bounded_files_refuse_inline_secrets_and_preserve_reference_only_schema() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("key.json");
        let config = configuration();
        let value = serde_json::json!({"issuer_ref":config.issuer_ref,"key_epoch":1,"public_key":config.public_key,"seed_env":config.seed_env});
        std::fs::write(&file, value.to_string()).unwrap();
        assert!(load(&file, &|_| Some(STANDARD.encode([11; 32]))).is_ok());
        let mut inline = value;
        inline["seed"] = serde_json::json!("inline-fixture-value");
        std::fs::write(&file, inline.to_string()).unwrap();
        assert!(
            load(&file, &|_| panic!(
                "inline secret config cannot resolve environment"
            ))
            .is_err()
        );
        std::fs::write(&file, vec![b' '; 16 * 1024 + 1]).unwrap();
        assert!(
            load(&file, &|_| panic!(
                "oversized config cannot resolve environment"
            ))
            .is_err()
        );
    }
}
