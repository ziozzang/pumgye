//! Bounded, immutable, server-owned authentication trust. No secret fields.
use crate::authentication::{CheckedService, Configuration, Refused, ServiceTrust};
use base64::{Engine, engine::general_purpose::STANDARD};
use hopae_grpc::receipt_binding;
use serde::Deserialize;
use std::{collections::HashMap, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub entries: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub identity_epoch: String,
    pub service: String,
    pub audience: String,
    pub minimum_revision: u64,
    pub public_key: String,
}
struct Issuer {
    key_epoch: u64,
    identity_epoch: String,
    public: [u8; 32],
    scopes: HashMap<String, HashMap<String, ServiceTrust>>,
}
pub struct Trust {
    issuers: HashMap<String, Issuer>,
    entries: usize,
}
impl Trust {
    pub fn compile(document: Document) -> Result<Self, Refused> {
        if document.entries.is_empty() || document.entries.len() > 128 {
            return Err(Refused);
        }
        let count = document.entries.len();
        let mut issuers = HashMap::<String, Issuer>::new();
        let mut material_owners = HashMap::<[u8; 32], String>::new();
        for entry in document.entries {
            if entry.public_key.len() != 44 {
                return Err(Refused);
            }
            let mut public = [0; 32];
            if STANDARD
                .decode_slice(&entry.public_key, &mut public)
                .map_err(|_| Refused)?
                != 32
            {
                return Err(Refused);
            }
            if let Some(owner) = material_owners.get(&public) {
                if owner != &entry.issuer_ref {
                    return Err(Refused);
                }
            } else {
                material_owners.insert(public, entry.issuer_ref.clone());
            }
            let verifier = ServiceTrust::new(Configuration {
                issuer: entry.issuer_ref.clone(),
                key_epoch: entry.key_epoch,
                identity_epoch: entry.identity_epoch.clone(),
                service: entry.service.clone(),
                audience: entry.audience.clone(),
                minimum_revision: entry.minimum_revision,
                public_key: public,
            })?;
            let issuer = issuers.entry(entry.issuer_ref).or_insert_with(|| Issuer {
                key_epoch: entry.key_epoch,
                identity_epoch: entry.identity_epoch.clone(),
                public,
                scopes: HashMap::new(),
            });
            if issuer.key_epoch != entry.key_epoch
                || issuer.identity_epoch != entry.identity_epoch
                || issuer.public != public
            {
                return Err(Refused);
            }
            if issuer
                .scopes
                .entry(entry.service)
                .or_default()
                .insert(entry.audience, verifier)
                .is_some()
            {
                return Err(Refused);
            }
        }
        Ok(Self {
            issuers,
            entries: count,
        })
    }
    pub fn entries(&self) -> usize {
        self.entries
    }
    pub fn verify<'a>(
        &self,
        context: &receipt_binding::Context<'a>,
        bytes: &[u8],
        request_sha256: &[u8; 32],
        now_ms: u64,
    ) -> Result<CheckedService<'a>, Refused> {
        // Borrowed lookup: no issuer/service/audience concatenation or allocation.
        let issuer = self.issuers.get(context.issuer_ref).ok_or(Refused)?;
        if context.key_epoch != issuer.key_epoch {
            return Err(Refused);
        }
        issuer
            .scopes
            .get(context.service)
            .and_then(|audiences| audiences.get(context.audience))
            .ok_or(Refused)?
            .verify(context, bytes, request_sha256, now_ms)
    }
}
pub fn load(path: &Path) -> Result<Trust, Refused> {
    let file = std::fs::File::open(path).map_err(|_| Refused)?;
    if !file.metadata().map_err(|_| Refused)?.is_file() {
        return Err(Refused);
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Refused)?;
    if bytes.len() > 64 * 1024 {
        return Err(Refused);
    }
    Trust::compile(serde_json::from_slice(&bytes).map_err(|_| Refused)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use hopae_grpc::{PrincipalKind, receipt};
    fn entry() -> Entry {
        Entry {
            issuer_ref: "hopae".into(),
            key_epoch: 1,
            identity_epoch: "epoch1".into(),
            service: "orders".into(),
            audience: "orders-api".into(),
            minimum_revision: 3,
            public_key: STANDARD
                .encode(SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes()),
        }
    }
    #[test]
    fn scoped_borrowed_lookup_requires_server_selected_issuer_epoch_and_audience() {
        let trust = Trust::compile(Document {
            entries: vec![entry()],
        })
        .unwrap();
        assert_eq!(trust.entries(), 1);
        let context = receipt_binding::Context {
            issuer_ref: "hopae",
            key_epoch: 1,
            identity_authority_epoch: "epoch1:service:3",
            identity: receipt_binding::Identity {
                subject_ref: "s_0123456789abcdef0123456789abcdef0123456789abcdef",
                kind: PrincipalKind::Service,
                aal: 0,
                revision: 3,
                credential_generation: 3,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [5; 32],
        };
        let key = SigningKey::from_bytes(&[9; 32]);
        let bytes = receipt::sign(
            &key,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 1000,
                expires_ms: 1800,
                binding: receipt_binding::digest(&context, None).unwrap(),
                nonce: [7; 32],
            },
        )
        .unwrap();
        assert_eq!(
            trust
                .verify(&context, &bytes, &[5; 32], 1001)
                .unwrap()
                .revision(),
            3
        );
        let mut unknown = context;
        unknown.audience = "billing-api";
        assert!(trust.verify(&unknown, &bytes, &[5; 32], 1001).is_err());
        unknown.audience = "orders-api";
        unknown.key_epoch = 2;
        assert!(trust.verify(&unknown, &bytes, &[5; 32], 1001).is_err());
        unknown.key_epoch = 1;
        unknown.issuer_ref = "untrusted";
        assert!(trust.verify(&unknown, &bytes, &[5; 32], 1001).is_err());
    }
    #[test]
    fn duplicate_or_inconsistent_identity_and_cross_issuer_material_are_refused() {
        assert!(Trust::compile(Document { entries: vec![] }).is_err());
        assert!(
            Trust::compile(Document {
                entries: vec![entry(), entry()]
            })
            .is_err()
        );
        for case in ["key", "epoch", "identity", "material-owner"] {
            let mut changed = entry();
            changed.service = "billing".into();
            changed.audience = "billing-api".into();
            match case {
                "key" => {
                    changed.public_key = STANDARD
                        .encode(SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes())
                }
                "epoch" => changed.key_epoch = 2,
                "identity" => changed.identity_epoch = "other".into(),
                "material-owner" => changed.issuer_ref = "other".into(),
                _ => unreachable!(),
            }
            assert!(
                Trust::compile(Document {
                    entries: vec![entry(), changed]
                })
                .is_err(),
                "{case}"
            );
        }
        let mut second = entry();
        second.audience = "orders-reporting".into();
        assert_eq!(
            Trust::compile(Document {
                entries: vec![entry(), second]
            })
            .unwrap()
            .entries(),
            2
        );
        assert!(
            Trust::compile(Document {
                entries: (0..129).map(|_| entry()).collect()
            })
            .is_err()
        );
    }
    #[test]
    fn file_schema_refuses_inline_secret_unknown_fields_and_oversize() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("trust.json");
        let key = entry().public_key;
        let value = serde_json::json!({"entries":[{"issuer_ref":"hopae","key_epoch":1,"identity_epoch":"epoch1","service":"orders","audience":"orders-api","minimum_revision":3,"public_key":key}]});
        std::fs::write(&file, value.to_string()).unwrap();
        assert_eq!(load(&file).unwrap().entries(), 1);
        let mut unknown = value;
        unknown["entries"][0]["seed"] = serde_json::json!("inline-fixture-value");
        std::fs::write(&file, unknown.to_string()).unwrap();
        assert!(load(&file).is_err());
        std::fs::write(&file, vec![b' '; 64 * 1024 + 1]).unwrap();
        assert!(load(&file).is_err());
    }
}
