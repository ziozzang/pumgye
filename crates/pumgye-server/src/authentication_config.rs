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
pub struct RevisionFloor {
    pub issuer: String,
    pub service: String,
    pub audience: String,
    pub identity_epoch: String,
    pub minimum_revision: u64,
}
pub struct Trust {
    floors: Vec<RevisionFloor>,
    issuers: HashMap<String, Issuer>,
    entries: usize,
}
impl Trust {
    /// Compile the observed SDK policy from this immutable native trust snapshot.
    /// The additional floors are native startup policy, never request fields.
    #[cfg(feature = "observed-authentication")]
    pub(crate) fn observed_policy(
        &self,
        issuer_ref: &str,
        minimum_application_generation: u64,
        minimum_key_registry_revision: u64,
    ) -> Result<hopae_grpc::observed_client::ServiceTrustPolicy, Refused> {
        use hopae_grpc::observed_client::{ServiceScope, ServiceTrustPolicy};
        let issuer = self.issuers.get(issuer_ref).ok_or(Refused)?;
        let floors: Vec<_> = self
            .floors
            .iter()
            .filter(|f| f.issuer == issuer_ref)
            .collect();
        Ok(ServiceTrustPolicy {
            issuer_ref: issuer_ref.to_owned(),
            key_epoch: issuer.key_epoch,
            verifying_key: ed25519_dalek::VerifyingKey::from_bytes(&issuer.public)
                .map_err(|_| Refused)?,
            identity_authority: issuer.identity_epoch.clone(),
            scopes: floors
                .iter()
                .map(|f| ServiceScope {
                    service: f.service.clone(),
                    audience: f.audience.clone(),
                })
                .collect(),
            minimum_profile_revision: floors
                .iter()
                .map(|f| f.minimum_revision)
                .min()
                .ok_or(Refused)?,
            minimum_application_generation,
            minimum_key_registry_revision,
        })
    }

    #[cfg(feature = "observed-authentication")]
    pub(crate) fn human_observed_policy(
        &self,
        issuer_ref: &str,
        scopes: Vec<hopae_grpc::human_observed_client::HumanScope>,
        minimum_source_revision: u64,
        minimum_application_generation: u64,
        minimum_key_registry_revision: u64,
    ) -> Result<hopae_grpc::human_observed_client::HumanTrustPolicy, Refused> {
        let issuer = self.issuers.get(issuer_ref).ok_or(Refused)?;
        if scopes.is_empty()
            || scopes.len() > 128
            || scopes.iter().any(|scope| {
                issuer
                    .scopes
                    .get(&scope.service)
                    .and_then(|a| a.get(&scope.audience))
                    .is_none()
            })
        {
            return Err(Refused);
        }
        Ok(hopae_grpc::human_observed_client::HumanTrustPolicy {
            issuer_ref: issuer_ref.to_owned(),
            key_epoch: issuer.key_epoch,
            verifying_key: ed25519_dalek::VerifyingKey::from_bytes(&issuer.public)
                .map_err(|_| Refused)?,
            identity_authority: issuer.identity_epoch.clone(),
            scopes,
            minimum_source_revision,
            minimum_application_generation,
            minimum_key_registry_revision,
        })
    }
    #[cfg(feature = "observed-authentication")]
    pub(crate) fn human_observed_scope(
        &self,
        c: &hopae_grpc::v1::AuthenticationReceiptContext,
    ) -> Result<(), Refused> {
        let issuer = self.issuers.get(&c.issuer_ref).ok_or(Refused)?;
        let identity = c.identity.as_ref().ok_or(Refused)?;
        let epoch =
            hopae_grpc::human_epoch::decode(&c.identity_authority_epoch).map_err(|_| Refused)?;
        let scope = issuer
            .scopes
            .get(&c.service)
            .and_then(|a| a.get(&c.audience))
            .ok_or(Refused)?;
        if identity.kind != 1
            // Hopae seals the presented level; AAL3 only for opted-in applications.
            || !(1..=3).contains(&identity.aal)
            || issuer.key_epoch != c.key_epoch
            || epoch.authority != issuer.identity_epoch
            || epoch.source_scope_revision < scope.minimum_revision()
        {
            return Err(Refused);
        }
        Ok(())
    }

    /// Native scope-specific floor, in addition to SDK signature/time checks.
    #[cfg(feature = "observed-authentication")]
    pub(crate) fn observed_scope(
        &self,
        c: &hopae_grpc::v1::AuthenticationReceiptContext,
    ) -> Result<(), Refused> {
        let issuer = self.issuers.get(&c.issuer_ref).ok_or(Refused)?;
        let identity = c.identity.as_ref().ok_or(Refused)?;
        let epoch = hopae_grpc::service_epoch::decode_clock(&c.identity_authority_epoch)
            .map_err(|_| Refused)?;
        if issuer.key_epoch != c.key_epoch
            || epoch.epoch.authority != issuer.identity_epoch
            || issuer
                .scopes
                .get(&c.service)
                .and_then(|audiences| audiences.get(&c.audience))
                .is_none_or(|scope| identity.revision < scope.minimum_revision())
        {
            return Err(Refused);
        }
        Ok(())
    }
    /// Separate typed Workload trust compiled from the same native pins/scopes.
    /// No Service decoder or caller-selected class participates in this path.
    #[cfg(feature = "observed-authentication")]
    pub(crate) fn workload_observed_policy(
        &self,
        issuer_ref: &str,
        minimum_application_generation: u64,
        minimum_key_registry_revision: u64,
    ) -> Result<hopae_grpc::workload_observed_client::WorkloadTrustPolicy, Refused> {
        let policy = self.observed_policy(
            issuer_ref,
            minimum_application_generation,
            minimum_key_registry_revision,
        )?;
        Ok(hopae_grpc::workload_observed_client::WorkloadTrustPolicy {
            issuer_ref: policy.issuer_ref,
            key_epoch: policy.key_epoch,
            verifying_key: policy.verifying_key,
            identity_authority: policy.identity_authority,
            scopes: policy
                .scopes
                .into_iter()
                .map(
                    |scope| hopae_grpc::workload_observed_client::WorkloadScope {
                        service: scope.service,
                        audience: scope.audience,
                    },
                )
                .collect(),
            minimum_profile_revision: policy.minimum_profile_revision,
            minimum_application_generation: policy.minimum_application_generation,
            minimum_key_registry_revision: policy.minimum_key_registry_revision,
        })
    }
    #[cfg(feature = "observed-authentication")]
    pub(crate) fn workload_observed_scope(
        &self,
        c: &hopae_grpc::v1::AuthenticationReceiptContext,
    ) -> Result<(), Refused> {
        let issuer = self.issuers.get(&c.issuer_ref).ok_or(Refused)?;
        let identity = c.identity.as_ref().ok_or(Refused)?;
        let epoch =
            hopae_grpc::workload_epoch::decode(&c.identity_authority_epoch).map_err(|_| Refused)?;
        if identity.kind != 3
            || identity.aal != 0
            || issuer.key_epoch != c.key_epoch
            || epoch.authority != issuer.identity_epoch
            || identity.revision != epoch.profile_revision
            || identity.credential_generation != epoch.profile_revision
            || issuer
                .scopes
                .get(&c.service)
                .and_then(|audiences| audiences.get(&c.audience))
                .is_none_or(|scope| identity.revision < scope.minimum_revision())
        {
            return Err(Refused);
        }
        Ok(())
    }
    pub fn compile(document: Document) -> Result<Self, Refused> {
        if document.entries.is_empty() || document.entries.len() > 128 {
            return Err(Refused);
        }
        let count = document.entries.len();
        let mut floors = Vec::with_capacity(count);
        let mut issuers = HashMap::<String, Issuer>::new();
        let mut material_owners = HashMap::<[u8; 32], String>::new();
        for entry in document.entries {
            floors.push(RevisionFloor {
                issuer: entry.issuer_ref.clone(),
                service: entry.service.clone(),
                audience: entry.audience.clone(),
                identity_epoch: entry.identity_epoch.clone(),
                minimum_revision: entry.minimum_revision,
            });
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
            floors,
            issuers,
            entries: count,
        })
    }
    /// Public descriptors only; persistent ownership remains in the server store.
    pub fn receipt_keys(&self) -> Vec<hopae_grpc::receipt_keys::Key> {
        self.issuers
            .iter()
            .map(|(issuer, value)| hopae_grpc::receipt_keys::Key {
                issuer_ref: issuer.clone(),
                purpose: hopae_grpc::receipt::Purpose::Authentication,
                epoch: value.key_epoch,
                public_key: value.public,
            })
            .collect()
    }
    pub fn revision_floors(&self) -> &[RevisionFloor] {
        &self.floors
    }
    pub fn has_issuer(&self, issuer: &str) -> bool {
        self.issuers.contains_key(issuer)
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
            identity_authority_epoch: "epoch1:service:3:app:1",
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

#[cfg(all(test, feature = "observed-authentication"))]
mod human_tests {
    use super::*;
    fn trust() -> Trust {
        Trust::compile(Document {
            entries: vec![Entry {
                issuer_ref: "human-hop".into(),
                key_epoch: 1,
                identity_epoch: "owned".into(),
                service: "orders".into(),
                audience: "orders-api".into(),
                minimum_revision: 7,
                public_key: STANDARD.encode(
                    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                        .verifying_key()
                        .as_bytes(),
                ),
            }],
        })
        .unwrap()
    }
    fn context() -> hopae_grpc::v1::AuthenticationReceiptContext {
        hopae_grpc::v1::AuthenticationReceiptContext {
            issuer_ref: "human-hop".into(),
            key_epoch: 1,
            identity_authority_epoch: hopae_grpc::human_epoch::encode(
                "owned",
                7,
                1,
                "123456789abcdef0123456789abcdef0",
            )
            .unwrap(),
            identity: Some(hopae_grpc::v1::ReceiptIdentity {
                subject_ref: format!("human1:{}", "a".repeat(64)),
                kind: 1,
                aal: 1,
                revision: 1,
                credential_generation: 2,
            }),
            service: "orders".into(),
            audience: "orders-api".into(),
            request_sha256: vec![1; 32],
        }
    }
    #[test]
    fn human_source_floor_is_not_a_user_revision_floor_and_class_is_fixed() {
        let trust = trust();
        let base = context();
        trust.human_observed_scope(&base).unwrap();
        let mut other = base.clone();
        other.identity.as_mut().unwrap().revision = 999;
        other.identity.as_mut().unwrap().credential_generation = 1000;
        trust.human_observed_scope(&other).unwrap();
        for kind in [0, 2, 3, 4, u32::MAX] {
            let mut bad = base.clone();
            bad.identity.as_mut().unwrap().kind = kind;
            assert!(trust.human_observed_scope(&bad).is_err());
        }
        for aal in [0, 4, u32::MAX] {
            let mut bad = base.clone();
            bad.identity.as_mut().unwrap().aal = aal;
            assert!(trust.human_observed_scope(&bad).is_err());
        }
        // Hopae seals AAL3 for opted-in applications (ADR-0018 decision 11).
        let mut high = base.clone();
        high.identity.as_mut().unwrap().aal = 3;
        trust.human_observed_scope(&high).unwrap();
        let mut bad = base;
        bad.identity_authority_epoch =
            hopae_grpc::human_epoch::encode("owned", 6, 1, "123456789abcdef0123456789abcdef0")
                .unwrap();
        assert!(trust.human_observed_scope(&bad).is_err());
    }
    #[test]
    fn human_policy_cannot_promote_an_unknown_configured_service() {
        let trust = trust();
        assert!(
            trust
                .human_observed_policy("human-hop", vec![], 7, 1, 1)
                .is_err()
        );
        let scope = hopae_grpc::human_observed_client::HumanScope {
            service: "wrong".into(),
            audience: "orders-api".into(),
            app_id: "app".into(),
            route_id: "route".into(),
            route_revision: 1,
            destination_sha256: [1; 32],
            header_policy_revision: 1,
            header_names: vec![],
            reserved_names: vec![],
        };
        assert!(
            trust
                .human_observed_policy("human-hop", vec![scope], 7, 1, 1)
                .is_err()
        );
    }
}
