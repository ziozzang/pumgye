//! Single-owner persistence; queries use immutable memory views, never this database.
use crate::Document;
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MAX_POLICY_BYTES: usize = 1024 * 1024;
#[derive(serde::Serialize)]
pub struct AuditRecord {
    pub revision: u64,
    pub at_unix: u64,
    pub actor: String,
    pub sha256: String,
    /// `v1` (policy document) or `v2` (policy model version 2 document).
    pub document: String,
}
/// Maximum retained read-only simulation audit rows (oldest pruned first); rows
/// older than the configured age bound are also pruned on every insert.
pub const MAX_SIMULATION_AUDIT_ROWS: i64 = 100_000;
/// One administrative simulation (explain, batch explain or candidate diff).
/// Simulations never change policy; this is a separate table from publication audit.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SimulationRecord {
    pub id: u64,
    pub at_unix: u64,
    /// Always `simulation` (ADR 0019 event kind); never `enforced`.
    pub kind: &'static str,
    /// Authenticated transport actor (client certificate digest or loopback).
    pub actor: String,
    /// Untrusted caller-declared delegated actor, for correlation only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    pub operation: String,
    pub source: String,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_sha256: Option<String>,
    pub request_sha256: String,
    pub cases: u64,
    pub allowed: u64,
    pub denied: u64,
    pub unavailable: u64,
    pub changed: u64,
}
/// Shadow explanation row: id, created (Unix seconds), actor, rule JSON, reason.
pub type Explanation = (u64, u64, String, String, String);
pub struct Store {
    connection: Connection,
    _ownership: Ownership,
}
/// Explicitly release flock before closing: a concurrently forked child may
/// briefly retain the same open-file description until exec despite CLOEXEC.
struct Ownership(File);
impl Drop for Ownership {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}
impl Store {
    pub fn open(path: &Path, bootstrap: Option<&Path>) -> Result<(Self, Document)> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        ensure!(parent.is_dir(), "database parent must exist");
        let lock_path = path.with_extension("pumgye-owner");
        let ownership = private_file(&lock_path)?;
        ownership
            .try_lock_exclusive()
            .context("Pumgye database already has a runtime owner")?;
        let ownership = Ownership(ownership);
        // Hold ownership before opening SQLite. WAL is private to this authority.
        let _ = private_file(path)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS policy (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (revision INTEGER PRIMARY KEY, at_unix INTEGER NOT NULL, actor TEXT NOT NULL, sha256 TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS simulation_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at_unix INTEGER NOT NULL, kind TEXT NOT NULL CHECK(kind='simulation'), actor TEXT NOT NULL, on_behalf_of TEXT, operation TEXT NOT NULL, source TEXT NOT NULL, revision INTEGER NOT NULL, candidate_sha256 TEXT, request_sha256 TEXT NOT NULL, cases INTEGER NOT NULL, allowed INTEGER NOT NULL, denied INTEGER NOT NULL, unavailable INTEGER NOT NULL, changed INTEGER NOT NULL);")?;
        // Additive v2 schema: one revision sequence and one publication audit for
        // both document versions; authoritative model and shadow window persist.
        let has_kind: bool = connection
            .prepare("SELECT 1 FROM pragma_table_info('audit') WHERE name='document'")?
            .exists([])?;
        if !has_kind {
            connection.execute_batch(
                "ALTER TABLE audit ADD COLUMN document TEXT NOT NULL DEFAULT 'v1'",
            )?;
        }
        connection.execute_batch("CREATE TABLE IF NOT EXISTS policy_v2 (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS authority_model (id INTEGER PRIMARY KEY CHECK(id=1), model TEXT NOT NULL CHECK(model IN ('v1','v2')));
            CREATE TABLE IF NOT EXISTS model_history (id INTEGER PRIMARY KEY AUTOINCREMENT, at_unix INTEGER NOT NULL, model TEXT NOT NULL, revision INTEGER NOT NULL, actor TEXT NOT NULL, approval_ref TEXT, reason TEXT NOT NULL, gate TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS shadow_window (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS shadow_explanations (id INTEGER PRIMARY KEY AUTOINCREMENT, at_unix INTEGER NOT NULL, actor TEXT NOT NULL, rule TEXT NOT NULL, reason TEXT NOT NULL, retired INTEGER NOT NULL DEFAULT 0);")?;
        let stored: Option<String> = connection
            .query_row("SELECT document FROM policy WHERE id=1", [], |r| r.get(0))
            .optional()?;
        let document = match stored {
            Some(bytes) => {
                ensure!(
                    bytes.len() <= MAX_POLICY_BYTES,
                    "stored policy exceeds bound"
                );
                let document: Document = serde_json::from_str(&bytes)?;
                document.policy.compile()?;
                let revision: i64 =
                    connection
                        .query_row("SELECT revision FROM policy WHERE id=1", [], |r| r.get(0))?;
                ensure!(
                    revision > 0 && document.revision == revision as u64,
                    "stored policy revision mismatch"
                );
                document
            }
            None => {
                let bootstrap =
                    bootstrap.context("initial policy is required for an empty database")?;
                let mut bytes = Vec::new();
                File::open(bootstrap)?
                    .take((MAX_POLICY_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() <= MAX_POLICY_BYTES,
                    "initial policy exceeds bound"
                );
                let mut document: Document = serde_json::from_slice(&bytes)?;
                document.policy.compile()?;
                // The server owns revision issuance; bootstrap always begins at one.
                document.revision = 1;
                let bytes = serde_json::to_string(&document)?;
                let transaction = connection.transaction()?;
                transaction.execute("INSERT INTO policy VALUES(1,1,?1)", [&bytes])?;
                audit(&transaction, 1, "bootstrap", &bytes, "v1")?;
                transaction.commit()?;
                document
            }
        };
        Ok((
            Self {
                connection,
                _ownership: ownership,
            },
            document,
        ))
    }
    /// Persist ownership: a source-managed DB cannot silently become a native writer on restart.
    pub fn claim_source(&mut self, kubernetes: bool) -> Result<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS source_owner (id INTEGER PRIMARY KEY CHECK(id=1), source TEXT NOT NULL)")?;
        let owner: Option<String> = self
            .connection
            .query_row("SELECT source FROM source_owner WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        ensure!(
            owner.as_deref().is_none_or(|v| v == "kubernetes") && (kubernetes || owner.is_none()),
            "source-owned database requires Kubernetes reconciliation"
        );
        if kubernetes && owner.is_none() {
            self.connection
                .execute("INSERT INTO source_owner VALUES(1,'kubernetes')", [])?;
        }
        Ok(())
    }
    /// Startup-only public key publication. Queries never read this table.
    /// Empty configuration retires all active keys while preserving history.
    pub fn reconcile_receipt_keys(
        &mut self,
        keys: &[hopae_grpc::receipt_keys::Key],
        floors: &[pumgye_server::authentication_config::RevisionFloor],
    ) -> Result<()> {
        use hopae_grpc::receipt_keys::Registry;
        let transaction = self.connection.transaction()?;
        transaction.execute_batch("CREATE TABLE IF NOT EXISTS receipt_keys (id INTEGER PRIMARY KEY CHECK(id=1), document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS receipt_key_audit (revision INTEGER PRIMARY KEY, sha256 TEXT NOT NULL)")?;
        let stored: Option<String> = transaction
            .query_row("SELECT document FROM receipt_keys WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()?;
        let prior = stored
            .as_deref()
            .map(|bytes| {
                Registry::decode(bytes, 1)
                    .map_err(|_| anyhow::anyhow!("stored receipt key history refused"))
            })
            .transpose()?;
        let revision = prior
            .as_ref()
            .map_or(Some(1), |registry| registry.revision().checked_add(1))
            .context("receipt key revision exhausted")?;
        let next = Registry::compile(revision, keys, prior.as_ref())
            .map_err(|_| anyhow::anyhow!("receipt key retirement or rotation refused"))?;
        let bytes = next
            .encode()
            .map_err(|_| anyhow::anyhow!("receipt key snapshot refused"))?;
        transaction.execute("INSERT INTO receipt_keys VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET document=excluded.document", [&bytes])?;
        transaction.execute(
            "INSERT INTO receipt_key_audit VALUES(?1,?2)",
            params![
                revision as i64,
                format!("{:x}", Sha256::digest(bytes.as_bytes()))
            ],
        )?;
        transaction.execute_batch("CREATE TABLE IF NOT EXISTS authentication_floors (issuer TEXT NOT NULL, service TEXT NOT NULL, audience TEXT NOT NULL, identity_epoch TEXT NOT NULL, minimum_revision INTEGER NOT NULL, PRIMARY KEY(issuer,service,audience))")?;
        for floor in floors {
            ensure!(
                (1..=9_007_199_254_740_991).contains(&floor.minimum_revision),
                "invalid authentication revision floor"
            );
            let prior: Option<(String, i64)> = transaction.query_row("SELECT identity_epoch,minimum_revision FROM authentication_floors WHERE issuer=?1 AND service=?2 AND audience=?3", params![floor.issuer, floor.service, floor.audience], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
            ensure!(
                prior.is_none_or(|(epoch, revision)| epoch == floor.identity_epoch
                    && revision > 0
                    && floor.minimum_revision >= revision as u64),
                "authentication epoch or revision rollback refused"
            );
            transaction.execute("INSERT INTO authentication_floors VALUES(?1,?2,?3,?4,?5) ON CONFLICT(issuer,service,audience) DO UPDATE SET minimum_revision=excluded.minimum_revision", params![floor.issuer, floor.service, floor.audience, floor.identity_epoch, floor.minimum_revision as i64])?;
        }
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM authentication_floors", [], |row| {
                row.get(0)
            })?;
        ensure!(count <= 4096, "authentication floor history exhausted");
        transaction.commit()?;
        Ok(())
    }
    pub fn audit_after(&self, after: u64) -> Result<Vec<AuditRecord>> {
        ensure!(after <= i64::MAX as u64, "invalid audit cursor");
        let mut statement=self.connection.prepare("SELECT revision,at_unix,actor,sha256,document FROM audit WHERE revision>?1 ORDER BY revision LIMIT 100")?;
        Ok(statement
            .query_map([after as i64], |row| {
                Ok(AuditRecord {
                    revision: row.get::<_, i64>(0)? as u64,
                    at_unix: row.get::<_, i64>(1)? as u64,
                    actor: row.get(2)?,
                    sha256: row.get(3)?,
                    document: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Append one simulation audit row and prune beyond the retention bound.
    /// Returns the row ID. The policy and publication audit tables are untouched.
    pub fn record_simulation(
        &mut self,
        record: &SimulationRecord,
        max_age_seconds: u64,
    ) -> Result<u64> {
        let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.record_simulation_at(record, at, max_age_seconds)
    }
    /// [`Self::record_simulation`] at an explicit time (tests inject old rows).
    pub fn record_simulation_at(
        &mut self,
        record: &SimulationRecord,
        at: u64,
        max_age_seconds: u64,
    ) -> Result<u64> {
        ensure!(at <= i64::MAX as u64, "simulation time out of range");
        ensure!(
            record.revision <= i64::MAX as u64,
            "simulation revision out of range"
        );
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO simulation_audit (at_unix,kind,actor,on_behalf_of,operation,source,revision,candidate_sha256,request_sha256,cases,allowed,denied,unavailable,changed) VALUES(?1,'simulation',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                at as i64,
                record.actor,
                record.on_behalf_of,
                record.operation,
                record.source,
                record.revision as i64,
                record.candidate_sha256,
                record.request_sha256,
                record.cases as i64,
                record.allowed as i64,
                record.denied as i64,
                record.unavailable as i64,
                record.changed as i64,
            ],
        )?;
        let id = transaction.last_insert_rowid();
        transaction.execute(
            "DELETE FROM simulation_audit WHERE id <= ?1 OR at_unix < ?2",
            params![
                id - MAX_SIMULATION_AUDIT_ROWS,
                at.saturating_sub(max_age_seconds) as i64
            ],
        )?;
        transaction.commit()?;
        Ok(id as u64)
    }
    pub fn simulations_after(&self, after: u64) -> Result<Vec<SimulationRecord>> {
        ensure!(after <= i64::MAX as u64, "invalid audit cursor");
        let mut statement = self.connection.prepare("SELECT id,at_unix,actor,on_behalf_of,operation,source,revision,candidate_sha256,request_sha256,cases,allowed,denied,unavailable,changed FROM simulation_audit WHERE id>?1 ORDER BY id LIMIT 100")?;
        Ok(statement
            .query_map([after as i64], |row| {
                Ok(SimulationRecord {
                    id: row.get::<_, i64>(0)? as u64,
                    at_unix: row.get::<_, i64>(1)? as u64,
                    kind: "simulation",
                    actor: row.get(2)?,
                    on_behalf_of: row.get(3)?,
                    operation: row.get(4)?,
                    source: row.get(5)?,
                    revision: row.get::<_, i64>(6)? as u64,
                    candidate_sha256: row.get(7)?,
                    request_sha256: row.get(8)?,
                    cases: row.get::<_, i64>(9)? as u64,
                    allowed: row.get::<_, i64>(10)? as u64,
                    denied: row.get::<_, i64>(11)? as u64,
                    unavailable: row.get::<_, i64>(12)? as u64,
                    changed: row.get::<_, i64>(13)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    #[cfg(test)]
    pub fn reject_writes(&self) {
        self.connection
            .execute_batch("PRAGMA query_only=ON")
            .unwrap();
    }
    /// One durable transaction binds the policy, revision and audit receipt.
    pub fn publish(&mut self, expected: u64, next: &Document, actor: &str) -> Result<()> {
        // Revisions are one sequence across document versions: the next v1
        // revision may skip numbers used by version 2 publications.
        ensure!(
            expected < i64::MAX as u64
                && next.revision > expected
                && next.revision <= i64::MAX as u64,
            "invalid revision"
        );
        let bytes = serde_json::to_string(next)?;
        ensure!(bytes.len() <= MAX_POLICY_BYTES, "policy exceeds bound");
        let transaction = self.connection.transaction()?;
        ensure!(
            transaction.execute(
                "UPDATE policy SET revision=?1, document=?2 WHERE id=1 AND revision=?3",
                params![next.revision as i64, bytes, expected as i64]
            )? == 1,
            "durable revision conflict"
        );
        audit(&transaction, next.revision, actor, &bytes, "v1")?;
        transaction.commit()?;
        Ok(())
    }
    /// Highest revision issued in either document version.
    pub fn global_revision(&self) -> Result<u64> {
        let r: i64 = self.connection.query_row(
            "SELECT max(coalesce((SELECT revision FROM policy WHERE id=1),0), coalesce((SELECT revision FROM policy_v2 WHERE id=1),0), coalesce((SELECT max(revision) FROM audit),0))",
            [],
            |r| r.get(0),
        )?;
        Ok(r as u64)
    }
    pub fn load_v2(&self) -> Result<Option<(u64, String)>> {
        Ok(self
            .connection
            .query_row(
                "SELECT revision, document FROM policy_v2 WHERE id=1",
                [],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)),
            )
            .optional()?)
    }
    /// CAS publication of a version 2 document (`expected` 0: none yet). The
    /// optional model switch commits in the same transaction (cutover).
    pub fn publish_v2(
        &mut self,
        expected: u64,
        revision: u64,
        document: &str,
        actor: &str,
        model: Option<(&str, Option<&str>, &str, &str)>,
    ) -> Result<()> {
        ensure!(document.len() <= MAX_POLICY_BYTES, "policy exceeds bound");
        ensure!(revision <= i64::MAX as u64, "invalid revision");
        let transaction = self.connection.transaction()?;
        let current: Option<i64> = transaction
            .query_row("SELECT revision FROM policy_v2 WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        ensure!(
            current.map_or(0, |r| r as u64) == expected,
            "durable revision conflict"
        );
        transaction.execute(
            "INSERT INTO policy_v2 VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, document=excluded.document",
            params![revision as i64, document],
        )?;
        audit(&transaction, revision, actor, document, "v2")?;
        if let Some((model, approval, reason, gate)) = model {
            set_model(&transaction, model, revision, actor, approval, reason, gate)?;
        }
        transaction.commit()?;
        Ok(())
    }
    /// Republish the retained v1 document at a new revision and switch the model
    /// back to v1 in one transaction (ADR 0021 rollback).
    pub fn rollback_v1(
        &mut self,
        expected: u64,
        next: &Document,
        actor: &str,
        reason: &str,
    ) -> Result<()> {
        let bytes = serde_json::to_string(next)?;
        let transaction = self.connection.transaction()?;
        ensure!(
            transaction.execute(
                "UPDATE policy SET revision=?1, document=?2 WHERE id=1 AND revision=?3",
                params![next.revision as i64, bytes, expected as i64]
            )? == 1,
            "durable revision conflict"
        );
        audit(&transaction, next.revision, actor, &bytes, "v1")?;
        set_model(&transaction, "v1", next.revision, actor, None, reason, "{}")?;
        transaction.commit()?;
        Ok(())
    }
    pub fn model(&self) -> Result<String> {
        Ok(self
            .connection
            .query_row("SELECT model FROM authority_model WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or_else(|| "v1".into()))
    }
    pub fn model_history(&self) -> Result<Vec<serde_json::Value>> {
        let mut statement = self.connection.prepare("SELECT id,at_unix,model,revision,actor,approval_ref,reason,gate FROM model_history ORDER BY id DESC LIMIT 20")?;
        Ok(statement
            .query_map([], |r| {
                Ok(serde_json::json!({"id": r.get::<_, i64>(0)?, "at_unix": r.get::<_, i64>(1)?, "model": r.get::<_, String>(2)?,
                    "revision": r.get::<_, i64>(3)?, "actor": r.get::<_, String>(4)?, "approval_ref": r.get::<_, Option<String>>(5)?,
                    "reason": r.get::<_, String>(6)?, "gate": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(7)?).unwrap_or_default()}))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn save_shadow(&self, state: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO shadow_window VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
            [state],
        )?;
        Ok(())
    }
    pub fn load_shadow(&self) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row("SELECT state FROM shadow_window WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?)
    }
    pub fn add_explanation(&self, actor: &str, rule: &str, reason: &str) -> Result<u64> {
        let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM shadow_explanations WHERE retired=0",
            [],
            |r| r.get(0),
        )?;
        ensure!(count < 64, "explanation capacity");
        self.connection.execute(
            "INSERT INTO shadow_explanations (at_unix,actor,rule,reason) VALUES(?1,?2,?3,?4)",
            params![at as i64, actor, rule, reason],
        )?;
        Ok(self.connection.last_insert_rowid() as u64)
    }
    pub fn explanations(&self) -> Result<Vec<Explanation>> {
        let mut statement = self.connection.prepare("SELECT id,at_unix,actor,rule,reason FROM shadow_explanations WHERE retired=0 ORDER BY id")?;
        Ok(statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, i64>(1)? as u64,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
}
fn set_model(
    transaction: &rusqlite::Transaction<'_>,
    model: &str,
    revision: u64,
    actor: &str,
    approval: Option<&str>,
    reason: &str,
    gate: &str,
) -> Result<()> {
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    transaction.execute(
        "INSERT INTO authority_model VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET model=excluded.model",
        [model],
    )?;
    transaction.execute(
        "INSERT INTO model_history (at_unix,model,revision,actor,approval_ref,reason,gate) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![at as i64, model, revision as i64, actor, approval, reason, gate],
    )?;
    Ok(())
}
fn audit(
    transaction: &rusqlite::Transaction<'_>,
    revision: u64,
    actor: &str,
    bytes: &str,
    document: &str,
) -> Result<()> {
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    transaction.execute(
        "INSERT INTO audit (revision,at_unix,actor,sha256,document) VALUES(?1,?2,?3,?4,?5)",
        params![
            revision as i64,
            at as i64,
            actor,
            format!("{:x}", Sha256::digest(bytes.as_bytes())),
            document
        ],
    )?;
    Ok(())
}
fn private_file(path: &Path) -> Result<File> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        ensure!(
            meta.file_type().is_file(),
            "persistent paths must be regular files"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            ensure!(
                meta.nlink() == 1 && meta.uid() == unsafe { libc::geteuid() },
                "persistent files must have one link and belong to this owner"
            );
            ensure!(
                meta.permissions().mode() & 0o077 == 0,
                "persistent files must be private"
            );
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_retirement_survives_restart_and_failed_publication_is_atomic() {
        use hopae_grpc::{receipt::Purpose, receipt_keys::Key};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.sqlite3");
        let initial = root.path().join("initial.json");
        std::fs::write(&initial, r#"{"revision":1,"policy":{"version":1,"information_classes":["public"],"services":{}}}"#).unwrap();
        let key = |epoch, seed| Key {
            issuer_ref: "hopae".into(),
            purpose: Purpose::Authentication,
            epoch,
            public_key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        };
        let (mut store, _) = Store::open(&path, Some(&initial)).unwrap();
        store.reconcile_receipt_keys(&[key(1, 7)], &[]).unwrap();
        store.reconcile_receipt_keys(&[key(1, 7)], &[]).unwrap();
        store.reconcile_receipt_keys(&[], &[]).unwrap();
        drop(store);
        let (mut store, _) = Store::open(&path, None).unwrap();
        let snapshot = || {
            store
                .connection
                .query_row("SELECT document FROM receipt_keys", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap()
        };
        let before = snapshot();
        assert!(store.reconcile_receipt_keys(&[key(1, 7)], &[]).is_err());
        assert!(store.reconcile_receipt_keys(&[key(2, 7)], &[]).is_err());
        assert_eq!(
            before,
            store
                .connection
                .query_row("SELECT document FROM receipt_keys", [], |row| row
                    .get::<_, String>(0))
                .unwrap()
        );
        store.reconcile_receipt_keys(&[key(2, 8)], &[]).unwrap();
        store.reject_writes();
        assert!(store.reconcile_receipt_keys(&[], &[]).is_err());
        drop(store);
        let (mut store, _) = Store::open(&path, None).unwrap();
        store.reconcile_receipt_keys(&[key(2, 8)], &[]).unwrap();
        assert!(store.reconcile_receipt_keys(&[key(3, 7)], &[]).is_err());
    }
    #[test]
    fn identity_floor_survives_removal_restart_and_rejects_epoch_reset_atomically() {
        use pumgye_server::authentication_config::RevisionFloor;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.sqlite3");
        let initial = root.path().join("initial.json");
        std::fs::write(&initial, r#"{"revision":1,"policy":{"version":1,"information_classes":["public"],"services":{}}}"#).unwrap();
        let floor = |epoch: &str, revision| RevisionFloor {
            issuer: "hopae".into(),
            service: "orders".into(),
            audience: "orders-api".into(),
            identity_epoch: epoch.into(),
            minimum_revision: revision,
        };
        let (mut store, _) = Store::open(&path, Some(&initial)).unwrap();
        store
            .reconcile_receipt_keys(&[], &[floor("owned1", 7)])
            .unwrap();
        store.reconcile_receipt_keys(&[], &[]).unwrap();
        drop(store);
        let (mut store, _) = Store::open(&path, None).unwrap();
        for (epoch, revision) in [("owned1", 6), ("owned2", 8)] {
            assert!(
                store
                    .reconcile_receipt_keys(&[], &[floor(epoch, revision)])
                    .is_err()
            );
        }
        let audit_count: i64 = store
            .connection
            .query_row("SELECT count(*) FROM receipt_key_audit", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(audit_count, 2);
        store
            .reconcile_receipt_keys(&[], &[floor("owned1", 8)])
            .unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn child_inherited_descriptor_does_not_extend_released_owner_lock() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.sqlite3");
        let initial = root.path().join("initial.json");
        std::fs::write(&initial, r#"{"revision":1,"policy":{"version":1,"information_classes":["public"],"services":{}}}"#).unwrap();
        let (store, _) = Store::open(&path, Some(&initial)).unwrap();
        let mut pipe = [0; 2];
        // The child uses only async-signal-safe syscalls, no Rust allocations,
        // destructors, SQLite or inherited locks. It waits while retaining FDs.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        use std::os::fd::AsRawFd;
        let mut retained = [pipe[0] as u32, store._ownership.0.as_raw_fd() as u32];
        retained.sort_unstable();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                // Preserve only the synchronization pipe and inherited owner.
                // Other parallel tests may own listeners; never prolong them.
                libc::syscall(libc::SYS_close_range, 0u32, retained[0] - 1, 0u32);
                libc::syscall(
                    libc::SYS_close_range,
                    retained[0] + 1,
                    retained[1] - 1,
                    0u32,
                );
                libc::syscall(libc::SYS_close_range, retained[1] + 1, u32::MAX, 0u32);
                let mut byte = 0u8;
                libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe {
            libc::close(pipe[0]);
        }
        assert!(Store::open(&path, None).is_err());
        drop(store);
        let reopened = Store::open(&path, None);
        unsafe {
            libc::write(pipe[1], (&1u8 as *const u8).cast(), 1);
            libc::close(pipe[1]);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        assert!(reopened.is_ok(), "child must not retain released ownership");
    }
    #[test]
    fn single_owner_transaction_cas_and_restart() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.sqlite3");
        let initial = root.path().join("initial.json");
        std::fs::write(&initial, r#"{"revision":900,"policy":{"version":1,"information_classes":["public"],"services":{}}}"#).unwrap();
        let (mut store, mut doc) = Store::open(&path, Some(&initial)).unwrap();
        assert_eq!(doc.revision, 1);
        assert!(Store::open(&path, None).is_err());
        doc.revision = 2;
        store.publish(1, &doc, "administrator").unwrap();
        assert!(store.publish(1, &doc, "administrator").is_err());
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM audit", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            2
        );
        drop(store);
        let (store, recovered) = Store::open(&path, None).unwrap();
        assert_eq!(recovered.revision, 2);
        assert_eq!(recovered.policy, doc.policy);
        assert_eq!(
            store
                .connection
                .query_row("SELECT max(revision) FROM audit", [], |r| r
                    .get::<_, u32>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn simulation_audit_is_trimmed_by_age_and_count_on_insert() {
        let root = tempfile::tempdir().unwrap();
        let initial = root.path().join("initial.json");
        std::fs::write(&initial, r#"{"revision":1,"policy":{"version":1,"information_classes":["public"],"services":{}}}"#).unwrap();
        let (mut store, _) = Store::open(&root.path().join("p.sqlite3"), Some(&initial)).unwrap();
        let record = SimulationRecord {
            id: 0,
            at_unix: 0,
            kind: "simulation",
            actor: "fixture".into(),
            on_behalf_of: None,
            operation: "explain".into(),
            source: "published".into(),
            revision: 1,
            candidate_sha256: None,
            request_sha256: "0".repeat(64),
            cases: 1,
            allowed: 1,
            denied: 0,
            unavailable: 0,
            changed: 0,
        };
        let day = 86_400;
        let now = 1_800_000_000;
        store
            .record_simulation_at(&record, now - 40 * day, 30 * day)
            .unwrap();
        store
            .record_simulation_at(&record, now - 31 * day, 30 * day)
            .unwrap();
        store
            .record_simulation_at(&record, now - 29 * day, 30 * day)
            .unwrap();
        // The row older than 30 days relative to the newest insert is trimmed now.
        let id = store.record_simulation_at(&record, now, 30 * day).unwrap();
        let rows = store.simulations_after(0).unwrap();
        assert_eq!(
            rows.iter().map(|r| r.at_unix).collect::<Vec<_>>(),
            [now - 29 * day, now]
        );
        assert_eq!(rows.last().unwrap().id, id);
        // Publication audit is untouched by simulation retention.
        assert_eq!(store.audit_after(0).unwrap().len(), 1);
    }
}
