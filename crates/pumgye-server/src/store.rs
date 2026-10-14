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
}
pub struct Store {
    connection: Connection,
    _ownership: File,
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
        // Hold ownership before opening SQLite. WAL is private to this authority.
        let _ = private_file(path)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS policy (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (revision INTEGER PRIMARY KEY, at_unix INTEGER NOT NULL, actor TEXT NOT NULL, sha256 TEXT NOT NULL);")?;
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
                audit(&transaction, 1, "bootstrap", &bytes)?;
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
    pub fn audit_after(&self, after: u64) -> Result<Vec<AuditRecord>> {
        ensure!(after <= i64::MAX as u64, "invalid audit cursor");
        let mut statement=self.connection.prepare("SELECT revision,at_unix,actor,sha256 FROM audit WHERE revision>?1 ORDER BY revision LIMIT 100")?;
        Ok(statement
            .query_map([after as i64], |row| {
                Ok(AuditRecord {
                    revision: row.get::<_, i64>(0)? as u64,
                    at_unix: row.get::<_, i64>(1)? as u64,
                    actor: row.get(2)?,
                    sha256: row.get(3)?,
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
        ensure!(
            expected < i64::MAX as u64 && next.revision == expected + 1,
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
        audit(&transaction, next.revision, actor, &bytes)?;
        transaction.commit()?;
        Ok(())
    }
}
fn audit(
    transaction: &rusqlite::Transaction<'_>,
    revision: u64,
    actor: &str,
    bytes: &str,
) -> Result<()> {
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    transaction.execute(
        "INSERT INTO audit VALUES(?1,?2,?3,?4)",
        params![
            revision as i64,
            at as i64,
            actor,
            format!("{:x}", Sha256::digest(bytes.as_bytes()))
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
}
