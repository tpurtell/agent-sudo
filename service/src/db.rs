//! SQLite storage. One connection behind a mutex: this service handles a handful of
//! hosts and approvers, and SQLite in WAL mode answers in microseconds.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

const MIGRATIONS: &[&str] = &[
    // 1: initial schema
    r#"
    CREATE TABLE users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name TEXT NOT NULL,
        password_hash TEXT,
        webauthn_id TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL CHECK (role IN ('admin', 'approver', 'viewer')),
        created_at INTEGER NOT NULL,
        disabled_at INTEGER
    );
    CREATE TABLE invites (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        user_id TEXT NOT NULL REFERENCES users(id),
        created_by TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    );
    CREATE TABLE passkeys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        cred_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        passkey_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER
    );
    CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        label TEXT NOT NULL,
        kind TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        revoked_at INTEGER
    );
    CREATE TABLE push_subscriptions (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES devices(id),
        endpoint TEXT NOT NULL UNIQUE,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_success_at INTEGER,
        failures INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE web_sessions (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        user_id TEXT NOT NULL REFERENCES users(id),
        device_id TEXT NOT NULL REFERENCES devices(id),
        csrf TEXT NOT NULL,
        auth_method TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER NOT NULL,
        strong_auth_at INTEGER,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER
    );
    CREATE TABLE hosts (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        hostname TEXT NOT NULL,
        public_key TEXT NOT NULL,
        groups_json TEXT NOT NULL DEFAULT '[]',
        hostd_version TEXT NOT NULL DEFAULT '',
        enrolled_by TEXT,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        revoked_at INTEGER
    );
    CREATE TABLE enrollment_tokens (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        created_by TEXT,
        name_hint TEXT,
        groups_json TEXT NOT NULL DEFAULT '[]',
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER,
        used_by_host TEXT
    );
    CREATE TABLE requests (
        id TEXT PRIMARY KEY,
        code TEXT NOT NULL,
        host_id TEXT NOT NULL REFERENCES hosts(id),
        client_request_id TEXT NOT NULL,
        state TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        deadline_at INTEGER NOT NULL,
        envelope_json TEXT NOT NULL,
        class TEXT NOT NULL,
        features_json TEXT NOT NULL,
        assessment_json TEXT,
        decision_json TEXT,
        decided_at INTEGER,
        grant_id TEXT,
        delegation_id TEXT,
        user_name TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        command_key TEXT NOT NULL,
        quiet INTEGER NOT NULL DEFAULT 0,
        flagged_at INTEGER,
        UNIQUE (host_id, client_request_id)
    );
    CREATE INDEX requests_state ON requests(state, created_at);
    CREATE INDEX requests_created ON requests(created_at);
    CREATE INDEX requests_user ON requests(user_name, created_at);
    CREATE TABLE grants (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('grant', 'delegation')),
        label TEXT NOT NULL,
        spec_json TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_from_request TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER,
        revoked_by TEXT,
        uses INTEGER NOT NULL DEFAULT 0,
        max_uses INTEGER,
        last_used_at INTEGER,
        paused_at INTEGER,
        pause_reason TEXT
    );
    CREATE TABLE audit (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        at INTEGER NOT NULL,
        actor TEXT NOT NULL,
        kind TEXT NOT NULL,
        subject TEXT,
        detail_json TEXT NOT NULL
    );
    CREATE INDEX audit_at ON audit(at);
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    "#,
    // 0.2.0: the per-day delegation budget counts a rule's recent approvals.
    r#"
    CREATE INDEX requests_delegation ON requests(delegation_id, decided_at);
    "#,
];

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        Self::init(conn)
    }

    pub fn memory() -> Result<Db> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Db> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;",
        )?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        for (i, migration) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(migration)
                .with_context(|| format!("applying migration {}", i + 1))?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)?;
            tx.commit()?;
        }
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_row("SELECT value FROM settings WHERE key = ?", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.lock().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_and_stores_settings() {
        let db = Db::memory().unwrap();
        assert_eq!(db.setting("x").unwrap(), None);
        db.set_setting("x", "1").unwrap();
        db.set_setting("x", "2").unwrap();
        assert_eq!(db.setting("x").unwrap().as_deref(), Some("2"));
    }

    #[test]
    fn reopening_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        Db::open(&path).unwrap().set_setting("k", "v").unwrap();
        let db = Db::open(&path).unwrap();
        assert_eq!(db.setting("k").unwrap().as_deref(), Some("v"));
    }
}
