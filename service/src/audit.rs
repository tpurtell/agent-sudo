//! Append-only audit log.

use rusqlite::params;
use serde_json::Value;

use crate::db::Db;
use crate::util::now_ms;

pub fn record(db: &Db, actor: &str, kind: &str, subject: Option<&str>, detail: Value) {
    let result = db.lock().execute(
        "INSERT INTO audit (at, actor, kind, subject, detail_json) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![now_ms(), actor, kind, subject, detail.to_string()],
    );
    if let Err(e) = result {
        tracing::error!("failed to write audit record {kind}: {e}");
    }
    tracing::info!(target: "audit", actor, kind, subject, "{detail}");
}
