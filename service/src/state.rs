//! Shared application state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use webauthn_rs::Webauthn;

use crate::advisor::Advisor;
use crate::config::ServiceConfig;
use crate::db::Db;
use crate::events::Event;
use crate::passkeys::Ceremony;
use crate::push::Push;

pub struct AppState {
    pub cfg: ServiceConfig,
    pub db: Db,
    pub events: broadcast::Sender<Event>,
    pub advisor: Option<Arc<Advisor>>,
    pub webauthn: Webauthn,
    pub ceremonies: Mutex<HashMap<String, (Ceremony, i64)>>,
    pub push: Push,
    /// Host request nonces seen within the signature window.
    pub nonces: Mutex<HashMap<String, i64>>,
    /// Failed login attempts per key (user or address): (count, window start).
    pub login_failures: Mutex<HashMap<String, (u32, i64)>>,
    /// Consecutive declined evaluations per delegation.
    pub delegation_declines: Mutex<HashMap<String, u32>>,
    /// Pending digest counts per delegation.
    pub digests: Mutex<HashMap<String, Vec<String>>>,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    pub fn automation_enabled(&self) -> bool {
        self.cfg.policy.automation.enabled
            && self
                .db
                .setting("automation_enabled")
                .ok()
                .flatten()
                .as_deref()
                != Some("false")
    }
}
