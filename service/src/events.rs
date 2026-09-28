//! Live updates for open browsers (Server-Sent Events) and host long-polls.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Request {
        id: String,
        state: String,
        version: i64,
    },
    Grants,
    Hosts,
    Devices,
    Settings,
    Users,
}

impl Event {
    pub fn name(&self) -> &'static str {
        match self {
            Event::Request { .. } => "request",
            Event::Grants => "grants",
            Event::Hosts => "hosts",
            Event::Devices => "devices",
            Event::Settings => "settings",
            Event::Users => "users",
        }
    }
}
