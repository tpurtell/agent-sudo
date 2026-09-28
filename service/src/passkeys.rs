//! Passkey (WebAuthn) ceremonies.
//!
//! Ceremony state lives in memory for five minutes, keyed by a random id the browser
//! echoes back. Registered credentials are stored as webauthn-rs `Passkey` JSON.

use rusqlite::params;
use serde::Serialize;
use webauthn_rs::prelude::*;

use crate::auth::User;
use crate::state::AppState;
use crate::util::{new_id, new_token, now_ms};

const CEREMONY_TTL_MS: i64 = 5 * 60_000;

pub enum Ceremony {
    Register {
        user_id: String,
        name: String,
        state: PasskeyRegistration,
    },
    Authenticate {
        user_id: String,
        state: PasskeyAuthentication,
    },
    Discoverable {
        state: DiscoverableAuthentication,
    },
}

pub fn build(cfg: &crate::config::ServiceConfig) -> anyhow::Result<Webauthn> {
    let origin = cfg.origin();
    Ok(WebauthnBuilder::new(&cfg.rp_id(), &origin)?
        .rp_name(&cfg.name)
        .build()?)
}

#[derive(Debug, Clone, Serialize)]
pub struct PasskeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

pub fn list(state: &AppState, user_id: &str) -> anyhow::Result<Vec<PasskeyInfo>> {
    let db = state.db.lock();
    let mut stmt = db.prepare("SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at")?;
    let rows = stmt
        .query_map([user_id], |r| {
            Ok(PasskeyInfo {
                id: r.get(0)?,
                name: r.get(1)?,
                created_at: r.get(2)?,
                last_used_at: r.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn stored(state: &AppState, user_id: &str) -> anyhow::Result<Vec<(String, Passkey)>> {
    let db = state.db.lock();
    let mut stmt = db.prepare("SELECT id, passkey_json FROM passkeys WHERE user_id = ?")?;
    let rows = stmt
        .query_map([user_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, json)| serde_json::from_str(&json).ok().map(|pk| (id, pk)))
        .collect())
}

fn put(state: &AppState, ceremony: Ceremony) -> String {
    let id = new_token();
    let now = now_ms();
    let mut map = state.ceremonies.lock().unwrap();
    map.retain(|_, (_, at)| now - *at < CEREMONY_TTL_MS);
    map.insert(id.clone(), (ceremony, now));
    id
}

fn take(state: &AppState, id: &str) -> Option<Ceremony> {
    let mut map = state.ceremonies.lock().unwrap();
    map.remove(id)
        .filter(|(_, at)| now_ms() - *at < CEREMONY_TTL_MS)
        .map(|(c, _)| c)
}

pub fn start_registration(
    state: &AppState,
    user: &User,
    name: &str,
) -> anyhow::Result<(String, serde_json::Value)> {
    let existing: Vec<CredentialID> = stored(state, &user.id)?
        .into_iter()
        .map(|(_, pk)| pk.cred_id().clone())
        .collect();
    let uuid = Uuid::parse_str(&user.webauthn_id)?;
    let (challenge, reg) = state.webauthn.start_passkey_registration(
        uuid,
        &user.name,
        &user.display_name,
        Some(existing),
    )?;
    // Ask for a discoverable credential so "Sign in with a passkey" works without a
    // username. The server does not verify residency, so this is purely a client hint.
    let mut challenge = serde_json::to_value(&challenge)?;
    if let Some(sel) = challenge["publicKey"]["authenticatorSelection"].as_object_mut() {
        sel.insert("residentKey".into(), "preferred".into());
        sel.insert("requireResidentKey".into(), false.into());
    }
    let id = put(
        state,
        Ceremony::Register {
            user_id: user.id.clone(),
            name: name.to_string(),
            state: reg,
        },
    );
    Ok((id, challenge))
}

pub fn finish_registration(
    state: &AppState,
    user: &User,
    ceremony: &str,
    credential: &RegisterPublicKeyCredential,
) -> anyhow::Result<PasskeyInfo> {
    let Some(Ceremony::Register {
        user_id,
        name,
        state: reg,
    }) = take(state, ceremony)
    else {
        anyhow::bail!("registration expired; please try again");
    };
    if user_id != user.id {
        anyhow::bail!("registration belongs to another user");
    }
    let passkey = state
        .webauthn
        .finish_passkey_registration(credential, &reg)?;
    let id = new_id("pk");
    let now = now_ms();
    state.db.lock().execute(
        "INSERT INTO passkeys (id, user_id, cred_id, name, passkey_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, user.id, serde_json::to_string(passkey.cred_id())?, name, serde_json::to_string(&passkey)?, now],
    )?;
    Ok(PasskeyInfo {
        id,
        name,
        created_at: now,
        last_used_at: None,
    })
}

/// Start authentication. With a user, the browser is told which credentials to use;
/// without, it offers any discoverable passkey for this site.
pub fn start_authentication(
    state: &AppState,
    user: Option<&User>,
) -> anyhow::Result<(String, RequestChallengeResponse)> {
    match user {
        Some(user) => {
            let keys: Vec<Passkey> = stored(state, &user.id)?
                .into_iter()
                .map(|(_, pk)| pk)
                .collect();
            if keys.is_empty() {
                anyhow::bail!("no passkeys registered");
            }
            let (challenge, auth) = state.webauthn.start_passkey_authentication(&keys)?;
            Ok((
                put(
                    state,
                    Ceremony::Authenticate {
                        user_id: user.id.clone(),
                        state: auth,
                    },
                ),
                challenge,
            ))
        }
        None => {
            let (challenge, auth) = state.webauthn.start_discoverable_authentication()?;
            Ok((
                put(state, Ceremony::Discoverable { state: auth }),
                challenge,
            ))
        }
    }
}

fn record_use(
    state: &AppState,
    user_id: &str,
    result: &AuthenticationResult,
) -> anyhow::Result<()> {
    for (id, mut pk) in stored(state, user_id)? {
        if pk.cred_id() == result.cred_id() {
            pk.update_credential(result);
            state.db.lock().execute(
                "UPDATE passkeys SET passkey_json = ?1, last_used_at = ?2 WHERE id = ?3",
                params![serde_json::to_string(&pk)?, now_ms(), id],
            )?;
        }
    }
    Ok(())
}

/// Finish authentication and return the authenticated user id.
pub fn finish_authentication(
    state: &AppState,
    ceremony: &str,
    credential: &PublicKeyCredential,
) -> anyhow::Result<String> {
    match take(state, ceremony) {
        Some(Ceremony::Authenticate {
            user_id,
            state: auth,
        }) => {
            let result = state
                .webauthn
                .finish_passkey_authentication(credential, &auth)?;
            if !result.user_verified() {
                anyhow::bail!("the authenticator did not verify the user");
            }
            record_use(state, &user_id, &result)?;
            Ok(user_id)
        }
        Some(Ceremony::Discoverable { state: auth }) => {
            let (uuid, _cred) = state
                .webauthn
                .identify_discoverable_authentication(credential)?;
            let user = crate::auth::user_by_webauthn_id(state, &uuid.to_string())?
                .ok_or_else(|| anyhow::anyhow!("this passkey is not registered here"))?;
            let keys: Vec<DiscoverableKey> = stored(state, &user.id)?
                .into_iter()
                .map(|(_, pk)| DiscoverableKey::from(pk))
                .collect();
            let result = state
                .webauthn
                .finish_discoverable_authentication(credential, auth, &keys)?;
            if !result.user_verified() {
                anyhow::bail!("the authenticator did not verify the user");
            }
            record_use(state, &user.id, &result)?;
            Ok(user.id)
        }
        _ => anyhow::bail!("sign-in expired; please try again"),
    }
}
