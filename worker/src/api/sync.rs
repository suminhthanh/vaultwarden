use axum::{Json, Router, extract::State as AxumState, http::StatusCode, response::IntoResponse, routing::get};
use serde_json::{Value, json};

use crate::AppState;
use crate::api::ciphers::cipher_to_json_with_attachments_and_folder;
use crate::api::collections::collection_to_json_for;
use crate::api::folders::folder_to_json;
use crate::api::organizations::membership_json;
use crate::api::sends::send_json;
use crate::auth::Headers;
use crate::db::models::{
    Cipher, CipherCollection, Collection, Favorite, Folder, FolderCipher, Membership, OrgPolicy,
    Organization, Send, TwoFactor, UserCollection,
};

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/sync", get(get_sync))
}

fn profile_for_sync(
    u: &crate::db::models::User,
    organizations: &[Value],
    two_factor_enabled: bool,
) -> Value {
    json!({
        "Object": "profile",
        "Id": u.uuid,
        "Name": u.name,
        "Email": u.email,
        "EmailVerified": u.verified_at.is_some(),
        "Premium": true,
        "PremiumFromOrganization": false,
        "MasterPasswordHint": u.password_hint,
        "Culture": "en-US",
        "TwoFactorEnabled": two_factor_enabled,
        "Key": u.akey,
        "PrivateKey": u.private_key,
        "SecurityStamp": u.security_stamp,
        "ForcePasswordReset": false,
        "UsesKeyConnector": false,
        "AvatarColor": u.avatar_color,
        "Organizations": organizations,
        "Providers": [],
        "ProviderOrganizations": [],
    })
}

fn policy_to_json(p: &OrgPolicy) -> Value {
    let data: Value = serde_json::from_str(&p.data).unwrap_or(Value::Null);
    json!({
        "Object": "policy",
        "Id": p.uuid,
        "OrganizationId": p.org_uuid,
        "Type": p.atype,
        "Data": data,
        "Enabled": p.enabled == 1,
    })
}

#[worker::send]
async fn get_sync(AxumState(state): AxumState<AppState>, headers: Headers) -> impl IntoResponse {
    let user = &headers.user;

    let folders = Folder::find_by_user(&state.db, &user.uuid).await.unwrap_or_default();
    let ciphers = Cipher::find_visible_to_user(&state.db, &user.uuid).await.unwrap_or_default();
    let favorite_uuids: std::collections::HashSet<String> = Favorite::cipher_uuids_for_user(&state.db, &user.uuid)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();

    let memberships = Membership::find_by_user(&state.db, &user.uuid).await.unwrap_or_default();
    let user_acls = UserCollection::find_by_user(&state.db, &user.uuid).await.unwrap_or_default();
    let mut organizations_json = Vec::new();
    let mut collections_json: Vec<Value> = Vec::new();
    let mut policies_json: Vec<Value> = Vec::new();
    for m in &memberships {
        let org_name = match Organization::find_by_uuid(&state.db, &m.org_uuid).await {
            Ok(Some(o)) => o.name,
            _ => "(unknown)".to_owned(),
        };
        organizations_json.push(membership_json(m, &org_name));
        if let Ok(cs) = Collection::find_by_org(&state.db, &m.org_uuid).await {
            for c in cs.iter() {
                let acl = user_acls.iter().find(|a| a.collection_uuid == c.uuid);
                collections_json.push(collection_to_json_for(c, m.atype, acl));
            }
        }
        if let Ok(ps) = OrgPolicy::find_by_org(&state.db, &m.org_uuid).await {
            policies_json.extend(ps.iter().map(policy_to_json));
        }
    }

    let folders_json: Vec<Value> = folders.iter().map(folder_to_json).collect();
    let user_folder_ids: std::collections::HashSet<String> =
        folders.iter().map(|f| f.uuid.clone()).collect();
    let mut ciphers_json: Vec<Value> = Vec::with_capacity(ciphers.len());
    for c in &ciphers {
        let coll_ids = if c.organization_uuid.is_some() {
            CipherCollection::list_by_cipher(&state.db, &c.uuid).await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let folder_id = match FolderCipher::list_by_cipher(&state.db, &c.uuid).await {
            Ok(ids) => ids.into_iter().find(|id| user_folder_ids.contains(id)),
            Err(_) => None,
        };
        ciphers_json.push(cipher_to_json_with_attachments_and_folder(
            &state,
            c,
            favorite_uuids.contains(&c.uuid),
            &coll_ids,
            folder_id.as_deref(),
        ).await);
    }

    let sends = Send::find_by_user(&state.db, &user.uuid).await.unwrap_or_default();
    let sends_json: Vec<Value> = sends.iter().map(send_json).collect();

    let two_factor_enabled = TwoFactor::find_by_user(&state.db, &user.uuid)
        .await
        .map(|fs| fs.iter().any(|f| f.enabled == 1))
        .unwrap_or(false);

    let equivalent_domains: Value = serde_json::from_str(&user.equivalent_domains).unwrap_or(Value::Null);
    let excluded_globals: Value = serde_json::from_str(&user.excluded_globals).unwrap_or(json!([]));

    let body = json!({
        "Object": "sync",
        "Profile": profile_for_sync(user, &organizations_json, two_factor_enabled),
        "Folders": folders_json,
        "Collections": collections_json,
        "Policies": policies_json,
        "Ciphers": ciphers_json,
        "Domains": {
            "Object": "domains",
            "EquivalentDomains": equivalent_domains,
            "GlobalEquivalentDomains": [],
            "ExcludedGlobalEquivalentDomains": excluded_globals,
        },
        "Sends": sends_json,
        "unofficialServer": true,
    });
    (StatusCode::OK, Json(body))
}
