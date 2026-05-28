use axum::{
    Json, Router,
    extract::{Path, State as AxumState},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Headers;
use crate::db::models::{Membership, Organization, User};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/organizations", post(post_organization))
        .route("/api/organizations/{org_id}", get(get_organization).put(put_organization).post(put_organization).delete(delete_organization))
        .route("/api/organizations/{org_id}/delete", post(delete_organization))
        .route("/api/organizations/{org_id}/leave", post(leave_organization))
        .route("/api/organizations/{org_id}/keys", get(get_organization_keys).post(post_organization_keys))
        .route("/api/organizations/{org_id}/public-key", get(get_organization_public_key))
        .route("/api/organizations/{org_id}/users", get(list_users))
        .route("/api/organizations/{org_id}/users/mini-details", get(list_users_mini))
        .route("/api/organizations/{org_id}/users/public-keys", post(member_public_keys))
        .route("/api/organizations/{org_id}/users/invite", post(invite))
        .route("/api/organizations/{org_id}/users/reinvite", post(bulk_reinvite))
        .route("/api/organizations/{org_id}/users/confirm", post(bulk_confirm))
        .route("/api/organizations/{org_id}/users/restore", post(bulk_restore_member))
        .route("/api/organizations/{org_id}/users/revoke", post(bulk_revoke_member))
        .route("/api/organizations/{org_id}/users/{member_id}/reinvite", post(reinvite))
        .route("/api/organizations/{org_id}/users/{member_id}/accept", post(accept))
        .route("/api/organizations/{org_id}/users/{member_id}/confirm", post(confirm))
        .route("/api/organizations/{org_id}/users/{member_id}", get(get_member).put(update_member).post(update_member).delete(remove_member))
        .route("/api/organizations/{org_id}/users/{member_id}/delete", post(remove_member))
        .route("/api/organizations/{org_id}/users/{member_id}/revoke", axum::routing::put(revoke_member))
        .route("/api/organizations/{org_id}/users/{member_id}/restore", axum::routing::put(restore_member))
        .route("/api/organizations/{org_id}/users/{member_id}/restore/vnext", axum::routing::put(restore_member))
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password",
            axum::routing::put(reset_password),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password-details",
            get(reset_password_details),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password-enrollment",
            axum::routing::put(reset_password_enrollment),
        )
        .route("/api/organizations/{org_id}/api-key", post(get_org_api_key))
        .route("/api/organizations/{org_id}/rotate-api-key", post(rotate_org_api_key))
        .route("/api/organizations/{org_id}/auto-enroll-status", get(auto_enroll_status))
        .route("/api/organizations/{org_id}/billing/metadata", get(billing_metadata))
        .route("/api/organizations/{org_id}/billing/vnext/self-host/metadata", get(billing_metadata))
        .route("/api/organizations/{org_id}/billing/vnext/warnings", get(billing_warnings))
        .route("/api/organizations/{org_id}/export", get(org_export))
        .route("/api/organizations/domain/sso/verified", post(sso_verified_stub))
}

fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

pub(crate) fn organization_json(o: &Organization) -> Value {
    json!({
        "Object": "organization",
        "Id": o.uuid,
        "Name": o.name,
        "BillingEmail": o.billing_email,
        "PublicKey": o.public_key,
        "PrivateKey": o.private_key,
    })
}

pub(crate) fn membership_json(m: &Membership, name: &str) -> Value {
    // Mirrors upstream's `Membership::to_json`. Most capability flags are
    // hardcoded — Vaultwarden self-hosters get the full feature set regardless
    // of seat tier. Custom-role permissions are emitted as the simple "manager
    // with access_all" case.
    let manager_type_as_custom = if m.atype == 3 { 4 } else { m.atype };
    let permissions = json!({
        "accessEventLogs": false,
        "accessImportExport": false,
        "accessReports": false,
        "createNewCollections": manager_type_as_custom == 4 && m.access_all == 1,
        "editAnyCollection": manager_type_as_custom == 4 && m.access_all == 1,
        "deleteAnyCollection": manager_type_as_custom == 4 && m.access_all == 1,
        "manageGroups": false,
        "managePolicies": false,
        "manageSso": false,
        "manageUsers": false,
        "manageResetPassword": false,
        "manageScim": false,
    });
    json!({
        "Object": "profileOrganization",
        "Id": m.org_uuid,
        "id": m.org_uuid,
        "identifier": Value::Null,
        "Name": name,
        "name": name,
        "seats": 20,
        "maxCollections": Value::Null,
        "usersGetPremium": true,
        "use2fa": true,
        "useDirectory": false,
        "useEvents": true,
        "useGroups": true,
        "useTotp": true,
        "useScim": false,
        "usePolicies": true,
        "useApi": true,
        "selfHost": true,
        "hasPublicAndPrivateKeys": true,
        "resetPasswordEnrolled": m.reset_password_key.is_some(),
        "useResetPassword": true,
        "ssoBound": false,
        "useSso": false,
        "useKeyConnector": false,
        "useSecretsManager": false,
        "usePasswordManager": true,
        "useCustomPermissions": true,
        "useActivateAutofillPolicy": false,
        "useAdminSponsoredFamilies": false,
        "useRiskInsights": false,
        "organizationUserId": m.uuid,
        "providerId": Value::Null,
        "providerName": Value::Null,
        "providerType": Value::Null,
        "familySponsorshipFriendlyName": Value::Null,
        "familySponsorshipAvailable": false,
        "productTierType": 3,
        "keyConnectorEnabled": false,
        "keyConnectorUrl": Value::Null,
        "familySponsorshipLastSyncDate": Value::Null,
        "familySponsorshipValidUntil": Value::Null,
        "familySponsorshipToDelete": Value::Null,
        "accessSecretsManager": false,
        "limitCollectionCreation": manager_type_as_custom < 3 || m.access_all == 0,
        "limitCollectionDeletion": true,
        "limitItemDeletion": false,
        "allowAdminAccessToAllCollectionItems": true,
        "userIsManagedByOrganization": false,
        "userIsClaimedByOrganization": false,
        "permissions": permissions,
        "maxStorageGb": i16::MAX,
        // Legacy capitalised fields kept alongside camelCase so older clients
        // still parse the response.
        "Status": m.status,
        "status": m.status,
        "Type": m.atype,
        "type": m.atype,
        "Enabled": true,
        "enabled": true,
        "AccessAll": m.access_all == 1,
        "Key": m.akey,
        "key": m.akey,
        "ResetPasswordEnrolled": m.reset_password_key.is_some(),
        "ProviderType": Value::Null,
        "userId": m.user_uuid,
        "UserId": m.user_uuid,
    })
}

#[derive(Deserialize)]
struct CreateOrganization {
    name: String,
    #[serde(rename = "billingEmail")]
    billing_email: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    keys: Option<KeyPair>,
}

#[derive(Deserialize)]
struct KeyPair {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: String,
}

#[worker::send]
async fn post_organization(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<CreateOrganization>,
) -> impl IntoResponse {
    if body.name.trim().is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "name is required");
    }
    let mut org = Organization::new(body.name, body.billing_email);
    if let Some(kp) = body.keys {
        org.public_key = Some(kp.public_key);
        org.private_key = Some(kp.encrypted_private_key);
    }
    if org.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save organization");
    }
    // Owner = type 0, status 2 (Confirmed). access_all is on for the creator.
    let mut m = Membership::new(headers.user.uuid.clone(), org.uuid.clone(), body.key.unwrap_or_default(), 0, 2);
    m.access_all = 1;
    if m.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save membership");
    }
    (StatusCode::OK, Json(organization_json(&org)))
}

async fn require_membership(
    state: &AppState,
    headers: &Headers,
    org_id: &str,
) -> Result<Membership, (StatusCode, Json<Value>)> {
    Membership::find_by_user_and_org(&state.db, &headers.user.uuid, org_id)
        .await
        .map_err(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or_else(|| err_json(StatusCode::NOT_FOUND, "Organization not found"))
}

#[worker::send]
async fn get_organization(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_membership(&state, &headers, &org_id).await {
        return e;
    }
    let org = match Organization::find_by_uuid(&state.db, &org_id).await {
        Ok(Some(o)) => o,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "Organization not found"),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    (StatusCode::OK, Json(organization_json(&org)))
}

#[worker::send]
async fn get_organization_keys(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_membership(&state, &headers, &org_id).await {
        return e;
    }
    let org = match Organization::find_by_uuid(&state.db, &org_id).await {
        Ok(Some(o)) => o,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "Organization not found"),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    (
        StatusCode::OK,
        Json(json!({
            "Object": "organizationKeys",
            "PublicKey": org.public_key,
            "PrivateKey": org.private_key,
        })),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgKeysBody {
    encrypted_private_key: String,
    public_key: String,
}

/// First-time RSA keypair upload for an org. Mirrors upstream's
/// `POST /organizations/{org_id}/keys`. Refuses if the org already has keys
/// — once set, re-keying happens through the dedicated rotation flow.
#[worker::send]
async fn post_organization_keys(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<OrgKeysBody>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut org = match Organization::find_by_uuid(&state.db, &org_id).await {
        Ok(Some(o)) => o,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "Organization not found"),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    if org.private_key.is_some() && org.public_key.is_some() {
        return err_json(StatusCode::BAD_REQUEST, "Organization Keys already exist");
    }
    org.private_key = Some(body.encrypted_private_key);
    org.public_key = Some(body.public_key);
    if org.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (
        StatusCode::OK,
        Json(json!({
            "object": "organizationKeys",
            "publicKey": org.public_key,
            "privateKey": org.private_key,
        })),
    )
}

// Membership status values (mirror upstream `MembershipStatus`).
const STATUS_INVITED: i32 = 0;
const STATUS_ACCEPTED: i32 = 1;
const STATUS_CONFIRMED: i32 = 2;

// Membership type values (mirror upstream `MembershipType`).
const TYPE_OWNER: i32 = 0;
#[allow(dead_code)]
const TYPE_ADMIN: i32 = 1;
const TYPE_USER: i32 = 2;
#[allow(dead_code)]
const TYPE_MANAGER: i32 = 3;

#[derive(Deserialize)]
struct InviteBody {
    emails: Vec<String>,
    #[serde(rename = "type")]
    atype: Option<i32>,
    #[serde(default, rename = "accessAll")]
    access_all: Option<bool>,
    #[serde(default)]
    collections: Option<Vec<MemberCollectionEntry>>,
    #[serde(default)]
    groups: Option<Vec<String>>,
}

async fn require_org_admin(
    state: &AppState,
    headers: &Headers,
    org_id: &str,
) -> Result<Membership, (StatusCode, Json<Value>)> {
    let m = require_membership(state, headers, org_id).await?;
    if m.status != STATUS_CONFIRMED {
        return Err(err_json(StatusCode::FORBIDDEN, "membership not confirmed"));
    }
    if m.atype > TYPE_USER {
        // owner=0, admin=1, user=2 — anything stricter (manager/custom) we treat as not allowed for invites yet.
        return Err(err_json(StatusCode::FORBIDDEN, "manager/custom roles can't invite yet"));
    }
    Ok(m)
}

#[worker::send]
async fn invite(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<InviteBody>,
) -> impl IntoResponse {
    let actor = match require_org_admin(&state, &headers, &org_id).await {
        Ok(m) => m,
        Err(e) => return e,
    };
    let new_type = body.atype.unwrap_or(TYPE_USER);
    if new_type != TYPE_USER && actor.atype != TYPE_OWNER {
        return err_json(StatusCode::FORBIDDEN, "Only Owners can invite Admins or Owners");
    }
    // Rate-limit on the inviter so a hostile admin can't spam strangers' inboxes.
    if !crate::ratelimit::check(
        &state.ratelimit_kv,
        &crate::ratelimit::EMAIL_SEND_LIMIT,
        &headers.user.uuid,
    )
    .await
    {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many invitations");
    }

    let mut invited_count = 0usize;
    for email in body.emails.iter().map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()) {
        // Find or create the invitee user. Upstream creates an "invited" user
        // automatically if the email isn't registered; we mirror that.
        let invitee = match User::find_by_email(&state.db, &email).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                let mut u = User::new(&email, None);
                u.enabled = 1;
                if u.save(&state.db).await.is_err() {
                    return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to create invitee");
                }
                u
            }
            Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
        };

        // Skip if already a member.
        if let Ok(Some(_)) = Membership::find_by_user_and_org(&state.db, &invitee.uuid, &org_id).await {
            continue;
        }

        let mut m = Membership::new(invitee.uuid.clone(), org_id.clone(), String::new(), new_type, STATUS_INVITED);
        if let Some(true) = body.access_all {
            m.access_all = 1;
        }
        if m.save(&state.db).await.is_err() {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save membership");
        }
        invited_count += 1;

        // Optional per-collection ACL at invite time. Mirrors upstream's
        // `collections: [{ id, readOnly, hidePasswords, manage }]` body.
        if let Some(ref collections) = body.collections {
            for entry in collections {
                let acl = crate::db::models::UserCollection::new(
                    invitee.uuid.clone(),
                    entry.id.clone(),
                    entry.read_only,
                    entry.hide_passwords,
                    entry.manage,
                );
                let _save = acl.upsert(&state.db).await;
            }
        }
        if let Some(ref group_ids) = body.groups {
            for gid in group_ids {
                let _set = crate::db::models::GroupUser::set(&state.db, gid, &m.uuid).await;
            }
        }

        crate::api::events::log_org_event(
            &state,
            crate::api::events::event_type::ORG_USER_INVITED,
            &org_id,
            &headers.user.uuid,
            Some(&m.uuid),
            headers.device.atype,
        )
        .await;

        // Best-effort email — Provider::Log just no-ops in dev.
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let host = state.env_var("DOMAIN").unwrap_or_default();
        let org_name = match Organization::find_by_uuid(&state.db, &org_id).await {
            Ok(Some(o)) => o.name,
            _ => "an organization".to_owned(),
        };
        let link = format!(
            "{host}/#/accept-organization?orgId={org_id}&orgUserId={}&orgName={}&email={}",
            m.uuid,
            urlencoded(&org_name),
            urlencoded(&email),
        );
        let _result = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: email,
                subject: format!("Join {org_name} on Vaultwarden"),
                text: format!(
                    "You have been invited to join {org_name}. Click the link below to accept:\n\n{link}\n\nMembership ID: {}",
                    m.uuid,
                ),
                html: None,
            })
            .await;
    }
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": [], "Invited": invited_count })))
}

fn urlencoded(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                String::from_utf8(vec![b]).unwrap_or_default()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AcceptBody {
    #[allow(dead_code)]
    token: Option<String>,
}

#[worker::send]
async fn accept(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(_body): Json<AcceptBody>,
) -> impl IntoResponse {
    let mut m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    if m.user_uuid != headers.user.uuid {
        return err_json(StatusCode::FORBIDDEN, "Only the invited user may accept");
    }
    if m.status != STATUS_INVITED {
        return err_json(StatusCode::BAD_REQUEST, "Invite already accepted or confirmed");
    }
    m.status = STATUS_ACCEPTED;
    if m.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    // Email every confirmed admin/owner so they know the invite needs
    // confirming. Best-effort — failure to send doesn't fail the accept.
    if let Ok(members) = Membership::find_by_org(&state.db, &org_id).await {
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let host = state.env_var("DOMAIN").unwrap_or_default();
        for admin in members.into_iter().filter(|x| {
            x.status == STATUS_CONFIRMED && (x.atype == TYPE_OWNER || x.atype == TYPE_ADMIN)
        }) {
            if let Ok(Some(admin_user)) = User::find_by_uuid(&state.db, &admin.user_uuid).await {
                let _send = state
                    .mail
                    .send(&crate::mail::MailMessage {
                        from_email: from_email.clone(),
                        from_name: from_name.clone(),
                        to: admin_user.email,
                        subject: "Vaultwarden member ready for confirmation".into(),
                        text: format!(
                            "{} accepted their invitation. Confirm them at {host} so they can decrypt shared items.",
                            headers.user.email,
                        ),
                        html: None,
                    })
                    .await;
            }
        }
    }
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct ConfirmBody {
    key: String,
}

#[worker::send]
async fn confirm(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(body): Json<ConfirmBody>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    if m.status != STATUS_ACCEPTED {
        return err_json(StatusCode::BAD_REQUEST, "Membership not in accepted state");
    }
    m.akey = body.key;
    m.status = STATUS_CONFIRMED;
    if m.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_USER_CONFIRMED,
        &org_id,
        &headers.user.uuid,
        Some(&m.uuid),
        headers.device.atype,
    )
    .await;
    // Email the new member so they know their access is live. Best-effort —
    // failure to send doesn't fail the confirmation.
    if let Ok(Some(user)) = User::find_by_uuid(&state.db, &m.user_uuid).await {
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let host = state.env_var("DOMAIN").unwrap_or_default();
        let org_name = match Organization::find_by_uuid(&state.db, &org_id).await {
            Ok(Some(o)) => o.name,
            _ => "an organization".to_owned(),
        };
        let _send = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: user.email,
                subject: format!("You've been confirmed to {org_name}"),
                text: format!(
                    "Your invitation to {org_name} has been confirmed. Sign in at {host} to access shared items.",
                ),
                html: None,
            })
            .await;
    }
    // Force the newly-confirmed member to re-sync so shared collections show
    // up immediately rather than at the next periodic poll.
    crate::api::notify::notify_user(
        &state,
        &m.user_uuid,
        crate::api::notify::kind::SYNC_VAULT,
        &m.user_uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn list_users(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    use crate::db::models::{GroupUser, UserCollection};

    if let Err(e) = require_membership(&state, &headers, &org_id).await {
        return e;
    }
    let members = match Membership::find_by_org(&state.db, &org_id).await {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    let mut data = Vec::with_capacity(members.len());
    for m in members {
        let (email, name, two_factor_enabled) = match User::find_by_uuid(&state.db, &m.user_uuid).await {
            Ok(Some(u)) => {
                let tf = crate::db::models::TwoFactor::find_by_user(&state.db, &u.uuid)
                    .await
                    .map(|fs| fs.iter().any(|f| f.enabled == 1 && f.atype < 1000))
                    .unwrap_or(false);
                (u.email, u.name, tf)
            }
            _ => (String::new(), String::new(), false),
        };

        let collections = UserCollection::find_by_user(&state.db, &m.user_uuid)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|c| {
                json!({
                    "Id": c.collection_uuid,
                    "ReadOnly": c.read_only == 1,
                    "HidePasswords": c.hide_passwords == 1,
                    "Manage": c.manage == 1,
                })
            })
            .collect::<Vec<_>>();
        let groups = GroupUser::list_by_member(&state.db, &m.uuid).await.unwrap_or_default();

        data.push(json!({
            "Object": "organizationUserUserDetails",
            "Id": m.uuid,
            "UserId": m.user_uuid,
            "Email": email,
            "Name": name,
            "Status": m.status,
            "Type": m.atype,
            "AccessAll": m.access_all == 1,
            "TwoFactorEnabled": two_factor_enabled,
            "ResetPasswordEnrolled": m.reset_password_key.is_some(),
            "Collections": collections,
            "Groups": groups,
            "ExternalId": Value::Null,
        }));
    }
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

// ---------------------------------------------------------------------------
// Phase 5: org admin surface — update org, leave/delete, public-key,
// member CRUD (get/update/remove/revoke/restore), bulk reinvite.

#[derive(Deserialize)]
struct UpdateOrgBody {
    name: String,
    #[serde(default, rename = "billingEmail")]
    billing_email: Option<String>,
    #[serde(default, rename = "identifier")]
    _identifier: Option<String>,
}

#[worker::send]
async fn put_organization(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<UpdateOrgBody>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut org = match Organization::find_by_uuid(&state.db, &org_id).await {
        Ok(Some(o)) => o,
        _ => return err_json(StatusCode::NOT_FOUND, "Organization not found"),
    };
    org.name = body.name;
    if let Some(em) = body.billing_email
        && !em.is_empty()
    {
        org.billing_email = em.to_lowercase();
    }
    if org.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_UPDATED,
        &org_id,
        &headers.user.uuid,
        None,
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_org(
        &state,
        &org_id,
        crate::api::notify::kind::SYNC_ORG_KEYS,
        &org_id,
    )
    .await;
    (StatusCode::OK, Json(organization_json(&org)))
}

#[worker::send]
async fn delete_organization(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    let actor = match require_org_admin(&state, &headers, &org_id).await {
        Ok(m) => m,
        Err(e) => return e,
    };
    if actor.atype != TYPE_OWNER {
        return err_json(StatusCode::FORBIDDEN, "Only owners may delete the organization");
    }
    // Snapshot member uuids before the cascade clears the membership table —
    // we need them after the row goes to push a sync notification.
    let member_uuids: Vec<String> = Membership::find_by_org(&state.db, &org_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| m.user_uuid)
        .collect();
    let db = state.db.as_ref();
    // Best-effort R2 cleanup of org-shared cipher attachments first.
    if let Ok(att_rows) = db
        .prepare(
            "SELECT a.cipher_uuid AS cipher_uuid, a.id AS attachment_id \
             FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid \
             WHERE c.organization_uuid = ?1",
        )
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&org_id)])
    {
        #[derive(serde::Deserialize)]
        struct Row { cipher_uuid: String, attachment_id: String }
        if let Ok(result) = att_rows.all().await
            && let Ok(rows) = result.results::<Row>()
        {
            for r in rows {
                let key = format!("{}/{}", r.cipher_uuid, r.attachment_id);
                let _r2 = state.attachments.delete(&key).await;
            }
        }
    }
    let bind = worker::wasm_bindgen::JsValue::from_str(&org_id);
    for sql in [
        "DELETE FROM attachments WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE organization_uuid = ?1)",
        "DELETE FROM ciphers_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM users_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM collections_groups WHERE collections_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM collections WHERE org_uuid = ?1",
        "DELETE FROM groups_users WHERE groups_uuid IN (SELECT uuid FROM groups WHERE organizations_uuid = ?1)",
        "DELETE FROM groups WHERE organizations_uuid = ?1",
        "DELETE FROM ciphers WHERE organization_uuid = ?1",
        "DELETE FROM users_organizations WHERE org_uuid = ?1",
        "DELETE FROM org_policies WHERE org_uuid = ?1",
        "DELETE FROM organization_api_key WHERE org_uuid = ?1",
        "DELETE FROM event WHERE org_uuid = ?1",
        "DELETE FROM organizations WHERE uuid = ?1",
    ] {
        let stmt = match db.prepare(sql).bind(&[bind.clone()]) {
            Ok(s) => s,
            Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "bind failed"),
        };
        if stmt.run().await.is_err() {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "delete failed");
        }
    }
    // Tell every member to re-sync — the org is gone from their UI.
    for user_uuid in &member_uuids {
        crate::api::notify::notify_user(
            &state,
            user_uuid,
            crate::api::notify::kind::SYNC_VAULT,
            user_uuid,
        )
        .await;
    }
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn leave_organization(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    let m = match Membership::find_by_user_and_org(&state.db, &headers.user.uuid, &org_id).await {
        Ok(Some(m)) => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    if m.atype == TYPE_OWNER {
        // Refuse to let the last owner leave (Bitwarden parity).
        if let Ok(members) = Membership::find_by_org(&state.db, &org_id).await {
            let owners = members.iter().filter(|x| x.atype == TYPE_OWNER && x.status == STATUS_CONFIRMED).count();
            if owners <= 1 {
                return err_json(StatusCode::BAD_REQUEST, "Org needs at least one Owner");
            }
        }
    }
    let member_uuid = m.uuid.clone();
    if m.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "leave failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_USER_LEFT,
        &org_id,
        &headers.user.uuid,
        Some(&member_uuid),
        headers.device.atype,
    )
    .await;
    // Force the leaving user to re-sync so the org disappears from their UI
    // immediately rather than at next login.
    crate::api::notify::notify_user(
        &state,
        &headers.user.uuid,
        crate::api::notify::kind::SYNC_VAULT,
        &headers.user.uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn get_organization_public_key(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_membership(&state, &headers, &org_id).await {
        return e;
    }
    let org = match Organization::find_by_uuid(&state.db, &org_id).await {
        Ok(Some(o)) => o,
        _ => return err_json(StatusCode::NOT_FOUND, "Organization not found"),
    };
    (
        StatusCode::OK,
        Json(json!({ "Object": "organizationPublicKey", "PublicKey": org.public_key })),
    )
}

#[worker::send]
async fn list_users_mini(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_membership(&state, &headers, &org_id).await {
        return e;
    }
    let members = match Membership::find_by_org(&state.db, &org_id).await {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    let mut data = Vec::with_capacity(members.len());
    for m in members {
        let (email, name) = match User::find_by_uuid(&state.db, &m.user_uuid).await {
            Ok(Some(u)) => (u.email, u.name),
            _ => (String::new(), String::new()),
        };
        data.push(json!({
            "Id": m.uuid,
            "UserId": m.user_uuid,
            "Email": email,
            "Name": name,
            "Type": m.atype,
            "Status": m.status,
        }));
    }
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn get_member(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
) -> impl IntoResponse {
    use crate::db::models::{GroupUser, UserCollection};

    if let Err(e) = require_membership(&state, &headers, &org_id).await {
        return e;
    }
    let m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    let (email, name, two_factor_enabled) = match User::find_by_uuid(&state.db, &m.user_uuid).await {
        Ok(Some(u)) => {
            let tf = crate::db::models::TwoFactor::find_by_user(&state.db, &u.uuid)
                .await
                .map(|fs| fs.iter().any(|f| f.enabled == 1 && f.atype < 1000))
                .unwrap_or(false);
            (u.email, u.name, tf)
        }
        _ => (String::new(), String::new(), false),
    };
    let collections = UserCollection::find_by_user(&state.db, &m.user_uuid)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            json!({
                "Id": c.collection_uuid,
                "ReadOnly": c.read_only == 1,
                "HidePasswords": c.hide_passwords == 1,
                "Manage": c.manage == 1,
            })
        })
        .collect::<Vec<_>>();
    let groups = GroupUser::list_by_member(&state.db, &m.uuid).await.unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({
            "Object": "organizationUserDetails",
            "Id": m.uuid,
            "UserId": m.user_uuid,
            "Email": email,
            "Name": name,
            "Status": m.status,
            "Type": m.atype,
            "AccessAll": m.access_all == 1,
            "TwoFactorEnabled": two_factor_enabled,
            "ResetPasswordEnrolled": m.reset_password_key.is_some(),
            "Collections": collections,
            "Groups": groups,
        })),
    )
}

#[derive(Deserialize)]
struct UpdateMemberBody {
    #[serde(rename = "type")]
    atype: i32,
    #[serde(default, rename = "accessAll")]
    access_all: Option<bool>,
    #[serde(default)]
    collections: Option<Vec<MemberCollectionEntry>>,
    #[serde(default)]
    groups: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct MemberCollectionEntry {
    id: String,
    #[serde(default, rename = "readOnly")]
    read_only: bool,
    #[serde(default, rename = "hidePasswords")]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[worker::send]
async fn update_member(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(body): Json<UpdateMemberBody>,
) -> impl IntoResponse {
    use crate::db::models::{GroupUser, UserCollection};

    let actor = match require_org_admin(&state, &headers, &org_id).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let mut m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    // Only owners can promote/demote into Owner/Admin slots.
    if (body.atype != TYPE_USER || m.atype != TYPE_USER) && actor.atype != TYPE_OWNER {
        return err_json(StatusCode::FORBIDDEN, "Only Owners may update Owner/Admin members");
    }
    m.atype = body.atype;
    if let Some(a) = body.access_all {
        m.access_all = if a { 1 } else { 0 };
    }
    if m.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }

    // Per-collection ACL: replace the member's existing assignments with the
    // supplied set. The body uses *collection* UUIDs, not membership UUIDs.
    if let Some(collections) = body.collections {
        let existing = UserCollection::find_by_user(&state.db, &m.user_uuid)
            .await
            .unwrap_or_default();
        for entry in existing {
            // Only clear assignments that are in this org so we don't
            // accidentally clobber another org's ACL.
            if let Ok(Some(col)) = crate::db::models::Collection::find_by_uuid(&state.db, &entry.collection_uuid).await
                && col.org_uuid == org_id
            {
                let _del = entry.delete(&state.db).await;
            }
        }
        for entry in collections {
            let acl = UserCollection::new(
                m.user_uuid.clone(),
                entry.id,
                entry.read_only,
                entry.hide_passwords,
                entry.manage,
            );
            let _save = acl.upsert(&state.db).await;
        }
    }

    // Group assignment: body sends a list of group UUIDs.
    let mut groups_changed = false;
    if let Some(group_ids) = body.groups {
        groups_changed = true;
        let existing = GroupUser::list_by_member(&state.db, &m.uuid).await.unwrap_or_default();
        for group_id in existing {
            let _del = GroupUser::unset(&state.db, &group_id, &m.uuid).await;
        }
        for group_id in group_ids {
            let _set = GroupUser::set(&state.db, &group_id, &m.uuid).await;
        }
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_USER_UPDATED,
        &org_id,
        &headers.user.uuid,
        Some(&m.uuid),
        headers.device.atype,
    )
    .await;
    // Upstream emits a separate event when group membership changes so the
    // audit log differentiates a permission flip from a role change.
    if groups_changed {
        crate::api::events::log_org_event(
            &state,
            crate::api::events::event_type::ORG_USER_UPDATED_GROUPS,
            &org_id,
            &headers.user.uuid,
            Some(&m.uuid),
            headers.device.atype,
        )
        .await;
    }
    (StatusCode::OK, Json(membership_json(&m, "")))
}

#[worker::send]
async fn remove_member(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let actor = match require_org_admin(&state, &headers, &org_id).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    if (m.atype == TYPE_OWNER || m.atype == TYPE_ADMIN) && actor.atype != TYPE_OWNER {
        return err_json(StatusCode::FORBIDDEN, "Only Owners may remove Owner/Admin members");
    }
    let member_uuid = m.uuid.clone();
    let member_user_uuid = m.user_uuid.clone();
    if m.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "remove failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_USER_REMOVED,
        &org_id,
        &headers.user.uuid,
        Some(&member_uuid),
        headers.device.atype,
    )
    .await;
    // Force the removed user to re-sync so the org disappears from their UI
    // immediately rather than at next login.
    crate::api::notify::notify_user(
        &state,
        &member_user_uuid,
        crate::api::notify::kind::SYNC_VAULT,
        &member_user_uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn revoke_member(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    // Status -1 == Revoked in Bitwarden's enum.
    m.status = -1;
    if m.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_USER_REVOKED,
        &org_id,
        &headers.user.uuid,
        Some(&m.uuid),
        headers.device.atype,
    )
    .await;
    // Force the revoked user to re-sync so the org disappears from their UI
    // immediately rather than at next login.
    crate::api::notify::notify_user(
        &state,
        &m.user_uuid,
        crate::api::notify::kind::SYNC_VAULT,
        &m.user_uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn restore_member(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    m.status = if m.akey.is_empty() { STATUS_INVITED } else { STATUS_CONFIRMED };
    if m.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_USER_RESTORED,
        &org_id,
        &headers.user.uuid,
        Some(&m.uuid),
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_user(
        &state,
        &m.user_uuid,
        crate::api::notify::kind::SYNC_VAULT,
        &m.user_uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn reinvite(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    if m.status != STATUS_INVITED {
        return err_json(StatusCode::BAD_REQUEST, "Member is not in invited state");
    }
    if let Ok(Some(u)) = User::find_by_uuid(&state.db, &m.user_uuid).await {
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let _result = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: u.email,
                subject: "Reminder: organization invitation".into(),
                text: format!("You have a pending invitation. Membership ID: {}", m.uuid),
                html: None,
            })
            .await;
    }
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct BulkReinviteBody {
    #[serde(default)]
    ids: Vec<String>,
}

#[worker::send]
async fn bulk_reinvite(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<BulkReinviteBody>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut count = 0u32;
    for id in body.ids {
        if let Ok(Some(m)) = Membership::find_by_uuid(&state.db, &id).await
            && m.org_uuid == org_id
            && m.status == STATUS_INVITED
            && let Ok(Some(u)) = User::find_by_uuid(&state.db, &m.user_uuid).await
        {
            let (from_email, from_name) = state.mail_from.as_ref().clone();
            let _result = state
                .mail
                .send(&crate::mail::MailMessage {
                    from_email,
                    from_name,
                    to: u.email,
                    subject: "Reminder: organization invitation".into(),
                    text: format!("You have a pending invitation. Membership ID: {}", m.uuid),
                    html: None,
                })
                .await;
            count += 1;
        }
    }
    (StatusCode::OK, Json(json!({ "Reinvited": count })))
}

// ---------------------------------------------------------------------------
// Round-9 expanded org surface: bulk member ops, public-key lookup,
// reset-password endpoints, billing stubs, export, sso-verified.

#[derive(Deserialize)]
struct BulkConfirmBody {
    #[serde(default)]
    keys: Vec<BulkConfirmEntry>,
}

#[derive(Deserialize)]
struct BulkConfirmEntry {
    id: String,
    #[serde(default)]
    key: Option<String>,
}

#[worker::send]
async fn bulk_confirm(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<BulkConfirmBody>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut data = Vec::new();
    for entry in body.keys {
        let mut m = match Membership::find_by_uuid(&state.db, &entry.id).await {
            Ok(Some(m)) if m.org_uuid == org_id && m.status == STATUS_ACCEPTED => m,
            _ => {
                data.push(json!({"Object": "OrganizationUserBulkResponseModel", "Id": entry.id, "Error": "Not acceptable"}));
                continue;
            }
        };
        if let Some(k) = entry.key {
            m.akey = k;
        }
        m.status = STATUS_CONFIRMED;
        if m.save(&state.db).await.is_err() {
            data.push(json!({"Object": "OrganizationUserBulkResponseModel", "Id": entry.id, "Error": "save failed"}));
            continue;
        }
        crate::api::events::log_org_event(
            &state,
            crate::api::events::event_type::ORG_USER_CONFIRMED,
            &org_id,
            &headers.user.uuid,
            Some(&m.uuid),
            headers.device.atype,
        )
        .await;
        // Force the newly-confirmed member to re-sync so shared collections
        // appear in their UI without waiting for the next periodic poll.
        crate::api::notify::notify_user(
            &state,
            &m.user_uuid,
            crate::api::notify::kind::SYNC_VAULT,
            &m.user_uuid,
        )
        .await;
        data.push(json!({"Object": "OrganizationUserBulkResponseModel", "Id": entry.id, "Error": ""}));
    }
    (StatusCode::OK, Json(json!({"Object": "list", "Data": data, "ContinuationToken": Value::Null})))
}

#[derive(Deserialize)]
struct BulkIdsBody {
    #[serde(default)]
    ids: Vec<String>,
}

#[worker::send]
async fn bulk_restore_member(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<BulkIdsBody>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut data = Vec::new();
    for id in body.ids {
        let mut m = match Membership::find_by_uuid(&state.db, &id).await {
            Ok(Some(m)) if m.org_uuid == org_id => m,
            _ => continue,
        };
        m.status = STATUS_CONFIRMED;
        let _save = m.save(&state.db).await;
        crate::api::events::log_org_event(
            &state,
            crate::api::events::event_type::ORG_USER_RESTORED,
            &org_id,
            &headers.user.uuid,
            Some(&m.uuid),
            headers.device.atype,
        )
        .await;
        crate::api::notify::notify_user(
            &state,
            &m.user_uuid,
            crate::api::notify::kind::SYNC_VAULT,
            &m.user_uuid,
        )
        .await;
        data.push(json!({"Object": "OrganizationUserBulkResponseModel", "Id": id, "Error": ""}));
    }
    (StatusCode::OK, Json(json!({"Object": "list", "Data": data, "ContinuationToken": Value::Null})))
}

#[worker::send]
async fn bulk_revoke_member(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<BulkIdsBody>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut data = Vec::new();
    for id in body.ids {
        let mut m = match Membership::find_by_uuid(&state.db, &id).await {
            Ok(Some(m)) if m.org_uuid == org_id => m,
            _ => continue,
        };
        m.status = -1; // Revoked
        let _save = m.save(&state.db).await;
        crate::api::events::log_org_event(
            &state,
            crate::api::events::event_type::ORG_USER_REVOKED,
            &org_id,
            &headers.user.uuid,
            Some(&m.uuid),
            headers.device.atype,
        )
        .await;
        crate::api::notify::notify_user(
            &state,
            &m.user_uuid,
            crate::api::notify::kind::SYNC_VAULT,
            &m.user_uuid,
        )
        .await;
        data.push(json!({"Object": "OrganizationUserBulkResponseModel", "Id": id, "Error": ""}));
    }
    (StatusCode::OK, Json(json!({"Object": "list", "Data": data, "ContinuationToken": Value::Null})))
}

#[derive(Deserialize)]
struct PublicKeysBody {
    #[serde(default)]
    ids: Vec<String>,
}

#[worker::send]
async fn member_public_keys(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<PublicKeysBody>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let mut out = Vec::new();
    for id in body.ids {
        let m = match Membership::find_by_uuid(&state.db, &id).await {
            Ok(Some(m)) if m.org_uuid == org_id => m,
            _ => continue,
        };
        let user = match User::find_by_uuid(&state.db, &m.user_uuid).await {
            Ok(Some(u)) => u,
            _ => continue,
        };
        out.push(json!({
            "Object": "organizationUserPublicKeyResponseModel",
            "Id": m.uuid,
            "UserId": user.uuid,
            "Key": user.public_key,
        }));
    }
    (StatusCode::OK, Json(json!({"Object": "list", "Data": out, "ContinuationToken": Value::Null})))
}

#[derive(Deserialize)]
struct ResetPasswordBody {
    #[serde(rename = "newMasterPasswordHash")]
    new_master_password_hash: String,
    key: String,
}

#[worker::send]
async fn reset_password(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(body): Json<ResetPasswordBody>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Member not found"),
    };
    if m.reset_password_key.is_none() {
        return err_json(StatusCode::BAD_REQUEST, "Member has not enrolled in account recovery");
    }
    let mut user = match User::find_by_uuid(&state.db, &m.user_uuid).await {
        Ok(Some(u)) => u,
        _ => return err_json(StatusCode::NOT_FOUND, "User not found"),
    };
    user.akey = body.key;
    user.set_password(&body.new_master_password_hash);
    user.security_stamp = uuid::Uuid::new_v4().to_string();
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_USER_ADMIN_RESET_PASSWORD,
        &org_id,
        &headers.user.uuid,
        Some(&m.uuid),
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(Value::Null))
}

#[worker::send]
async fn reset_password_details(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    let m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Member not found"),
    };
    let user = match User::find_by_uuid(&state.db, &m.user_uuid).await {
        Ok(Some(u)) => u,
        _ => return err_json(StatusCode::NOT_FOUND, "User not found"),
    };
    (
        StatusCode::OK,
        Json(json!({
            "Object": "organizationUserResetPasswordDetails",
            "Kdf": user.client_kdf_type,
            "KdfIterations": user.client_kdf_iter,
            "KdfMemory": user.client_kdf_memory,
            "KdfParallelism": user.client_kdf_parallelism,
            "ResetPasswordKey": m.reset_password_key,
            "EncryptedPrivateKey": user.private_key,
        })),
    )
}

#[derive(Deserialize)]
struct EnrollmentBody {
    #[serde(rename = "resetPasswordKey", alias = "ResetPasswordKey", default)]
    reset_password_key: Option<String>,
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
}

#[worker::send]
async fn reset_password_enrollment(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(body): Json<EnrollmentBody>,
) -> impl IntoResponse {
    let mut m = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id && m.user_uuid == headers.user.uuid => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    if let Some(pw) = body.master_password_hash.as_deref()
        && !pw.is_empty()
        && !headers.user.check_valid_password(pw)
    {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    let was_enrolled = m.reset_password_key.is_some();
    m.reset_password_key = body.reset_password_key.filter(|s| !s.is_empty());
    let now_enrolled = m.reset_password_key.is_some();
    if m.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    let evt = match (was_enrolled, now_enrolled) {
        (false, true) => Some(crate::api::events::event_type::ORG_USER_RESET_PASSWORD_ENROLL),
        (true, false) => Some(crate::api::events::event_type::ORG_USER_RESET_PASSWORD_WITHDRAW),
        _ => None,
    };
    if let Some(e) = evt {
        crate::api::events::log_org_event(
            &state,
            e,
            &org_id,
            &headers.user.uuid,
            Some(&m.uuid),
            headers.device.atype,
        )
        .await;
    }
    (StatusCode::OK, Json(Value::Null))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct OrgApiKeyBody {
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
}

#[worker::send]
async fn get_org_api_key(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<OrgApiKeyBody>,
) -> impl IntoResponse {
    use base64::Engine as _;
    use crate::db::models::OrganizationApiKey;

    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    if let Some(pw) = body.master_password_hash.as_deref()
        && !pw.is_empty()
        && !headers.user.check_valid_password(pw)
    {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    // Find or mint a default-type api key (atype = 0) for this org, persisted
    // in `organization_api_key` so the directory connector can authenticate
    // with `Bearer <api_key>` against /api/public/*.
    let existing = OrganizationApiKey::find_by_org(&state.db, &org_id).await.unwrap_or_default();
    let mut key = existing.into_iter().find(|k| k.atype == 0);
    if key.is_none() {
        let mut buf = [0u8; 30];
        let _ = getrandom::getrandom(&mut buf);
        let api_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        let mut k = OrganizationApiKey::new(org_id.clone(), 0, api_key);
        if k.save(&state.db).await.is_err() {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
        }
        key = Some(k);
    }
    let k = key.expect("just minted or found");
    (
        StatusCode::OK,
        Json(json!({
            "Object": "apiKey",
            "ApiKey": k.api_key,
            "RevisionDate": k.revision_date,
        })),
    )
}

#[worker::send]
async fn rotate_org_api_key(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<OrgApiKeyBody>,
) -> impl IntoResponse {
    use base64::Engine as _;
    use crate::db::models::OrganizationApiKey;
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    if let Some(pw) = body.master_password_hash.as_deref()
        && !pw.is_empty()
        && !headers.user.check_valid_password(pw)
    {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    // Drop existing default key + mint fresh.
    let existing = OrganizationApiKey::find_by_org(&state.db, &org_id).await.unwrap_or_default();
    for k in existing.into_iter().filter(|k| k.atype == 0) {
        let _del = k.delete(&state.db).await;
    }
    let mut buf = [0u8; 30];
    let _ = getrandom::getrandom(&mut buf);
    let api_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    let mut k = OrganizationApiKey::new(org_id.clone(), 0, api_key);
    if k.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_UPDATED,
        &org_id,
        &headers.user.uuid,
        None,
        headers.device.atype,
    )
    .await;
    (
        StatusCode::OK,
        Json(json!({
            "Object": "apiKey",
            "ApiKey": k.api_key,
            "RevisionDate": k.revision_date,
        })),
    )
}

#[worker::send]
async fn auto_enroll_status(
    AxumState(_state): AxumState<AppState>,
    _headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "Object": "organizationAutoEnrollStatus",
            "Id": org_id,
            "ResetPasswordEnabled": false,
        })),
    )
}

#[worker::send]
async fn billing_metadata(
    AxumState(_state): AxumState<AppState>,
    _headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "Object": "organizationBillingMetadata",
            "Id": org_id,
            "IsEligibleForSelfHost": true,
            "IsManaged": false,
            "IsOnSecretsManagerStandalone": false,
            "IsSubscriptionUnpaid": false,
            "HasSubscription": false,
        })),
    )
}

#[worker::send]
async fn billing_warnings(
    AxumState(_state): AxumState<AppState>,
    _headers: Headers,
    Path(_org_id): Path<String>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"Object": "list", "Data": [], "ContinuationToken": Value::Null})))
}

#[worker::send]
async fn org_export(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_org_admin(&state, &headers, &org_id).await {
        return e;
    }
    // Export shape: { Ciphers, Collections, Folders } where folders is empty
    // for orgs. Defer to the existing helpers.
    let ciphers = crate::db::models::Cipher::find_visible_to_user(&state.db, &headers.user.uuid)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.organization_uuid.as_deref() == Some(org_id.as_str()))
        .collect::<Vec<_>>();
    let collections = crate::db::models::Collection::find_by_org(&state.db, &org_id).await.unwrap_or_default();
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_CLIENT_EXPORTED_VAULT,
        &org_id,
        &headers.user.uuid,
        None,
        headers.device.atype,
    )
    .await;
    (
        StatusCode::OK,
        Json(json!({
            "Object": "organizationExport",
            "Ciphers": ciphers.into_iter().map(|c| crate::api::ciphers::cipher_to_json_full(&c, false, &[], None)).collect::<Vec<_>>(),
            "Collections": collections.iter().map(crate::api::collections::collection_to_json).collect::<Vec<_>>(),
            "Folders": [],
        })),
    )
}

#[worker::send]
async fn sso_verified_stub(
    AxumState(_state): AxumState<AppState>,
    Json(_body): Json<Value>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"Object": "list", "Data": [], "ContinuationToken": Value::Null})))
}
