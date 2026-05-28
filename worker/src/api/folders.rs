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
use crate::api::notify::{kind, notify_user};
use crate::auth::Headers;
use crate::db::models::Folder;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/folders", get(list_folders).post(post_folder))
        .route("/api/folders/{uuid}", get(get_folder).put(put_folder).delete(delete_folder))
        .route("/api/folders/{uuid}/delete", post(delete_folder))
}

fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

pub(crate) fn folder_to_json(f: &Folder) -> Value {
    json!({
        "Object": "folder",
        "Id": f.uuid,
        "Name": f.name,
        "RevisionDate": f.updated_at,
    })
}

#[derive(Deserialize)]
struct FolderData {
    name: String,
}

async fn load_owned(
    state: &AppState,
    headers: &Headers,
    uuid: &str,
) -> Result<Folder, (StatusCode, Json<Value>)> {
    let f = Folder::find_by_uuid(&state.db, uuid)
        .await
        .map_err(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or_else(|| err_json(StatusCode::NOT_FOUND, "Folder not found"))?;
    if f.user_uuid != headers.user.uuid {
        return Err(err_json(StatusCode::NOT_FOUND, "Folder not found"));
    }
    Ok(f)
}

#[worker::send]
async fn list_folders(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    let folders = match Folder::find_by_user(&state.db, &headers.user.uuid).await {
        Ok(f) => f,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    let data: Vec<Value> = folders.iter().map(folder_to_json).collect();
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn post_folder(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<FolderData>,
) -> impl IntoResponse {
    let mut folder = Folder::new(headers.user.uuid.clone(), body.name);
    if folder.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save folder");
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_FOLDER_CREATE, &folder.uuid).await;
    (StatusCode::OK, Json(folder_to_json(&folder)))
}

#[worker::send]
async fn get_folder(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> impl IntoResponse {
    let folder = match load_owned(&state, &headers, &uuid).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    (StatusCode::OK, Json(folder_to_json(&folder)))
}

#[worker::send]
async fn put_folder(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
    Json(body): Json<FolderData>,
) -> impl IntoResponse {
    let mut folder = match load_owned(&state, &headers, &uuid).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    folder.name = body.name;
    if folder.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save folder");
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_FOLDER_UPDATE, &folder.uuid).await;
    (StatusCode::OK, Json(folder_to_json(&folder)))
}

#[worker::send]
async fn delete_folder(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> impl IntoResponse {
    let folder = match load_owned(&state, &headers, &uuid).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    let folder_uuid = folder.uuid.clone();
    if folder.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to delete folder");
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_FOLDER_DELETE, &folder_uuid).await;
    (StatusCode::OK, Json(json!({})))
}
