// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use sqlx::SqliteConnection;

use crate::{
    protocol::{json, Response, ServerError},
    server::db::User,
};

pub(crate) async fn who_am_i(user: &User) -> Result<Response, ServerError> {
    Ok(json::Response::WhoAmI {
        user: user.name.clone(),
    }
    .into())
}

pub(crate) async fn list_users(conn: &mut SqliteConnection) -> Result<Response, ServerError> {
    let users = User::list(conn)
        .await?
        .into_iter()
        .map(|user| user.name)
        .collect();

    Ok(json::Response::ListUsers { users }.into())
}
