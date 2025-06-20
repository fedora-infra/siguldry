// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::str::FromStr;

use anyhow::Context;
use sqlx::{sqlite::SqliteConnectOptions, Pool, Sqlite, SqliteConnection, SqlitePool};
use tracing::instrument;

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/");

/// Ensure the database is migrated to the latest version.
///
/// # Example
///
/// ```rust,no_run
/// let db = pool("sqlite::memory:")?;
/// migrate(&db).await?;
/// ```
#[instrument]
pub async fn migrate(pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    MIGRATIONS
        .run(pool)
        .await
        .context("Migrations could not be applied")?;
    Ok(())
}

pub async fn pool(db_uri: &str) -> anyhow::Result<Pool<Sqlite>> {
    let opts = SqliteConnectOptions::from_str(db_uri)
        .context("The database URL couldn't be parsed.")?
        .create_if_missing(true)
        .foreign_keys(true)
        .optimize_on_close(true, Some(400));
    SqlitePool::connect_with(opts)
        .await
        .context("Failed to connect to the database")
}

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub id: i64,
    pub name: String,
}

impl User {
    #[instrument(skip(conn))]
    pub async fn get(conn: &mut SqliteConnection, name: &str) -> Result<User, sqlx::Error> {
        sqlx::query_as!(User, "SELECT * FROM users WHERE users.name = ?;", name)
            .fetch_one(&mut *conn)
            .await
    }

    #[instrument(skip(conn))]
    pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<User>, sqlx::Error> {
        sqlx::query_as!(User, "SELECT * FROM users;")
            .fetch_all(&mut *conn)
            .await
    }

    #[instrument(skip(conn))]
    pub async fn create(conn: &mut SqliteConnection, name: &str) -> Result<User, sqlx::Error> {
        sqlx::query!("INSERT INTO users (name) VALUES (?) RETURNING id", name,)
            .fetch_one(&mut *conn)
            .await
            .map(|record| User {
                id: record.id,
                name: name.to_string(),
            })
    }

    #[instrument(skip(conn))]
    pub async fn delete(conn: &mut SqliteConnection, name: &str) -> Result<u64, sqlx::Error> {
        sqlx::query!("DELETE FROM users WHERE name = $1", name)
            .execute(&mut *conn)
            .await
            .map(|result| result.rows_affected())
    }
}

pub struct Key {
    pub id: i64,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[tokio::test]
    async fn create_delete_user() -> Result<()> {
        let db_pool = pool("sqlite::memory:").await?;
        migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let name = "test-user";

        let user = User::create(&mut conn, name).await?;
        let fetched_user = User::get(&mut conn, name).await?;
        assert_eq!(user, fetched_user);
        assert_eq!(user.name, name);

        let users_deleted = User::delete(&mut conn, name).await?;
        assert_eq!(1, users_deleted);
        assert_eq!(0, User::delete(&mut conn, name).await?);

        let fetched_user = User::get(&mut conn, name).await;
        assert!(matches!(fetched_user, Err(sqlx::Error::RowNotFound)));

        Ok(())
    }

    #[tokio::test]
    async fn user_must_be_unique() -> Result<()> {
        let db_pool = pool("sqlite::memory:").await?;
        migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let name = "test-user";

        _ = User::create(&mut conn, name).await?;
        let failed_user = User::create(&mut conn, name).await;
        assert!(failed_user.is_err_and(|error| {
            "UNIQUE constraint failed: users.name" == error.as_database_error().unwrap().message()
        }));

        Ok(())
    }
}
