// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::str::FromStr;

use anyhow::Context;
use sqlx::{Pool, Sqlite, SqliteConnection, SqlitePool, sqlite::SqliteConnectOptions};
use tracing::instrument;

use crate::protocol::KeyAlgorithm;

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

/// Get a database pool.
pub async fn pool(db_uri: &str) -> anyhow::Result<Pool<Sqlite>> {
    let opts = SqliteConnectOptions::from_str(db_uri)
        .context("The database URL couldn't be parsed.")?
        .create_if_missing(true)
        .foreign_keys(true)
        .optimize_on_close(true, Some(400));
    SqlitePool::connect_with(opts)
        .await
        .with_context(|| format!("Failed to connect to the database at {db_uri}"))
}

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub id: i64,
    pub name: String,
}

impl std::fmt::Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
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

/// Possible key locations.
///
/// This enumeration matches the values in the database's `key_locations` table.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum KeyLocation {
    /// Keys accessible via PKCS11.
    ///
    /// It's assumed p11-kit is being used to manage pkcs11 modules. These are typically keys stored
    /// in a hardware security module (HSM).
    Pkcs11,
    /// GPG keys for use with Sequoia's softkey keystore; they are encrypted by a server-generated password.
    SequoiaSoftkey,
    /// Keys for use with OpenSSL; they are encrypted by a server-generated password.
    Encrypted,
}

impl KeyLocation {
    pub fn as_str(&self) -> &str {
        match self {
            KeyLocation::Pkcs11 => "pkcs11",
            KeyLocation::SequoiaSoftkey => "sequoia-softkey",
            KeyLocation::Encrypted => "encrypted",
        }
    }
}

impl TryFrom<&str> for KeyLocation {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pkcs11" => Ok(Self::Pkcs11),
            "sequoia-softkey" => Ok(Self::SequoiaSoftkey),
            "encrypted" => Ok(Self::Encrypted),
            _ => Err(anyhow::anyhow!("Unknown key location '{value}'!")),
        }
    }
}

impl From<String> for KeyLocation {
    fn from(value: String) -> Self {
        // In the event that the database we're working from has been migrated to a different level
        // than the application, it's possible there's a variant we're not aware of. It's not great
        // but we really should panic and stop.
        let msg = "The database contains key locations the application is unaware \
            of; this is either an application bug, or the database migration level does not match \
            the application";
        Self::try_from(value.as_str()).expect(msg)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PublicKeyMaterialType {
    /// An X509 certificate.
    X509,
    /// A signed revocation for a key.
    Revocation,
}

impl TryFrom<&str> for PublicKeyMaterialType {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "x509" => Ok(Self::X509),
            "revocation" => Ok(Self::Revocation),
            _ => Err(anyhow::anyhow!(
                "The database contains public key material types the application \
            is unaware of; this is either an application bug, or the database migration level does \
            not match the application"
            )),
        }
    }
}

impl PublicKeyMaterialType {
    pub fn as_str(&self) -> &str {
        match self {
            PublicKeyMaterialType::X509 => "x509",
            PublicKeyMaterialType::Revocation => "revocation",
        }
    }
}

// This is technically fallible, but only if the database is out of sync with the application,
// in which case we very much do not want to continue.
#[allow(clippy::fallible_impl_from)]
impl From<String> for PublicKeyMaterialType {
    fn from(value: String) -> Self {
        Self::try_from(value.as_str()).expect("Database migration required")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKeyMaterial {
    pub id: i64,
    /// The ID of the private [`Key`] this material relates to.
    pub key_id: i64,
    /// The type stored in the data field.
    pub data_type: PublicKeyMaterialType,
    /// The material of type [`PublicKeyMaterialType`].
    pub data: String,
}

impl PublicKeyMaterial {
    /// Create a new public key material record.
    #[instrument(skip(conn, key, data), fields(key.name = key.name))]
    pub async fn create(
        conn: &mut SqliteConnection,
        key: &Key,
        data_type: PublicKeyMaterialType,
        data: String,
    ) -> Result<PublicKeyMaterial, sqlx::Error> {
        let data_type_ref = data_type.as_str();
        let data_ref = data.as_str();
        sqlx::query!(
            "INSERT INTO public_key_material (key_id, data_type, data) VALUES (?, ?, ?) RETURNING id",
            key.id, data_type_ref, data_ref)
            .fetch_one(&mut *conn)
            .await
            .map(|record| PublicKeyMaterial {
                id: record.id,
                key_id: key.id,
                data_type,
                data,
            })
    }

    /// List all public key material for a given key and type
    #[instrument(skip(conn, key), fields(key.name = key.name))]
    pub async fn list(
        conn: &mut SqliteConnection,
        key: &Key,
        data_type: PublicKeyMaterialType,
    ) -> Result<Vec<PublicKeyMaterial>, sqlx::Error> {
        let data_type_ref = data_type.as_str();
        sqlx::query_as!(
            PublicKeyMaterial,
            "SELECT * FROM public_key_material WHERE key_id = $1 AND data_type = $2;",
            key.id,
            data_type_ref
        )
        .fetch_all(&mut *conn)
        .await
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Key {
    /// The table's primary key.
    pub id: i64,
    /// A name that uniquely identifies the key.
    pub name: String,
    /// Indicates the key type.
    pub key_algorithm: KeyAlgorithm,
    /// The key location indicates where the key is stored. Keys may be stored on the filesystem
    /// or in a hardware security module.
    pub key_location: KeyLocation,
    /// This uniquely identifies a key. For example, the GPG key fingerprint, or the SHA256 sum of
    /// the public key.
    pub handle: String,
    /// The encrypted key material, or in the case of keys stored in hardware, information on how
    /// to access the key (e.g. a PKCS11 URI).
    ///
    /// The scheme is dependent on the type of key, but it will be a text representation
    /// (ASCII-armored, PEM-encoded, etc).
    pub key_material: String,
    /// The public key in a text-friendly encoding (ASCII-armored, PEM-encoded, etc).
    pub public_key: String,
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\"{}\" ({} key in {})",
            self.name,
            self.key_algorithm.as_str(),
            self.key_location.as_str()
        )
    }
}

impl Key {
    /// List all keys.
    ///
    /// Given the expected size of the keys table is in the dozens or hundreds, this does not
    /// perform any sort of pagination.
    #[instrument(skip(conn))]
    pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<Key>, sqlx::Error> {
        sqlx::query_as!(Key, "SELECT * FROM keys;")
            .fetch_all(&mut *conn)
            .await
    }

    /// Get a key by name.
    #[instrument(skip(conn))]
    pub async fn get(conn: &mut SqliteConnection, name: &str) -> Result<Key, sqlx::Error> {
        sqlx::query_as!(Key, "SELECT * FROM keys WHERE name = $1;", name)
            .fetch_one(&mut *conn)
            .await
    }

    /// Create a new key record in the database.
    ///
    /// This does not validate that the key actually exists, or that the handle is valid.
    #[instrument(skip(conn, key_material, public_key))]
    pub async fn create(
        conn: &mut SqliteConnection,
        name: &str,
        handle: &str,
        key_algorithm: KeyAlgorithm,
        key_location: KeyLocation,
        key_material: &str,
        public_key: &str,
    ) -> Result<Key, sqlx::Error> {
        let key_algorithm_str = key_algorithm.as_str();
        let key_location_str = key_location.as_str();
        sqlx::query!(
            "INSERT INTO keys (name, key_algorithm, key_location, handle, key_material, public_key) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
            name, key_algorithm_str, key_location_str, handle, key_material, public_key)
            .fetch_one(&mut *conn)
            .await
            .map(|record| Key {
                id: record.id,
                name: name.to_string(),
                key_algorithm,
                key_location,
                handle: handle.to_string(),
                key_material: key_material.to_string(),
                public_key: public_key.to_string(),
            })
    }

    /// Remove the key from the database.
    ///
    /// This does not delete the key from the filesystem or hardware security module.
    #[instrument(skip(conn))]
    pub async fn delete(conn: &mut SqliteConnection, name: &str) -> Result<u64, sqlx::Error> {
        sqlx::query!("DELETE FROM keys WHERE name = $1", name)
            .execute(&mut *conn)
            .await
            .map(|result| result.rows_affected())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyAccess {
    /// The table's primary key.
    pub id: i64,
    /// The key ID this access record unlocks.
    pub key_id: i64,
    /// The user ID that owns this access record.
    pub user_id: i64,
    /// The encrypted secret required to access the key referenced by `key_id`.
    ///
    /// This secret may be used to encrypt the key on the filesystem, or it may be the PIN needed
    /// to access a PKCS#11 token.
    ///
    /// The key secret is encrypted with the user-supplied secret. If the server has been configured
    /// to use it, the encrypted secret may be further encrypted using clevis.
    ///
    /// If Clevis is not in use, the value stored in this field is constructed as follows:
    ///
    ///         ------------------------------
    ///         | Secret used to encrypt key |
    ///         ------------------------------
    ///                       |
    ///                       | User passphrase
    ///                       |
    ///                       v
    ///            ------------------------
    ///            | encrypted_passphrase |
    ///            ------------------------
    ///
    /// If Clevis *is* in use, the value stored in this field is contructed like this:
    ///
    ///         ------------------------------
    ///         | Secret used to encrypt key |
    ///         ------------------------------
    ///                       |
    ///                       | Encrypted with Clevis configuration
    ///                       |
    ///                       v
    ///         -------------------------------
    ///         | First pass encrypted secret |
    ///         -------------------------------
    ///                       |
    ///                       | User passphrase
    ///                       |
    ///                       v
    ///            ------------------------
    ///            | encrypted_passphrase |
    ///            ------------------------
    pub encrypted_passphrase: Vec<u8>,
    /// If true, the user referenced in this access record may create additional KeyAccess records
    /// referencing this key for other users.
    pub key_admin: bool,
}

impl KeyAccess {
    /// Create a new key access record in the database.
    #[instrument(skip(conn, user, key, encrypted_passphrase), fields(key.name = key.name, user.name = %user))]
    pub async fn create(
        conn: &mut SqliteConnection,
        key: &Key,
        user: &User,
        encrypted_passphrase: Vec<u8>,
        key_admin: bool,
    ) -> Result<KeyAccess, sqlx::Error> {
        let passphrase_blob = encrypted_passphrase.as_slice();
        sqlx::query!(
            "INSERT INTO key_accesses (key_id, user_id, encrypted_passphrase, key_admin) VALUES (?, ?, ?, ?) RETURNING id;",
            key.id,
            user.id,
            passphrase_blob,
            key_admin,
         )
            .fetch_one(&mut *conn)
            .await
            .map(|record| KeyAccess {
                id: record.id,
                key_id: key.id,
                user_id: user.id,
                encrypted_passphrase,
                key_admin,
            })
    }

    #[instrument(skip_all, fields(key.name = key.name, user.name = %user))]
    pub async fn get(
        conn: &mut SqliteConnection,
        key: &Key,
        user: &User,
    ) -> Result<KeyAccess, sqlx::Error> {
        sqlx::query_as!(
            KeyAccess,
            "SELECT * FROM key_accesses WHERE key_id = $1 AND user_id = $2;",
            key.id,
            user.id
        )
        .fetch_one(&mut *conn)
        .await
    }

    /// Remove key access for a user.
    #[instrument(skip_all, fields(key.name = key.name, user.name = %user))]
    pub async fn delete(
        conn: &mut SqliteConnection,
        key: &Key,
        user: &User,
    ) -> Result<u64, sqlx::Error> {
        sqlx::query!(
            "DELETE FROM key_accesses WHERE key_id = $1 AND user_id = $2;",
            key.id,
            user.id
        )
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use sqlx::{Row, error::ErrorKind};

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

    // Assert the KeyType enum aligns with the database enumeration.
    #[tokio::test]
    async fn key_algorithms_match_db() -> Result<()> {
        let db_pool = pool("sqlite::memory:").await?;
        migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;

        let key_algorithms = sqlx::query("SELECT * FROM key_algorithms;")
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .map(|row| {
                let key_algorithm: &str = row.get("type");
                KeyAlgorithm::try_from(key_algorithm)
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        assert_eq!(2, key_algorithms.len());
        assert!(key_algorithms.contains(&KeyAlgorithm::Rsa4K));
        assert!(key_algorithms.contains(&KeyAlgorithm::P256));

        Ok(())
    }

    // Assert the KeyLocation enum aligns with the database enumeration.
    #[tokio::test]
    async fn key_locations_match_db() -> Result<()> {
        let db_pool = pool("sqlite::memory:").await?;
        migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;

        let key_algorithms = sqlx::query("SELECT * FROM key_locations;")
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .map(|row| {
                let location: &str = row.get("location");
                KeyLocation::try_from(location)
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        assert_eq!(3, key_algorithms.len());
        assert!(key_algorithms.contains(&KeyLocation::Pkcs11));
        assert!(key_algorithms.contains(&KeyLocation::SequoiaSoftkey));
        assert!(key_algorithms.contains(&KeyLocation::Encrypted));

        Ok(())
    }

    // Assert the PublicKeyMaterialType enum aligns with the database enumeration.
    #[tokio::test]
    async fn public_key_material_types() -> Result<()> {
        let db_pool = pool("sqlite::memory:").await?;
        migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;

        let public_key_material_types = sqlx::query("SELECT * FROM public_key_material_types;")
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .map(|row| {
                let type_: &str = row.get("type");
                PublicKeyMaterialType::try_from(type_)
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        assert_eq!(2, public_key_material_types.len());
        assert!(public_key_material_types.contains(&PublicKeyMaterialType::X509));
        assert!(public_key_material_types.contains(&PublicKeyMaterialType::Revocation));

        Ok(())
    }

    // Assert keys can be created and removed from the database.
    #[tokio::test]
    async fn key_create_list_delete() -> Result<()> {
        let db_pool = pool("sqlite::memory:").await?;
        migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let key = Key::create(
            &mut conn,
            "test-name",
            "unique-handle",
            KeyAlgorithm::P256,
            KeyLocation::Pkcs11,
            "pkcs11://something",
            "public-key",
        )
        .await?;

        let keys = Key::list(&mut conn).await?;
        assert_eq!(keys, vec![key.clone()]);

        let keys_deleted = Key::delete(&mut conn, key.name.as_str()).await?;
        assert_eq!(1, keys_deleted);
        assert_eq!(0, Key::list(&mut conn).await?.len());

        Ok(())
    }

    // Keys should only be allowed to have locations from the key_locations table.
    #[tokio::test]
    async fn key_constraint_on_location() -> Result<()> {
        let db_pool = pool("sqlite::memory:").await?;
        migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let key_algorithm_str = KeyAlgorithm::P256.as_str();
        let result = sqlx::query(
            "INSERT INTO keys (name, key_algorithm, key_location, handle, key_material, public_key) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind("test-name")
        .bind(key_algorithm_str)
        .bind("not-valid")
        .bind("unique")
        .bind("some-encrypted-key")
        .bind("some-public-key")
        .fetch_one(&mut *conn)
        .await;

        match result {
            Ok(_) => panic!("Database missing foreign key contraint on key_algorithm"),
            Err(sqlx::Error::Database(error)) => {
                assert_eq!(error.kind(), ErrorKind::ForeignKeyViolation);
            }
            _ => panic!("Unexpected error"),
        };

        Ok(())
    }

    // Keys should only be allowed to have types from the key_algorithms table.
    #[tokio::test]
    async fn key_constraint_on_type() -> Result<()> {
        let db_pool = pool("sqlite::memory:").await?;
        migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let key_location_str = KeyLocation::SequoiaSoftkey.as_str();
        let result = sqlx::query(
            "INSERT INTO keys (name, key_algorithm, key_location, handle, key_material, public_key) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind("test-name")
        .bind("not-valid")
        .bind(key_location_str)
        .bind("unique")
        .bind("key-material")
        .bind("public-key")
        .fetch_one(&mut *conn)
        .await;

        match result {
            Ok(_) => panic!("Database missing foreign key contraint on key_algorithm"),
            Err(sqlx::Error::Database(error)) => {
                assert_eq!(error.kind(), ErrorKind::ForeignKeyViolation);
            }
            _ => panic!("Unexpected error"),
        };

        Ok(())
    }
}
