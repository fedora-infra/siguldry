// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Import users and keys from Sigul.
//!
//! Sigul uses a combination of an SQLite database and a state directory to manage its users and
//! keys.
//!
//! # SQLite Database
//!
//! The database is stored at `server.sqlite` relative to the state directory. The database schema,
//! as of Sigul 1.3 is as follows:
//!
//! CREATE TABLE users (
//!     id INTEGER NOT NULL,
//!     name TEXT NOT NULL,
//!     sha512_password BINARY,
//!     admin BOOLEAN NOT NULL,
//!     PRIMARY KEY (id),
//!     UNIQUE (name)
//! );
//! CREATE TABLE keys (
//!     id INTEGER NOT NULL,
//!     name TEXT NOT NULL,
//!     keytype VARCHAR(6) NOT NULL,
//!     fingerprint TEXT NOT NULL,
//!     PRIMARY KEY (id),
//!     UNIQUE (name),
//!     UNIQUE (fingerprint)
//! );
//! CREATE TABLE key_accesses (
//!     id INTEGER NOT NULL,
//!     key_id INTEGER NOT NULL,
//!     user_id INTEGER NOT NULL,
//!     encrypted_passphrase BINARY NOT NULL,
//!     key_admin BOOLEAN NOT NULL,
//!     PRIMARY KEY (id),
//!     UNIQUE (key_id,user_id),
//!     FOREIGN KEY(key_id) REFERENCES keys (id),
//!     FOREIGN KEY(user_id) REFERENCES users (id)
//! );
//!
//! # Keys
//!
//! Keys are stored in the state directory. There are three general keytypes.
//!
//! ## PGP
//!
//! PGP keys are stored in the `gnupg/` directory relative to the state directory root by default,
//! and is used at the GPG_HOME location. Sigul uses gpg to generate and access the keys so the
//! layout should follow the standard for the version of gpg installed on the Sigul host.
//!
//! Sigul supports configuring a different location for the PGP keys; this is not supported by the
//! import tool and users must move the non-standard location to gnupg/ relative to the provided
//! state directory.
//!
//! In the database, these keys have the keytype of "gnupg".
//!
//! ## Non-PGP Keys and X509 Certificates
//!
//! Sigul stores other key pairs and any associated X509 certificates in the `keys/` directory
//! relative to the state directory. The keys are named using the `fingerprint` value in the
//! `keys` table in the SQLite database. Private keys are stored in the format `{fingerprint}.pem`.
//! Public keys are stored in `{fingerprint}.public.pem`. X509 certificates for the key pair are
//! stored in `{fingerprint}.cert.{certificate-name}.pem`.
//!
//! In the database, these keys have the keytype of "ECC" or "RSA".
//!
//! ## PKCS #11 Tokens
//!
//! Sigul has rudimentary support for PKCS #11 tokens. A row in the `keys` table is added for a
//! key in the token with the PKCS #11 URI. The user PIN for the token is stored in key_accesses
//! records for each user. Since Siguldry handles PKCS #11 tokens quite differently, these keys
//! are not importable.
//!
//! In the database, these keys have the keytype of "PKCS11".
//!
//! # Key Accesses
//!
//! Sigul encrypts keys using a server-generated secret. It then encrypts that secret using
//! per-user passwords via GPG symmetric encryption. Optionally, it will encrypt the server-
//! generated secret using a PKCS #11 public key or via TPM 1.2 (unsupported by this tool).
//! The per-user password is then used to encrypt the output of the "bound" server-generated
//! secret that was used to encrypt the key.
//!
//! To access the secret keys, the operations are:
//!
//! 1. Decrypt the value in the `encrypted_passphrase` using GPG.
//! 2. If the value obtained from step 1 begins with a "{" or "[" character the value is a
//!    JSON object or list of objects containing the PKCS #11 or TPM 1.2 encrypted secret used
//!    to encrypt the key. Decrypt the value using the information found in the JSON object
//! 3. Repeat step 2 until the value does not start with "{" or "["
//! 4. Use the result to decrypt the private key.

use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
};

use anyhow::Context;
use sequoia_openpgp::{crypto::Password, serialize::MarshalInto};
use siguldry::{
    protocol::KeyAlgorithm,
    server::{Pkcs11Binding, crypto, db},
};
use sqlx::{Pool, Row, Sqlite, SqliteConnection, SqlitePool, sqlite::SqliteConnectOptions};
use tracing::instrument;

use crate::management::PromptPassword;

/// A user record from the sigul database.
#[derive(Debug, Clone, sqlx::FromRow)]
struct SigulUser {
    id: i64,
    name: String,
}

impl SigulUser {
    #[instrument(skip_all, err)]
    async fn list(conn: &mut SqliteConnection) -> anyhow::Result<Vec<Self>> {
        let users = sqlx::query_as("SELECT id, name FROM users ORDER BY id ASC")
            .fetch_all(&mut *conn)
            .await?;
        tracing::info!("Loaded {} users from sigul database", users.len());

        Ok(users)
    }
}

/// Key types supported by sigul.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SigulKeyType {
    /// A GPG key stored in the gnupg home directory.
    Gnupg,
    /// An ECC key stored as PEM files in the keys/ directory.
    Ecc,
    /// An RSA key stored as PEM files in the keys/ directory.
    Rsa,
    /// A key stored in a PKCS #11 hardware token (unsupported).
    Pkcs11,
}

impl TryFrom<&str> for SigulKeyType {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "gnupg" => Ok(Self::Gnupg),
            "ECC" => Ok(Self::Ecc),
            "RSA" => Ok(Self::Rsa),
            "PKCS11" => Ok(Self::Pkcs11),
            _ => Err(anyhow::anyhow!(
                "This Sigul database contains unknown key types and cannot be imported"
            )),
        }
    }
}

/// A key record from the sigul database.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
struct SigulKey {
    id: i64,
    name: String,
    keytype: SigulKeyType,
    /// For gnupg keys, this is the GPG fingerprint.
    /// For ECC/RSA keys, this is the SHA1 hash of the public key DER.
    fingerprint: String,
    /// Path to where the keys are store; how they're stored depends on the `keytype`
    ///
    /// For RSA/ECC keys, public, private, and x509 certs are in this directory and prefixed with
    /// the fingerprint then ".pem" for encrypted secret, "public.pem" for public keys, and
    /// "cert.<name>.pem" for certs.
    ///
    /// For PGP keys, they're stored however gnupg wrote them out (version-dependent).
    keys_directory: PathBuf,
}

impl SigulKey {
    #[instrument(skip_all, err)]
    async fn list(
        conn: &mut SqliteConnection,
        sigul_data_directory: &Path,
    ) -> anyhow::Result<Vec<Self>> {
        let keys = sqlx::query("SELECT id, name, keytype, fingerprint FROM keys ORDER BY id ASC")
            .fetch_all(&mut *conn)
            .await?
            .iter()
            .map(|row| {
                let keytype = row
                    .get::<&str, usize>(2)
                    .try_into()
                    .expect("Database contains unknown keytype");
                let keys_directory = match keytype {
                    SigulKeyType::Gnupg => sigul_data_directory.join("gnupg"),
                    SigulKeyType::Ecc | SigulKeyType::Rsa => sigul_data_directory.join("keys"),
                    SigulKeyType::Pkcs11 => PathBuf::new(),
                };
                Self {
                    id: row.get(0),
                    name: row.get(1),
                    keytype,
                    fingerprint: row.get(3),
                    keys_directory,
                }
            })
            .collect::<Vec<Self>>();
        tracing::info!("Loaded {} keys from sigul database", keys.len());

        Ok(keys)
    }

    fn private_key_pem(&self) -> anyhow::Result<String> {
        let private_key_path = self
            .keys_directory
            .join(format!("{}.pem", self.fingerprint));
        let private_key = std::fs::read_to_string(&private_key_path).with_context(|| {
            format!(
                "Failed to read private key from {}",
                private_key_path.display()
            )
        })?;

        Ok(private_key)
    }

    fn public_key_pem(&self) -> anyhow::Result<String> {
        let public_key_path = self
            .keys_directory
            .join(format!("{}.public.pem", self.fingerprint));
        let public_key = std::fs::read_to_string(&public_key_path).with_context(|| {
            format!(
                "Failed to read public key from {}",
                public_key_path.display()
            )
        })?;

        Ok(public_key)
    }

    fn certificates_pem(&self) -> anyhow::Result<Vec<(String, String)>> {
        let cert_format = format!("{}.cert.", self.fingerprint);
        let certs = self
            .keys_directory
            .read_dir()?
            .filter_map(|dir_entry| {
                if let Ok(dir_entry) = dir_entry {
                    if let Some(name) = dir_entry.file_name().as_os_str().to_str()
                        && name.starts_with(&cert_format)
                    {
                        tracing::debug!(
                            "Reading certificate for key '{}' from {}",
                            self.name,
                            dir_entry.path().display()
                        );
                        let cert_name = name
                            .strip_prefix(&cert_format)
                            .and_then(|s| s.strip_suffix(".pem"))
                            .map(String::from);
                        let pem_cert = std::fs::read_to_string(dir_entry.path()).ok();
                        if let (Some(cert_name), Some(pem_cert)) = (cert_name, pem_cert) {
                            Some((cert_name, pem_cert))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(certs)
    }

    // Import a non-PGP key pair and any associated certificates.
    #[instrument(skip_all, err)]
    async fn import_keypair(
        &self,
        conn: &mut SqliteConnection,
        sigul_key_password: Password,
    ) -> anyhow::Result<db::Key> {
        let pubkey_pem = self.public_key_pem()?;
        let privkey_pem = self.private_key_pem()?;

        let pubkey = openssl::pkey::PKey::public_key_from_pem(pubkey_pem.as_bytes())?;
        let key_algorithm = if pubkey.rsa().is_ok() {
            match pubkey.bits() {
                4096 => KeyAlgorithm::Rsa4K,
                2048 => KeyAlgorithm::Rsa2K,
                other => {
                    tracing::warn!(
                        sigul_key = self.name,
                        "RSA key found, but key size ({}) is unsupported",
                        other
                    );
                    return Err(anyhow::anyhow!("Unsupported RSA key size"));
                }
            }
        } else if let Ok(ecc_key) = pubkey.ec_key() {
            if ecc_key.group().curve_name() == Some(openssl::nid::Nid::X9_62_PRIME256V1) {
                KeyAlgorithm::P256
            } else {
                tracing::warn!(sigul_key = self.name, curve=?ecc_key.group().curve_name(), "Found unsupported ECC key; skipping");
                return Err(anyhow::anyhow!("ECC key uses unsupported curve"));
            }
        } else {
            return Err(anyhow::anyhow!("Unknown key type"));
        };
        tracing::debug!(?key_algorithm, "Key algorithm detected");

        let privkey = sigul_key_password.map(|password| {
            openssl::pkey::PKey::private_key_from_pem_passphrase(privkey_pem.as_bytes(), password)
        })?;
        tracing::debug!("Successfully decrypted private key");
        let key_material = crypto::sigul::encrypt_key(sigul_key_password, privkey)?;
        let handle = hex::encode_upper(openssl::hash::hash(
            openssl::hash::MessageDigest::sha256(),
            &pubkey.public_key_to_der()?,
        )?);
        let key = db::Key::create(
            conn,
            &self.name,
            &handle,
            key_algorithm,
            db::KeyPurpose::Signing,
            &key_material,
            &pubkey_pem,
            None,
            None,
        )
        .await?;

        for (name, pem) in self.certificates_pem()? {
            db::PublicKeyMaterial::create(conn, &key, name, db::PublicKeyMaterialType::X509, pem)
                .await?;
        }

        Ok(key)
    }

    #[instrument(skip_all, err)]
    async fn import_gnupg(
        &self,
        conn: &mut SqliteConnection,
        sigul_key_password: Password,
    ) -> anyhow::Result<db::Key> {
        // It's annoying to use tokio's Command with a protected password
        let mut child = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(&self.keys_directory)
            .arg("--batch")
            .arg("--pinentry-mode")
            .arg("loopback")
            .arg("--passphrase-fd")
            .arg("0")
            .arg("--armor")
            .arg("--export-secret-keys")
            .arg(self.fingerprint.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to execute gpg to export secret key")?;
        let mut stdin = child.stdin.take().expect("Must spawn gpg with piped stdin");
        sigul_key_password.map(|password| {
            stdin.write_all(password)?;
            stdin.write_all(b"\n")
        })?;
        drop(stdin);
        let secret_output = child.wait_with_output()?;
        if !secret_output.status.success() {
            return Err(anyhow::anyhow!(
                "gpg export secret key failed: {}",
                String::from_utf8_lossy(&secret_output.stderr)
            ));
        }
        let (cert, key_algorithm) =
            crypto::sigul::check_gpg_key(&secret_output.stdout, sigul_key_password)?;
        let fingerprint = cert.fingerprint().to_hex();
        let private_key = String::from_utf8(cert.as_tsk().armored().to_vec()?)?;
        let public_key = String::from_utf8(cert.strip_secret_key_material().armored().to_vec()?)?;
        let key = db::Key::create(
            conn,
            &self.name,
            &fingerprint,
            key_algorithm,
            db::KeyPurpose::PGP,
            &private_key,
            &public_key,
            None,
            None,
        )
        .await?;

        Ok(key)
    }

    async fn as_siguldry_key(
        &self,
        conn: &mut SqliteConnection,
        sigul_key_password: Password,
    ) -> anyhow::Result<db::Key> {
        match self.keytype {
            SigulKeyType::Gnupg => self.import_gnupg(conn, sigul_key_password).await,
            SigulKeyType::Ecc | SigulKeyType::Rsa => {
                self.import_keypair(conn, sigul_key_password).await
            }
            SigulKeyType::Pkcs11 => Err(anyhow::anyhow!(
                "Skipping PKCS11 key {}; enroll it later",
                self.name
            )),
        }
    }
}

/// A key access record from the sigul database.
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
struct SigulKeyAccess {
    id: i64,
    key_id: i64,
    user_id: i64,
    encrypted_passphrase: Vec<u8>,
    key_admin: bool,
}

impl SigulKeyAccess {
    #[instrument(skip_all, err)]
    async fn for_user(conn: &mut SqliteConnection, user: &SigulUser) -> anyhow::Result<Vec<Self>> {
        let accesses: Vec<SigulKeyAccess> = sqlx::query_as(
            "SELECT id, key_id, user_id, encrypted_passphrase, key_admin \
            FROM key_accesses \
            WHERE user_id = $1 \
            ORDER BY key_id ASC",
        )
        .bind(user.id)
        .fetch_all(&mut *conn)
        .await?;

        tracing::info!(
            "Loaded {} key access records for {}",
            accesses.len(),
            user.name
        );
        Ok(accesses)
    }
}

fn prompt_yes_no(prompt: &str) -> anyhow::Result<bool> {
    print!("{} [y/N]: ", prompt);
    std::io::stdout().flush()?;
    let answer = std::io::stdin()
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to read yes/no"))?
        .map(|line| line.trim().to_lowercase())?;
    Ok(answer == "y" || answer == "yes")
}

pub async fn migrate_sigul(
    siguldry_conn: &mut SqliteConnection,
    siguldry_bindings: &[Pkcs11Binding],
    sigul_data_directory: PathBuf,
    sigul_binding: Option<Pkcs11Binding>,
) -> anyhow::Result<()> {
    let db_path = sigul_data_directory.join("server.sqlite");
    if !db_path.exists() {
        return Err(anyhow::anyhow!(
            "Sigul database not found at {}",
            db_path.display()
        ));
    }
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
        .context("The database URL couldn't be parsed.")?
        .create_if_missing(false)
        .foreign_keys(true)
        .read_only(true);
    let sigul_pool: Pool<Sqlite> = SqlitePool::connect_with(opts)
        .await
        .with_context(|| format!("Failed to connect to the database at {}", db_path.display()))?;
    let mut sigul_conn = sigul_pool.acquire().await?;

    let sigul_users = SigulUser::list(&mut sigul_conn)
        .await
        .with_context(|| format!("Failed to read user table from {}", db_path.display()))?;
    let sigul_keys = SigulKey::list(&mut sigul_conn, &sigul_data_directory)
        .await
        .with_context(|| format!("Failed to read keys table from {}", db_path.display()))?;
    // Maps the Sigul key id to the Siguldry key and is used to track if we've imported a key yet
    let mut imported_keys: HashMap<i64, db::Key> = HashMap::new();
    let mut imported_users: Vec<db::User> = vec![];
    let mut imported_key_accesses: Vec<db::KeyAccess> = vec![];

    // To completely migrate, we need to walk through each user's key access tokens to decrypt and re-encrypt
    // the key's encryption key using the new binding method.
    let mut skipped_users: Vec<SigulUser> = vec![];
    let mut skipped_key_accesses: Vec<SigulKeyAccess> = vec![];
    for sigul_user in sigul_users.iter() {
        if !prompt_yes_no(&format!("Import user '{}'?", sigul_user.name))? {
            println!(
                "Skipping user '{}' (any keys that only they can access will also be skipped)",
                sigul_user.name
            );
            skipped_users.push(sigul_user.clone());
            continue;
        }
        let user = db::User::create(siguldry_conn, &sigul_user.name)
            .await
            .context("Failed to create new user record in the siguldry database")?;
        imported_users.push(user.clone());

        // Walk through the keys they can access and prompt them for the user password
        let sigul_accesses = SigulKeyAccess::for_user(&mut sigul_conn, sigul_user)
            .await
            .with_context(|| format!("Failed to read key accesses from {}", db_path.display()))?;
        for sigul_key_access in sigul_accesses.iter() {
            let sigul_key = sigul_keys
                .iter()
                .find(|k| k.id == sigul_key_access.key_id)
                .ok_or_else(|| {
                    anyhow::anyhow!("foreign key constrait violation on sigul's key access key_id")
                })?;
            if sigul_key.keytype == SigulKeyType::Pkcs11 {
                println!(
                    "User '{}' has access to '{}' but this is a PKCS#11-backed key which aren't importable; skipping it",
                    user.name, sigul_key.name
                );
                continue;
            }

            if !prompt_yes_no(&format!(
                "Import {}'s access to the '{}' key (you need to know their access password)?",
                sigul_user.name, sigul_key.name
            ))? {
                println!("Skipping user's access to '{}'", sigul_key.name);
                skipped_key_accesses.push(sigul_key_access.clone());
                continue;
            }
            let (sigul_key_password, encrypted_password) = loop {
                let user_password = PromptPassword::new(format!(
                    "Enter {}'s user password to access the key '{}':",
                    user.name, sigul_key.name
                ))?
                .prompt()?;
                match crypto::binding::sigul::unbind_key_password(
                    user_password.clone(),
                    &sigul_key_access.encrypted_passphrase,
                    &sigul_binding,
                )
                .await
                {
                    Ok(sigul_key_password) => {
                        let encrypted_password = crypto::binding::encrypt_key_password(
                            siguldry_bindings,
                            user_password.clone(),
                            sigul_key_password.clone(),
                        )
                        .context("Failed to bind the key password")?;
                        tracing::debug!("Key passphrase has been successfully bound for Siguldry");
                        break Ok::<_, anyhow::Error>((sigul_key_password, encrypted_password));
                    }
                    Err(error) => eprintln!(
                        "Failed to unbind the '{}' key with that password ({}), please try again",
                        sigul_key.name, error,
                    ),
                };
            }?;

            // Look up the key, then see if we've previously imported the key itself.
            let key = if let Some(imported_key) = imported_keys.get(&sigul_key.id) {
                imported_key
            } else {
                tracing::debug!(sigul_key.name, "Importing key material");
                match sigul_key
                    .as_siguldry_key(siguldry_conn, sigul_key_password)
                    .await
                {
                    Ok(key) => {
                        imported_keys.insert(sigul_key.id, key);
                        imported_keys
                            .get(&sigul_key.id)
                            .expect("The key was just inserted into the map")
                    }
                    Err(error) => {
                        eprintln!("Failed to import the Sigul key: {error}");
                        continue;
                    }
                }
            };
            let siguldry_access = db::KeyAccess::create(
                siguldry_conn,
                key,
                &user,
                encrypted_password,
                sigul_key_access.key_admin,
            )
            .await?;
            imported_key_accesses.push(siguldry_access);
        }
    }

    if !skipped_users.is_empty() {
        println!(
            "\nSkipped {} user(s): {}",
            skipped_users.len(),
            skipped_users
                .into_iter()
                .map(|u| u.name)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for skipped_key in sigul_keys
        .into_iter()
        .filter(|k| !imported_keys.contains_key(&k.id))
    {
        eprintln!(
            "WARNING: Did not import the '{}' key as the user was skipped or the key access was skipped",
            skipped_key.name
        );
    }

    Ok(())
}
