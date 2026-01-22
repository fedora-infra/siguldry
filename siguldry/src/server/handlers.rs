// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{io::Write, sync::Arc};

use anyhow::Context;
use bytes::Bytes;
use sequoia_openpgp::parse::Parse;
use sqlx::SqliteConnection;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    protocol::{self, DigestAlgorithm, GpgSignatureType, Response, ServerError, json},
    server::{
        Config,
        db::{self, KeyPurpose, User},
        ipc,
    },
};

pub(crate) struct Handler {
    user: User,
    ipc_helper: ipc::Client,
}

impl Handler {
    pub(crate) async fn new(
        config: Arc<Config>,
        user: User,
        session_id: Uuid,
    ) -> anyhow::Result<Self> {
        let ipc_helper =
            ipc::Client::new(user.name.clone(), config.as_ref().clone(), session_id).await?;
        tracing::debug!("signing helper service initialized");
        Ok(Self { user, ipc_helper })
    }

    #[instrument(skip_all, err)]
    pub(crate) fn who_am_i(&self) -> Result<Response, ServerError> {
        Ok(json::Response::WhoAmI {
            user: self.user.name.clone(),
        }
        .into())
    }

    #[instrument(skip_all, err)]
    pub(crate) async fn list_users(
        &self,
        conn: &mut SqliteConnection,
    ) -> Result<Response, ServerError> {
        let users = User::list(conn)
            .await?
            .into_iter()
            .map(|user| user.name)
            .collect();

        Ok(json::Response::ListUsers { users }.into())
    }

    #[instrument(skip_all, err)]
    pub(crate) async fn list_keys(
        &self,
        conn: &mut SqliteConnection,
    ) -> Result<Response, ServerError> {
        let mut keys = vec![];
        for key in db::Key::list(conn).await? {
            let certificates = if key.key_purpose == KeyPurpose::PGP {
                let cert = sequoia_openpgp::Cert::from_bytes(&key.key_material.as_bytes())?;
                let version = cert.primary_key().key().version();
                let fingerprint = cert.fingerprint().to_hex();
                vec![crate::protocol::Certificate::Gpg {
                    version,
                    fingerprint,
                    certificate: key.public_key.clone(),
                }]
            } else {
                db::PublicKeyMaterial::list(conn, &key, db::PublicKeyMaterialType::X509)
                    .await?
                    .into_iter()
                    .map(|cert| crate::protocol::Certificate::X509 {
                        name: cert.name,
                        certificate: cert.data,
                    })
                    .collect()
            };
            keys.push(protocol::Key {
                name: key.name,
                key_algorithm: key.key_algorithm,
                handle: key.handle,
                public_key: key.public_key,
                certificates,
            });
        }

        Ok(json::Response::ListKeys { keys }.into())
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn unlock(
        &mut self,
        key: String,
        password: String,
    ) -> Result<Response, ServerError> {
        self.ipc_helper.unlock_request(key, password).await
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn pgp_sign(
        &mut self,
        key: String,
        signature_type: GpgSignatureType,
        blob: Bytes,
    ) -> Result<Response, ServerError> {
        self.ipc_helper
            .pgp_sign_request(key, signature_type, blob)
            .await
            .map_err(|_e| protocol::ServerError::Internal)
    }

    #[instrument(skip_all, err, fields(key = key_name))]
    pub(crate) async fn public_key(
        &self,
        conn: &mut SqliteConnection,
        key_name: String,
    ) -> Result<Response, ServerError> {
        let key = db::Key::get(conn, &key_name).await?;
        let certificates = if key.key_purpose == KeyPurpose::PGP {
            let cert = sequoia_openpgp::Cert::from_bytes(&key.key_material.as_bytes())?;
            let version = cert.primary_key().key().version();
            let fingerprint = cert.fingerprint().to_hex();
            vec![crate::protocol::Certificate::Gpg {
                version,
                fingerprint,
                certificate: key.public_key.clone(),
            }]
        } else {
            db::PublicKeyMaterial::list(conn, &key, db::PublicKeyMaterialType::X509)
                .await?
                .into_iter()
                .map(|cert| crate::protocol::Certificate::X509 {
                    name: cert.name,
                    certificate: cert.data,
                })
                .collect()
        };

        Ok(json::Response::GetKey {
            key: protocol::Key {
                name: key.name,
                key_algorithm: key.key_algorithm,
                handle: key.handle,
                public_key: key.public_key,
                certificates,
            },
        }
        .into())
    }

    #[instrument(skip_all, err, fields(key = key_name))]
    pub(crate) async fn sign(
        &mut self,
        key_name: &str,
        digest: DigestAlgorithm,
        blob: Bytes,
    ) -> Result<Response, ServerError> {
        let mut hash = openssl::hash::Hasher::new(digest.into())
            .context("OpenSSL missing support for digest")?;
        hash.write_all(&blob)?;
        let hash = hex::encode(hash.finish().context("Unable to hash payload")?);
        let mut response = self
            .ipc_helper
            .sign_request(key_name.to_string(), vec![(digest, hash)])
            .await?;

        Ok(Response {
            json: json::Response::Sign {},
            binary: Some(Bytes::from(response.pop().unwrap().signature)),
        })
    }

    #[instrument(skip_all, err, fields(key = key_name))]
    pub(crate) async fn sign_prehashed(
        &mut self,
        key_name: &str,
        digests: Vec<(DigestAlgorithm, String)>,
    ) -> Result<Response, ServerError> {
        let signatures = self
            .ipc_helper
            .sign_request(key_name.to_string(), digests)
            .await?;

        Ok(Response {
            json: json::Response::SignPrehashed { signatures },
            binary: None,
        })
    }

    #[instrument(skip_all, err)]
    pub(crate) async fn shutdown(self) -> anyhow::Result<()> {
        self.ipc_helper.shutdown().await
    }
}
