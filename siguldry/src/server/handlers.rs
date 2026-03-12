// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::sync::Arc;

use openssl::{hash::MessageDigest, x509::X509};
use sequoia_openpgp::parse::Parse;
use sqlx::SqliteConnection;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    protocol::{self, Certificate, DigestAlgorithm, Response, ServerError},
    server::{
        Config,
        db::{self, User},
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
        Ok(Response::WhoAmI {
            user: self.user.name.clone(),
        })
    }

    #[instrument(skip_all, err)]
    pub(crate) async fn list_keys(
        &self,
        conn: &mut SqliteConnection,
        user: &User,
    ) -> Result<Response, ServerError> {
        let mut keys = vec![];
        for key in db::Key::list_by_user(conn, user).await? {
            let certificates = certs_for_key(conn, &key).await?;
            keys.push(protocol::Key {
                name: key.name,
                key_algorithm: key.key_algorithm,
                handle: key.handle,
                public_key: key.public_key,
                certificates,
            });
        }

        Ok(Response::ListKeys { keys })
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn unlock(
        &mut self,
        key: String,
        password: String,
    ) -> Result<Response, ServerError> {
        self.ipc_helper.unlock_request(key, password).await
    }

    #[instrument(skip_all, err, fields(key = key_name))]
    pub(crate) async fn public_key(
        &self,
        conn: &mut SqliteConnection,
        key_name: String,
    ) -> Result<Response, ServerError> {
        let key = db::Key::get(conn, &key_name).await?;
        let certificates = certs_for_key(conn, &key).await?;

        Ok(Response::GetKey {
            key: protocol::Key {
                name: key.name,
                key_algorithm: key.key_algorithm,
                handle: key.handle,
                public_key: key.public_key,
                certificates,
            },
        })
    }

    #[instrument(skip_all, err, fields(key = key_name))]
    pub(crate) async fn sign(
        &mut self,
        key_name: &str,
        digest_algorithm: DigestAlgorithm,
        digest: String,
    ) -> Result<Response, ServerError> {
        let mut response = self
            .ipc_helper
            .sign_request(key_name.to_string(), vec![(digest_algorithm, digest)])
            .await?;

        Ok(Response::Sign {
            signature: response.pop().unwrap(),
        })
    }

    #[instrument(skip_all, err, fields(key = key_name))]
    pub(crate) async fn sign_all(
        &mut self,
        key_name: &str,
        digests: Vec<(DigestAlgorithm, String)>,
    ) -> Result<Response, ServerError> {
        let signatures = self
            .ipc_helper
            .sign_request(key_name.to_string(), digests)
            .await?;

        Ok(Response::SignPrehashed { signatures })
    }

    #[instrument(skip_all, err)]
    pub(crate) async fn shutdown(self) -> anyhow::Result<()> {
        self.ipc_helper.shutdown().await
    }
}

async fn certs_for_key(
    conn: &mut SqliteConnection,
    key: &db::Key,
) -> anyhow::Result<Vec<Certificate>> {
    let certificates = {
        let x509 = db::PublicKeyMaterial::list(conn, key, db::PublicKeyMaterialType::X509)
            .await?
            .into_iter()
            .filter_map(|cert| {
                X509::from_pem(cert.data.as_bytes())
                    .ok()
                    .and_then(|c| c.digest(MessageDigest::sha256()).ok())
                    .map(hex::encode_upper)
                    .map(|fingerprint| crate::protocol::Certificate {
                        name: cert.name,
                        certificate: cert.data,
                        certificate_type: crate::protocol::CertificateType::X509,
                        fingerprint,
                    })
            });
        let pgp = db::PublicKeyMaterial::list(conn, key, db::PublicKeyMaterialType::OpenPgpCert)
            .await?
            .into_iter()
            .filter_map(|cert| {
                sequoia_openpgp::Cert::from_bytes(cert.data.as_bytes())
                    .ok()
                    .map(|parsed_cert| crate::protocol::Certificate {
                        name: cert.name,
                        certificate: cert.data,
                        certificate_type: crate::protocol::CertificateType::Pgp,
                        fingerprint: parsed_cert.fingerprint().to_hex(),
                    })
            });

        x509.chain(pgp).collect()
    };

    Ok(certificates)
}
