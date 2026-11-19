// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Context;
use cryptoki::context::Pkcs11;
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use openssl::pkey::PKey;
use sequoia_openpgp::crypto::Password;
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use uuid::Uuid;

use crate::error::ServerError;
use crate::ipc_common::IpcClient;
use crate::protocol;
use crate::server::config::Pkcs11Binding;
use crate::server::crypto::binding::PinValidation;
use crate::{
    protocol::{DigestAlgorithm, Signature},
    server::{Config, crypto, db},
};

type KeyMap = HashMap<String, UnlockedKey>;

enum UnlockedKey {
    Private {
        key: PKey<openssl::pkey::Private>,
    },
    Pkcs11 {
        // Used to track if we've already loaded the module
        module: PathBuf,
        pkcs11: Pkcs11,
        slot: Slot,
        pin: AuthPin,
    },
}

/// The PKCS#11 bindings required to access keys, along with the PINs provided at service startup.
/// This is redefined from [`Pkcs11Binding`] because it does need to serialize/deserialize the PIN.
#[derive(Serialize, Deserialize)]
#[allow(clippy::exhaustive_enums)]
#[doc(hidden)]
struct BindingWithPin {
    public_key: PathBuf,
    private_key: String,
    pin: String,
}

impl From<BindingWithPin> for Pkcs11Binding {
    fn from(value: BindingWithPin) -> Self {
        Pkcs11Binding {
            certificate: value.public_key,
            private_key: Some(value.private_key),
            pin: Some(Password::from(value.pin)),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[allow(clippy::exhaustive_enums)]
#[doc(hidden)]
enum Request {
    Config {
        user: String,
        database_path: String,
        session_id: Uuid,
        pkcs11_bindings: Vec<BindingWithPin>,
    },
    Unlock {
        key: String,
        password: String,
    },
    Sign {
        key: String,
        digests: Vec<(DigestAlgorithm, String)>,
    },
    /// Log into each binding's token once to check its PIN.
    ///
    /// This must be the first and only request on a connection. It needs no user or database,
    /// so the server can send it at startup, before any client connects.
    CheckPin {
        pkcs11_bindings: Vec<BindingWithPin>,
    },
}

#[derive(Serialize, Deserialize)]
#[allow(clippy::exhaustive_enums)]
#[doc(hidden)]
enum Response {
    Signatures {
        signatures: Vec<Signature>,
    },
    PgpSign {
        payload_size: usize,
    },
    Success {},
    Failure {
        reason: String,
    },
    /// The PIN couldn't be checked (for example, the token wasn't reachable); it was not rejected.
    Unverified {
        reason: String,
    },
}

/// Collect the bindings that have both a private key and a PIN, ready to send to the signer.
fn bindings_with_pin(config: &Config) -> anyhow::Result<Vec<BindingWithPin>> {
    let mut bindings = vec![];
    for binding in config.pkcs11_bindings.iter() {
        if let (Some(private_key), Some(pin)) = (&binding.private_key, &binding.pin) {
            let pin = pin.map(|p| String::from_utf8(p.to_vec()))?;
            bindings.push(BindingWithPin {
                public_key: binding.certificate.clone(),
                private_key: private_key.clone(),
                pin,
            });
        }
    }
    Ok(bindings)
}

/// Ask the signing helper to check the binding PINs against their tokens.
///
/// The helper is the process that uses the tokens, so this works even when the server itself
/// has no access to the hardware. It's only an error if a token rejects a PIN; if the helper
/// can't be reached or can't check a PIN, we log a warning and carry on, since the PIN is
/// checked again when keys are unbound.
///
/// # Errors
///
/// Returns an error if a binding's PIN isn't valid UTF-8, or if the token rejects a PIN.
pub async fn check_binding_pin(config: &Config) -> anyhow::Result<()> {
    check_binding_pin_within(config, PIN_CHECK_TIMEOUT).await
}

/// How long the server waits for the signing helper to answer a PIN check at startup.
///
/// The helper loads the PKCS#11 module and logs into each token, which can be slow on real
/// hardware such as a TPM. If it takes longer, the server logs a warning and starts anyway,
/// and the PIN is checked when keys are unbound.
const PIN_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

async fn check_binding_pin_within(
    config: &Config,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let pkcs11_bindings = bindings_with_pin(config)?;
    if pkcs11_bindings.is_empty() {
        return Ok(());
    }

    let request = async {
        let mut client = IpcClient::new(&config.signer_socket_path).await?;
        let response = client
            .request(&Request::CheckPin { pkcs11_bindings })
            .await?;
        if let Err(error) = client.shutdown().await {
            tracing::debug!(?error, "Failed to shut down the signing helper connection");
        }
        Ok::<_, anyhow::Error>(response)
    };
    let response = tokio::time::timeout(timeout, request)
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "the signing helper didn't reply within {timeout:?}"
            ))
        });
    let response = match response.and_then(|r| Ok(serde_json::from_value(r)?)) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                ?error,
                "Unable to ask the signing helper to validate the binding PIN; \
                it will be checked when keys are unbound"
            );
            return Ok(());
        }
    };

    match response {
        Response::Success {} => {
            tracing::info!("The signing helper validated the binding PIN with the PKCS#11 token");
            Ok(())
        }
        Response::Unverified { reason } => {
            tracing::warn!(
                reason,
                "Unable to validate the binding PIN; it will be checked when keys are unbound"
            );
            Ok(())
        }
        Response::Failure { reason } => Err(anyhow::anyhow!(reason)),
        Response::Signatures { .. } | Response::PgpSign { .. } => {
            tracing::warn!("The signing helper returned an unexpected response to a PIN check");
            Ok(())
        }
    }
}

/// Check each binding's PIN by logging into its token once.
async fn check_pins(pkcs11_bindings: Vec<BindingWithPin>) -> Response {
    let bindings: Vec<Pkcs11Binding> = pkcs11_bindings.into_iter().map(|b| b.into()).collect();
    let result = tokio::task::spawn_blocking(move || {
        let mut skipped = vec![];
        for binding in &bindings {
            match crypto::binding::validate_binding_pin(binding)? {
                PinValidation::Valid => {}
                PinValidation::Skipped(reason) => skipped.push(reason),
            }
        }
        Ok::<_, anyhow::Error>(skipped)
    })
    .await;

    match result {
        Ok(Ok(skipped)) if skipped.is_empty() => Response::Success {},
        Ok(Ok(skipped)) => Response::Unverified {
            reason: skipped.join("; "),
        },
        Ok(Err(error)) => Response::Failure {
            reason: format!("{error:#}"),
        },
        Err(error) => Response::Unverified {
            reason: format!("PIN validation task failed: {error}"),
        },
    }
}

pub(crate) struct Client {
    inner: IpcClient,
}

impl Client {
    pub(crate) async fn new(
        user: String,
        config: Config,
        session_id: Uuid,
    ) -> anyhow::Result<Self> {
        let inner = IpcClient::new(&config.signer_socket_path).await?;
        let mut client = Self { inner };

        tracing::trace!("requesting signing helper config");
        let bindings = bindings_with_pin(&config)?;
        let database_path = config
            .database()
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Database path isn't valid UTF8"))?
            .to_string();
        client
            .inner
            .request(&Request::Config {
                user,
                database_path,
                session_id,
                pkcs11_bindings: bindings,
            })
            .await?;
        tracing::trace!("requested signing helper config");

        Ok(client)
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn unlock_request(
        &mut self,
        key: String,
        password: String,
    ) -> Result<protocol::Response, ServerError> {
        let response = self
            .inner
            .request(&Request::Unlock { key, password })
            .await?;
        let response = serde_json::from_value(response).map_err(|error| {
            tracing::error!(?error, "helper returned invalid response");
            ServerError::Internal
        })?;

        match response {
            Response::Failure { reason } => {
                tracing::error!(reason, "Failed to unlock key");
                Err(ServerError::Internal)
            }
            Response::Success {} => Ok(protocol::Response::Unlock {}),
            _ => {
                tracing::error!("helper returned invalid response");
                Err(ServerError::Internal)
            }
        }
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn sign_request(
        &mut self,
        key: String,
        digests: Vec<(DigestAlgorithm, String)>,
    ) -> Result<Vec<Signature>, ServerError> {
        let response = self.inner.request(&Request::Sign { key, digests }).await?;
        let response = serde_json::from_value(response).map_err(|error| {
            tracing::error!(?error, "helper returned invalid response");
            ServerError::Internal
        })?;

        match response {
            Response::Signatures { signatures } => Ok(signatures),
            Response::Failure { reason } => {
                tracing::error!(reason, "Failed to unlock key");
                Err(ServerError::Internal)
            }
            _ => {
                tracing::error!("helper returned invalid response");
                Err(ServerError::Internal)
            }
        }
    }

    /// Shut down the IPC client.
    pub(crate) async fn shutdown(self) -> anyhow::Result<()> {
        self.inner.shutdown().await?;
        Ok(())
    }
}

/// Start a siguldry-signer helper server.
#[instrument(name = "siguldry-signer", skip_all, fields(user = tracing::field::Empty, session_id = tracing::field::Empty))]
pub async fn serve<
    R: AsyncRead + Unpin + std::fmt::Debug,
    W: AsyncWrite + Unpin + std::fmt::Debug,
>(
    halt_token: CancellationToken,
    requests: R,
    mut responses: W,
) -> anyhow::Result<()> {
    tracing::debug!("Handling requests");
    let mut requests = BufReader::new(requests).lines();

    // Keys that the client has unlocked are stored in this map of key names to key passwords.
    // A performance optimization might be to decrypt the key once; we should benchmark and
    // decide on that.
    let mut key_passwords: KeyMap = HashMap::new();
    let (user, database_path, pkcs11_bindings) = tokio::select! {
        _ = halt_token.cancelled() => {
            tracing::info!("siguldry-helper received shut down signal");
            return Ok(())
        }
        request = requests.next_line() => {
            match request? {
                Some(request) => {
                    let request: Request = serde_json::from_str(&request)?;
                    match request {
                        Request::Config { user, database_path, session_id, pkcs11_bindings } => {
                            tracing::Span::current().record("session_id", tracing::field::display(session_id));
                            let mut response = serde_json::to_string(&Response::Success {  })?;
                            response.push('\n');
                            responses.write_all(response.as_bytes()).await?;
                            let bindings = pkcs11_bindings.into_iter().map(|b| b.into()).collect::<Vec<Pkcs11Binding>>();
                            (user, database_path, bindings)},
                        Request::CheckPin { pkcs11_bindings } => {
                            let mut response = serde_json::to_string(&check_pins(pkcs11_bindings).await)?;
                            response.push('\n');
                            responses.write_all(response.as_bytes()).await?;
                            responses.flush().await?;
                            return Ok(())
                        }
                        _ => return Err(anyhow::anyhow!("The first message must configure this helper"))
                    }
                },
                None => return Ok(())
            }
        }
    };

    let db_pool = db::pool(&database_path, true).await?;
    let mut db_conn = db_pool.acquire().await?;
    let user = db::User::get(&mut db_conn, &user).await?;
    tracing::Span::current().record("user", &user.name);
    drop(db_conn);
    tracing::info!("siguldry-signer is configured and ready to accept requests");

    loop {
        let request = tokio::select! {
            _ = halt_token.cancelled() => {
                tracing::info!("siguldry-signer received shut down signal");
                break;
            }
            request = requests.next_line() => request,
        }?;
        tracing::debug!("siguldry-signer got request");

        let request = if let Some(request) = request {
            serde_json::from_str(&request)?
        } else {
            tracing::info!("siguldry-signer received EOF and is shutting down");
            break;
        };

        let response = match request {
            Request::Config {
                user: _,
                database_path: _,
                session_id: _,
                pkcs11_bindings: _,
            } => Response::Failure {
                reason: "helper cannot be configured twice".to_string(),
            },
            Request::CheckPin { pkcs11_bindings: _ } => Response::Failure {
                reason: "PIN checks must be the first and only request on a connection".to_string(),
            },
            Request::Unlock { key, password } => {
                let mut conn = db_pool.begin().await?;
                match unlock(
                    &mut conn,
                    &mut key_passwords,
                    &pkcs11_bindings,
                    &user,
                    key,
                    Password::from(password),
                )
                .await
                {
                    Ok(_) => Response::Success {},
                    Err(error) => Response::Failure {
                        reason: error.to_string(),
                    },
                }
            }
            Request::Sign { key, digests } => {
                let mut conn = db_pool.begin().await?;
                match sign(&mut conn, &mut key_passwords, &key, digests).await {
                    Ok(signatures) => Response::Signatures { signatures },
                    Err(error) => Response::Failure {
                        reason: error.to_string(),
                    },
                }
            }
        };
        tracing::trace!("About to write response");
        let mut response = serde_json::to_string(&response)?;
        response.push('\n');
        responses.write_all(response.as_bytes()).await?;
        tracing::trace!("Successfully wrote response");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip_all, err, fields(key = key_name))]
async fn unlock(
    conn: &mut SqliteConnection,
    key_passwords: &mut KeyMap,
    pkcs11_bindings: &[Pkcs11Binding],
    user: &db::User,
    key_name: String,
    user_password: Password,
) -> anyhow::Result<()> {
    let key = db::Key::get(conn, &key_name).await?;
    let key_access = db::KeyAccess::get(conn, &key, user).await?;
    let password = crypto::binding::decrypt_key_password(
        pkcs11_bindings,
        user_password.clone(),
        &key_access.encrypted_passphrase,
    )
    .await?;
    if let Some(token_id) = key.pkcs11_token_id {
        let db_token = db::Pkcs11Token::get(conn, token_id).await?;
        let pin = password
            .map(|p| String::from_utf8(p.to_vec()))
            .map(AuthPin::from)?;

        let unlocked_key = if let Some(UnlockedKey::Pkcs11 {
            module: _,
            pkcs11,
            slot: _,
            pin: _,
        }) = key_passwords.values().find(|k| match k {
            UnlockedKey::Pkcs11 {
                module,
                pkcs11: _,
                slot: _,
                pin: _,
            } => &db_token.module_path == module,
            UnlockedKey::Private { .. } => false,
        }) {
            // This module has previously been loaded so we shouldn't re-initialize it
            let slot = db_token.slot(pkcs11)?;
            let session = pkcs11.open_ro_session(slot)?;
            session
                .login(cryptoki::session::UserType::User, Some(&pin))
                .context("Failed to login to the PKCS#11 token")?;

            UnlockedKey::Pkcs11 {
                module: db_token.module_path,
                pkcs11: pkcs11.clone(),
                slot,
                pin,
            }
        } else {
            let pkcs11 = db_token.intialize()?;
            let slot = db_token.slot(&pkcs11)?;
            let session = pkcs11.open_ro_session(slot)?;
            session
                .login(cryptoki::session::UserType::User, Some(&pin))
                .context("Failed to login to the PKCS#11 token")?;

            UnlockedKey::Pkcs11 {
                module: db_token.module_path,
                pkcs11,
                slot,
                pin,
            }
        };

        key_passwords.insert(key.name, unlocked_key);
    } else {
        let private_key = crypto::binding::decrypt_private_key(
            &key,
            &key_access.encrypted_passphrase,
            pkcs11_bindings,
            user_password,
        )
        .await?;
        key_passwords.insert(key.name, UnlockedKey::Private { key: private_key });
    }

    tracing::info!("Unlocked key");
    return Ok(());
}

#[instrument(skip_all, err, fields(key = key_name))]
async fn sign(
    conn: &mut SqliteConnection,
    key_passwords: &mut KeyMap,
    key_name: &str,
    digests: Vec<(DigestAlgorithm, String)>,
) -> anyhow::Result<Vec<Signature>> {
    let key = db::Key::get(conn, key_name).await?;
    let unlocked_key = key_passwords
        .get(key_name)
        .ok_or_else(|| anyhow::anyhow!("You need to unlock the key"))?;

    let signatures = match unlocked_key {
        UnlockedKey::Private { key: private_key } => {
            crypto::signing::sign_with_softkey(&key, private_key, digests)
        }
        UnlockedKey::Pkcs11 {
            module: _,
            pkcs11,
            slot,
            pin,
        } => {
            let session = pkcs11.open_ro_session(*slot)?;
            session.login(UserType::User, Some(pin))?;
            crypto::signing::sign_with_pkcs11(&key, &session, digests)
        }
    }?;

    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tokio::net::UnixListener;

    use super::*;
    use crate::server::crypto::test_utils::setup_hsm;

    fn with_pin(binding: &Pkcs11Binding) -> BindingWithPin {
        BindingWithPin {
            public_key: binding.certificate.clone(),
            private_key: binding.private_key.clone().unwrap(),
            pin: binding
                .pin
                .as_ref()
                .unwrap()
                .map(|p| String::from_utf8(p.to_vec()))
                .unwrap(),
        }
    }

    /// Send one request to a signing helper and return its reply, if any, along with how
    /// the helper finished.
    async fn send(request: &Request) -> Result<(Option<Response>, anyhow::Result<()>)> {
        let (client, server) = tokio::io::duplex(1 << 16);
        let (server_reader, server_writer) = tokio::io::split(server);
        let helper = tokio::spawn(serve(
            CancellationToken::new(),
            server_reader,
            server_writer,
        ));

        let (client_reader, mut client_writer) = tokio::io::split(client);
        let mut request = serde_json::to_string(request)?;
        request.push('\n');
        client_writer.write_all(request.as_bytes()).await?;
        let mut lines = BufReader::new(client_reader).lines();
        let response = lines
            .next_line()
            .await?
            .map(|line| serde_json::from_str(&line))
            .transpose()?;

        Ok((response, helper.await?))
    }

    /// Serve a single signing helper connection on a Unix socket and return a config that
    /// points at it.
    fn serve_one_connection(directory: &std::path::Path) -> Result<Config> {
        let socket_path = directory.join("signer.socket");
        let listener = UnixListener::bind(&socket_path)?;
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let (reader, writer) = stream.into_split();
            serve(CancellationToken::new(), reader, writer).await
        });

        Ok(Config {
            signer_socket_path: socket_path,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn check_pin_correct() -> Result<()> {
        let hsm = setup_hsm()?;
        let (response, helper) = send(&Request::CheckPin {
            pkcs11_bindings: vec![with_pin(hsm.bindings.first().unwrap())],
        })
        .await?;

        assert!(matches!(response, Some(Response::Success {})));
        helper?;
        Ok(())
    }

    #[tokio::test]
    async fn check_pin_incorrect() -> Result<()> {
        let hsm = setup_hsm()?;
        let mut binding = with_pin(hsm.bindings.first().unwrap());
        binding.pin = "not-the-pin".to_string();
        let (response, helper) = send(&Request::CheckPin {
            pkcs11_bindings: vec![binding],
        })
        .await?;

        match response {
            Some(Response::Failure { reason }) => {
                assert!(reason.contains("incorrect"), "unexpected reason: {reason}");
                assert!(
                    !reason.contains("not-the-pin"),
                    "the reason must not echo the PIN: {reason}"
                );
            }
            _ => panic!("expected the helper to reject the PIN"),
        }
        helper?;
        Ok(())
    }

    #[tokio::test]
    async fn check_pin_unreachable_token_is_unverified() -> Result<()> {
        let hsm = setup_hsm()?;
        // SAFETY: tests must run under nextest, which uses a process per test.
        unsafe { std::env::set_var("PKCS11_PROVIDER_MODULE", "/does/not/exist.so") };
        let (response, helper) = send(&Request::CheckPin {
            pkcs11_bindings: vec![with_pin(hsm.bindings.first().unwrap())],
        })
        .await?;

        match response {
            Some(Response::Unverified { reason }) => assert!(
                reason.contains("/does/not/exist.so"),
                "unexpected reason: {reason}"
            ),
            _ => panic!("expected the helper to report the PIN as unverified"),
        }
        helper?;
        Ok(())
    }

    // The helper still requires a config as the first message for anything other than a
    // PIN check.
    #[tokio::test]
    async fn first_request_must_configure_or_check_pin() -> Result<()> {
        let (response, helper) = send(&Request::Unlock {
            key: "some-key".to_string(),
            password: "password".to_string(),
        })
        .await?;

        assert!(response.is_none());
        let error = helper.unwrap_err();
        assert!(
            error.to_string().contains("must configure"),
            "unexpected error: {error:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_binding_pin_correct() -> Result<()> {
        let hsm = setup_hsm()?;
        let mut config = serve_one_connection(hsm.directory.path())?;
        config.pkcs11_bindings = hsm.bindings.clone();

        check_binding_pin(&config).await
    }

    #[tokio::test]
    async fn check_binding_pin_incorrect() -> Result<()> {
        let hsm = setup_hsm()?;
        let mut config = serve_one_connection(hsm.directory.path())?;
        config.pkcs11_bindings = hsm.bindings.clone();
        config
            .pkcs11_bindings
            .first_mut()
            .expect("the test HSM has a binding")
            .pin = Some(Password::from("not-the-pin"));

        let error = check_binding_pin(&config).await.unwrap_err();
        assert!(
            error.to_string().contains("incorrect"),
            "unexpected error: {error:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_binding_pin_unreachable_helper_is_not_fatal() -> Result<()> {
        let hsm = setup_hsm()?;
        let config = Config {
            signer_socket_path: hsm.directory.path().join("no-such.socket"),
            pkcs11_bindings: hsm.bindings.clone(),
            ..Default::default()
        };

        check_binding_pin(&config).await
    }

    #[tokio::test]
    async fn check_binding_pin_unverified_is_not_fatal() -> Result<()> {
        let hsm = setup_hsm()?;
        // SAFETY: tests must run under nextest, which uses a process per test.
        unsafe { std::env::set_var("PKCS11_PROVIDER_MODULE", "/does/not/exist.so") };
        let mut config = serve_one_connection(hsm.directory.path())?;
        config.pkcs11_bindings = hsm.bindings.clone();

        check_binding_pin(&config).await
    }

    // An older signing helper doesn't know about PIN checks and closes the connection.
    #[tokio::test]
    async fn check_binding_pin_helper_without_reply_is_not_fatal() -> Result<()> {
        let hsm = setup_hsm()?;
        let socket_path = hsm.directory.path().join("signer.socket");
        let listener = UnixListener::bind(&socket_path)?;
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            drop(stream);
            Ok::<_, anyhow::Error>(())
        });
        let config = Config {
            signer_socket_path: socket_path,
            pkcs11_bindings: hsm.bindings.clone(),
            ..Default::default()
        };

        check_binding_pin(&config).await
    }

    // A helper that accepts the connection but never answers must not hold up startup.
    #[tokio::test]
    async fn check_binding_pin_silent_helper_times_out() -> Result<()> {
        let hsm = setup_hsm()?;
        let socket_path = hsm.directory.path().join("signer.socket");
        let listener = UnixListener::bind(&socket_path)?;
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            // Hold the connection open without replying until the test ends.
            _ = accepted_tx.send(stream);
            Ok::<_, anyhow::Error>(())
        });
        let config = Config {
            signer_socket_path: socket_path,
            pkcs11_bindings: hsm.bindings.clone(),
            ..Default::default()
        };

        let check = check_binding_pin_within(&config, std::time::Duration::from_millis(200));
        tokio::time::timeout(std::time::Duration::from_secs(10), check)
            .await
            .context("the PIN check waited on a silent helper instead of timing out")??;

        assert!(
            accepted_rx.await.is_ok(),
            "the helper never got the request"
        );
        Ok(())
    }
}
