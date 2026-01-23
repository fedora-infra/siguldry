// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

#![cfg(feature = "server")]

use std::{
    io::Write,
    net::SocketAddr,
    num::NonZeroU16,
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
};

use anyhow::{Context, bail};
use assert_cmd::cargo;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::Attribute,
    session::UserType,
    slot::Slot,
    types::AuthPin,
};
use sequoia_openpgp::crypto::Password;
use siguldry::{
    bridge, client,
    config::Credentials,
    error::{ClientError, ConnectionError, ProtocolError, ServerError},
    protocol::{DigestAlgorithm, GpgSignatureType},
    server::{self, Pkcs11Binding},
};
use tokio::process::Command;
use tracing::Instrument;

#[derive(Clone)]
struct Creds {
    pub server: Credentials,
    pub bridge: Credentials,
    pub client: Credentials,
}

// Generate a set of credentials in the given directory.
async fn create_credentials(
    dir: &Path,
    bridge_hostname: &str,
    server_hostname: &str,
    client_name: &str,
) -> anyhow::Result<Creds> {
    let mut command = Command::new("bash");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../devel/siguldry_auth_keys.sh");
    let output = command
        .current_dir(dir)
        .arg(script.as_path())
        .args([server_hostname, bridge_hostname, client_name])
        .output()
        .await?;
    if !output.status.success() {
        bail!("Failed to generate auth keys");
    }

    let creds_directory = dir.join("creds/");
    Ok(Creds {
        server: Credentials {
            private_key: creds_directory.join("siguldry.server.private_key.pem"),
            certificate: creds_directory.join("siguldry.server.certificate.pem"),
            ca_certificate: creds_directory.join("siguldry.ca_certificate.pem"),
        },
        bridge: Credentials {
            private_key: creds_directory.join("siguldry.bridge.private_key.pem"),
            certificate: creds_directory.join("siguldry.bridge.certificate.pem"),
            ca_certificate: creds_directory.join("siguldry.ca_certificate.pem"),
        },
        client: Credentials {
            private_key: creds_directory.join("siguldry.client.private_key.pem"),
            certificate: creds_directory.join("siguldry.client.certificate.pem"),
            ca_certificate: creds_directory.join("siguldry.ca_certificate.pem"),
        },
    })
}

// Dropping TempDir cleans up the directory, but it needs to live to the end of the test.
#[allow(dead_code)]
struct Instance {
    pub server: server::service::Listener,
    pub bridge: bridge::Listener,
    pub client: client::Client,
    pub creds: Creds,
    pub state_dir: tempfile::TempDir,
}

impl Instance {
    pub async fn halt(self) -> anyhow::Result<()> {
        drop(self.client);
        self.server.halt().await?;
        self.bridge.halt().await?;
        Ok(())
    }
}

pub mod keys {
    pub const GPG_KEY_NAME: &str = "test-gpg-key";
    pub const GPG_KEY_PASSWORD: &str = "🪿🪿🪿";
    pub const GPG_KEY_EMAIL: &str = "admin@example.com";

    pub const CA_KEY_NAME: &str = "test-ca-key";
    pub const CA_KEY_PASSWORD: &str = "🦀🦀🦀🦀";

    pub const CODESIGNING_KEY_NAME: &str = "test-codesigning-key";
    pub const CODESIGNING_KEY_PASSWORD: &str = "🪶🪶🪶🪶";

    pub const EC_KEY_NAME: &str = "test-ec-key";
    pub const EC_KEY_PASSWORD: &str = "🌙🌙🌙🌙";

    pub const HSM_PIN: &str = "very-secret-pin";
    pub const HSM_ACCESS_PASSWORD: &str = "🦆🦆🦆🦆🪿";

    pub const HSM_EC_KEY_NAME: &str = "test-hsm-ec-key";
    pub const HSM_RSA_KEY_NAME: &str = "test-hsm-rsa-key";

    /// ID used for the PKCS#11 binding key
    pub const HSM_BINDING_KEY_ID: u8 = 99;
}

/// Builder for creating test instances with specific key configurations.
#[derive(Default)]
struct InstanceBuilder {
    creds: Option<Creds>,
    with_gpg_key: bool,
    with_ca_key: bool,
    with_codesigning_key: bool,
    with_ec_key: bool,
    with_hsm_ec_key: bool,
    with_hsm_rsa_key: bool,
    with_hsm: bool,
    with_pkcs11_binding: bool,
}

impl InstanceBuilder {
    fn new() -> Self {
        Self::default()
    }

    /// Use pre-generated credentials instead of creating new ones.
    fn with_creds(mut self, creds: Creds) -> Self {
        self.creds = Some(creds);
        self
    }

    fn with_gpg_key(mut self) -> Self {
        self.with_gpg_key = true;
        self
    }

    fn with_codesigning_key(mut self) -> Self {
        self.with_ca_key = true;
        self.with_codesigning_key = true;
        self
    }

    fn with_ec_key(mut self) -> Self {
        self.with_ca_key = true;
        self.with_ec_key = true;
        self
    }

    fn with_hsm_ec_key(mut self) -> Self {
        self.with_hsm = true;
        self.with_ca_key = true;
        self.with_hsm_ec_key = true;
        self
    }

    fn with_hsm_rsa_key(mut self) -> Self {
        self.with_hsm = true;
        self.with_ca_key = true;
        self.with_hsm_rsa_key = true;
        self
    }

    /// Configure the server to use a PKCS#11 binding key for key password encryption.
    fn with_pkcs11_binding(mut self) -> Self {
        self.with_hsm = true;
        self.with_pkcs11_binding = true;
        self
    }

    fn with_all_keys(mut self) -> Self {
        self.with_gpg_key = true;
        self.with_ca_key = true;
        self.with_codesigning_key = true;
        self.with_ec_key = true;
        self.with_hsm_rsa_key = true;
        self.with_hsm_ec_key = true;
        self
    }

    async fn setup_hsm(tempdir: &Path) -> anyhow::Result<(Pkcs11, Slot, AuthPin)> {
        let hsm_config_path = tempdir.join("kryoptic.toml");
        let hsm_db_path = tempdir.join("kryoptic.sql");
        std::fs::write(
            &hsm_config_path,
            format!(
                "[[slots]]\nslot = 1\ndbtype = \"sqlite\"\ndbargs = \"{}\"",
                hsm_db_path.display()
            ),
        )?;
        // SAFETY:
        // These tests are required to run with nextest, which starts a new process for each test.
        // Using set_var is only safe if no other code is interacting with the environment variables,
        // which should be true under nextest. Refer to
        // https://nexte.st/docs/configuration/env-vars/#altering-the-environment-within-tests to ensure
        // this remains the case with current versions of Rust.
        unsafe {
            std::env::set_var("KRYOPTIC_CONF", &hsm_config_path);
        };

        let pkcs11 = Pkcs11::new("/usr/lib64/pkcs11/libkryoptic_pkcs11.so")
            .context("Install the kryoptic PKCS#11 module")?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .context("Failed to initialized kryoptic PKCS#11 module")?;
        let slot = pkcs11
            .get_slots_with_token()?
            .pop()
            .expect("no slot available");
        let so_pin = AuthPin::new("12345678".into());
        let user_pin = AuthPin::new(keys::HSM_PIN.into());
        pkcs11
            .init_token(slot, &so_pin, "siguldry-test-token")
            .context("Failed to initialize token")?;
        pkcs11
            .open_rw_session(slot)
            .and_then(|session| {
                session.login(UserType::So, Some(&so_pin))?;
                session.init_pin(&user_pin)?;
                Ok(())
            })
            .context("Failed to initialize user pin")?;

        Ok((pkcs11, slot, user_pin))
    }

    async fn build(self) -> anyhow::Result<Instance> {
        // Unlike the server, which involves no DNS resolution from the client, the
        // bridge hostname needs to resolve and match the certificate it presents.
        let bridge_hostname = "localhost";
        let server_hostname = "siguldry-server";
        let client_name = "siguldry-client";
        let tempdir = tempfile::TempDir::new()?;
        let pkcs11 = if self.with_hsm {
            Some(Self::setup_hsm(tempdir.path()).await?)
        } else {
            None
        };
        let pkcs11_bindings = if self.with_pkcs11_binding {
            let (pkcs11, slot, user_pin) = pkcs11
                .as_ref()
                .expect("HSM must be set up for PKCS#11 binding");
            let binding = Self::create_binding_key(pkcs11, *slot, user_pin, tempdir.path()).await?;
            vec![binding]
        } else {
            vec![]
        };

        let creds = if let Some(creds) = self.creds {
            creds
        } else {
            create_credentials(
                tempdir.path(),
                bridge_hostname,
                server_hostname,
                client_name,
            )
            .await?
        };

        let bridge_config = bridge::Config {
            server_listening_address: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            client_listening_address: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            credentials: creds.bridge.clone(),
        };
        let bridge_config_file = tempdir.path().join("bridge.toml");
        std::fs::write(&bridge_config_file, toml::to_string_pretty(&bridge_config)?)?;
        let bridge = bridge::listen(bridge_config)
            .instrument(tracing::info_span!("bridge"))
            .await?;

        let server_config = server::Config {
            state_directory: tempdir.path().into(),
            bridge_hostname: bridge_hostname.to_string(),
            bridge_port: bridge.server_port(),
            credentials: creds.server.clone(),
            signer_executable: Some(
                assert_cmd::cargo::cargo_bin!("siguldry-signer")
                    .canonicalize()
                    .expect("siguldry-signer binary should exist"),
            ),
            user_password_length: NonZeroU16::new(keys::GPG_KEY_PASSWORD.len() as u16)
                .expect("it's three geese"),
            pkcs11_bindings,
            connection_pool_size: 1,
            ..Default::default()
        };
        let server_config_file = tempdir.path().join("server.toml");
        std::fs::write(&server_config_file, toml::to_string_pretty(&server_config)?)?;

        Self::run_server_command(&server_config_file, &["manage", "migrate"], None)?;
        Self::run_server_command(
            &server_config_file,
            &["manage", "users", "create", "siguldry-client"],
            None,
        )?;

        if self.with_gpg_key {
            Self::create_gpg_key(&server_config_file)?;
        }

        if self.with_ca_key {
            Self::create_ca_key(self.with_pkcs11_binding, &server_config_file)?;
        }

        if let Some((pkcs11, slot, user_pin)) = pkcs11 {
            if self.with_hsm_rsa_key {
                Self::create_hsm_rsa_key(&pkcs11, slot, &user_pin)?;
            }
            if self.with_hsm_ec_key {
                Self::create_hsm_ec_key(&pkcs11, slot, &user_pin)?;
            }

            Self::run_server_command(
                &server_config_file,
                &[
                    "manage",
                    "pkcs11",
                    "register",
                    "--module",
                    "/usr/lib64/pkcs11/libkryoptic_pkcs11.so",
                    "siguldry-client",
                ],
                Some(&format!(
                    "{}\n{}\n",
                    keys::HSM_PIN,
                    keys::HSM_ACCESS_PASSWORD
                )),
            )?;
        }

        if self.with_codesigning_key {
            Self::create_codesigning_key(&server_config_file)?;
        }

        if self.with_ec_key {
            Self::create_ec_key(&server_config_file)?;
        }

        let server = server::service::Server::new(server_config).await?;
        let server = server.run();

        let client_config = client::Config {
            server_hostname: server_hostname.to_string(),
            bridge_hostname: bridge_hostname.to_string(),
            bridge_port: bridge.client_port(),
            credentials: creds.client.clone(),
            ..Default::default()
        };
        let client_config_file = tempdir.path().join("client.toml");
        std::fs::write(&client_config_file, toml::to_string_pretty(&client_config)?)?;
        let client = client::Client::new(client_config)?;

        Ok(Instance {
            server,
            bridge,
            client,
            creds,
            state_dir: tempdir,
        })
    }

    /// Run a siguldry-server command with optional stdin input.
    fn run_server_command(
        config_file: &Path,
        args: &[&str],
        stdin_input: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut command = std::process::Command::new(cargo::cargo_bin!("siguldry-server"));
        command
            .env("SIGULDRY_SERVER_CONFIG", config_file)
            .args(args);

        if let Some(input) = stdin_input {
            command.stdin(Stdio::piped());
            let mut child = command.spawn()?;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(input.as_bytes())?;
            drop(stdin);
            let result = child.wait_with_output()?;
            if !result.status.success() {
                bail!("Command failed: {:?}", args);
            }
        } else {
            let result = command.output()?;
            if !result.status.success() {
                bail!("Command failed: {:?}", args);
            }
        }
        Ok(())
    }

    fn create_gpg_key(server_config_file: &Path) -> anyhow::Result<()> {
        Self::run_server_command(
            server_config_file,
            &[
                "manage",
                "gpg",
                "create",
                "siguldry-client",
                keys::GPG_KEY_NAME,
                keys::GPG_KEY_EMAIL,
            ],
            Some(&format!("{}\n", keys::GPG_KEY_PASSWORD)),
        )
    }

    fn create_hsm_rsa_key(pkcs11: &Pkcs11, slot: Slot, user_pin: &AuthPin) -> anyhow::Result<()> {
        let id = Attribute::Id(vec![1]);
        let label = Attribute::Label(keys::HSM_RSA_KEY_NAME.as_bytes().to_vec());
        let _ = pkcs11.open_rw_session(slot).and_then(|session| {
            session.login(UserType::User, Some(user_pin))?;
            session.generate_key_pair(
                &Mechanism::RsaPkcsKeyPairGen,
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Verify(true),
                    Attribute::Encrypt(true),
                    Attribute::ModulusBits(4096.into()),
                ],
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Sign(true),
                    Attribute::Decrypt(true),
                ],
            )
        })?;

        Ok(())
    }

    /// Create an RSA key in the HSM for PKCS#11 binding
    async fn create_binding_key(
        pkcs11: &Pkcs11,
        slot: Slot,
        user_pin: &AuthPin,
        tempdir: &Path,
    ) -> anyhow::Result<Pkcs11Binding> {
        let id = Attribute::Id(vec![keys::HSM_BINDING_KEY_ID]);
        let label = Attribute::Label(b"siguldry-binding-key".to_vec());
        pkcs11.open_rw_session(slot).and_then(|session| {
            session.login(UserType::User, Some(user_pin))?;
            session.generate_key_pair(
                &Mechanism::RsaPkcsKeyPairGen,
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Verify(true),
                    Attribute::Encrypt(true),
                    Attribute::ModulusBits(2048.into()),
                ],
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Sign(true),
                    Attribute::Decrypt(true),
                ],
            )
        })?;

        let key_uri = format!(
            "pkcs11:token=siguldry-test-token;id=%{:02x};type=private",
            keys::HSM_BINDING_KEY_ID
        );
        let module_path = "/usr/lib64/pkcs11/libkryoptic_pkcs11.so";
        let cert_file = tempdir.join("binding-cert.pem");
        let hsm_config_path = tempdir.join("kryoptic.toml");
        let mut command = Command::new("openssl");
        let output = command
            .env("KRYOPTIC_CONF", &hsm_config_path)
            .env("PKCS11_PROVIDER_MODULE", module_path)
            .args([
                "req",
                "-x509",
                "-provider",
                "pkcs11",
                "-subj",
                "/CN=siguldry-binding-key",
            ])
            .arg("-passin")
            .arg(format!("pass:{}", keys::HSM_PIN))
            .arg("-key")
            .arg(&key_uri)
            .arg("-out")
            .arg(&cert_file)
            .output()
            .await?;
        if !output.status.success() {
            panic!(
                "Failed to create x509 certificate:  {:?}",
                String::from_utf8_lossy(&output.stderr)
            )
        }
        let mut command = Command::new("pkcs11-tool");
        let output = command
            .env("KRYOPTIC_CONF", &hsm_config_path)
            .arg(format!("--module={}", module_path))
            .args([
                "--login",
                "--type=cert",
                "--label=self-signed-cert",
                "--id=1",
            ])
            .arg(format!("--pin={}", keys::HSM_PIN))
            .arg(format!("--write-object={}", cert_file.display()))
            .output()
            .await?;
        if !output.status.success() {
            panic!(
                "Failed to add cert to PKCS 11 token: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(Pkcs11Binding {
            certificate: cert_file,
            private_key: Some(key_uri),
            pin: Some(Password::from(keys::HSM_PIN)),
        })
    }

    fn create_hsm_ec_key(pkcs11: &Pkcs11, slot: Slot, user_pin: &AuthPin) -> anyhow::Result<()> {
        let id = Attribute::Id(vec![42]);
        let label = Attribute::Label(keys::HSM_EC_KEY_NAME.as_bytes().to_vec());
        let _ = pkcs11.open_rw_session(slot).and_then(|session| {
            session.login(UserType::User, Some(user_pin))?;

            // Annoyingly it doesn't seem possible to convert a named curve Nid to ASN.1 in
            // OpenSSL, so we manually create it from the OID for NIST P-256.
            let p256_oid = asn1::oid!(1, 2, 840, 10045, 3, 1, 7);
            let p256_oid_bytes = asn1::write_single(&p256_oid).unwrap();
            session.generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::EcParams(p256_oid_bytes),
                    Attribute::Verify(true),
                    Attribute::Encrypt(true),
                ],
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Sign(true),
                    Attribute::Decrypt(true),
                ],
            )
        })?;

        Ok(())
    }

    fn create_ca_key(with_pkcs11_binding: bool, server_config_file: &Path) -> anyhow::Result<()> {
        Self::run_server_command(
            server_config_file,
            &[
                "manage",
                "key",
                "create",
                "siguldry-client",
                keys::CA_KEY_NAME,
            ],
            Some(&format!("{}\n", keys::CA_KEY_PASSWORD)),
        )?;

        let input = if with_pkcs11_binding {
            format!("{}\n{}\n", keys::HSM_PIN, keys::CA_KEY_PASSWORD)
        } else {
            format!("{}\n", keys::CA_KEY_PASSWORD)
        };
        Self::run_server_command(
            server_config_file,
            &[
                "manage",
                "key",
                "x509",
                "--user-name",
                "siguldry-client",
                "--key-name",
                keys::CA_KEY_NAME,
                "--common-name",
                keys::CA_KEY_NAME,
                "--validity-days",
                "30",
                "certificate-authority",
            ],
            Some(&input),
        )
    }

    fn create_codesigning_key(server_config_file: &Path) -> anyhow::Result<()> {
        Self::run_server_command(
            server_config_file,
            &[
                "manage",
                "key",
                "create",
                "siguldry-client",
                keys::CODESIGNING_KEY_NAME,
            ],
            Some(&format!("{}\n", keys::CODESIGNING_KEY_PASSWORD)),
        )?;

        Self::run_server_command(
            server_config_file,
            &[
                "manage",
                "key",
                "x509",
                "--user-name",
                "siguldry-client",
                "--key-name",
                keys::CODESIGNING_KEY_NAME,
                "--common-name",
                keys::CODESIGNING_KEY_NAME,
                "--validity-days",
                "30",
                "--certificate-authority",
                keys::CA_KEY_NAME,
                "code-signing",
            ],
            Some(&format!("{}\n", keys::CA_KEY_PASSWORD)),
        )
    }

    fn create_ec_key(server_config_file: &Path) -> anyhow::Result<()> {
        Self::run_server_command(
            server_config_file,
            &[
                "manage",
                "key",
                "create",
                "--algorithm=p256",
                "siguldry-client",
                keys::EC_KEY_NAME,
            ],
            Some(&format!("{}\n", keys::EC_KEY_PASSWORD)),
        )?;

        Self::run_server_command(
            server_config_file,
            &[
                "manage",
                "key",
                "x509",
                "--user-name",
                "siguldry-client",
                "--key-name",
                keys::EC_KEY_NAME,
                "--common-name",
                keys::EC_KEY_NAME,
                "--validity-days",
                "30",
                "--certificate-authority",
                keys::CA_KEY_NAME,
                "code-signing",
            ],
            Some(&format!("{}\n", keys::CA_KEY_PASSWORD)),
        )
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn basic_bridge_config() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().build().await?;

    for _ in 0..5 {
        let username = instance.client.who_am_i().await.unwrap();
        assert_eq!(username, "siguldry-client");
    }

    instance.halt().await?;
    Ok(())
}

// If the bridge presents a certificate signed by a different CA, the client should reject it.
#[tokio::test]
#[tracing_test::traced_test]
async fn client_rejects_bridge_cert() -> anyhow::Result<()> {
    let bridge_hostname = "localhost";
    let server_hostname = "siguldry-server";
    let client_name = "siguldry-client";
    let instance = InstanceBuilder::new().build().await?;

    let tempdir = tempfile::TempDir::new()?;
    let creds = create_credentials(
        tempdir.path(),
        bridge_hostname,
        server_hostname,
        client_name,
    )
    .await?;
    let client_config = client::Config {
        server_hostname: server_hostname.to_string(),
        bridge_hostname: bridge_hostname.to_string(),
        bridge_port: instance.bridge.client_port(),
        credentials: creds.client,
        ..Default::default()
    };
    let client = client::Client::new(client_config)?;

    let username = client.who_am_i().await;
    match username {
        Ok(_) => panic!("The request should not succeed"),
        Err(ClientError::Connection(ConnectionError::Ssl(error))) => {
            let error = error.ssl_error().unwrap().errors().first().unwrap();
            assert_eq!(error.reason_code(), 134);
            assert_eq!(error.reason(), Some("certificate verify failed"));
            assert!(logs_contain("certificate verify failed"));
        }
        Err(other) => panic!("Incorrect error variant returned: {other:?}"),
    }

    drop(client);
    instance.halt().await?;
    Ok(())
}

// If the client presents a certificate signed by a different CA, the bridge should reject it.
#[tokio::test]
#[tracing_test::traced_test]
async fn bridge_rejects_client_cert() -> anyhow::Result<()> {
    let bridge_hostname = "localhost";
    let server_hostname = "siguldry-server";
    let client_name = "siguldry-client";
    let instance = InstanceBuilder::new().build().await?;

    let tempdir = tempfile::TempDir::new()?;
    let mut creds = create_credentials(
        tempdir.path(),
        bridge_hostname,
        server_hostname,
        client_name,
    )
    .await?;
    creds.client.ca_certificate = instance.creds.client.ca_certificate.clone();
    let client_config = client::Config {
        server_hostname: server_hostname.to_string(),
        bridge_hostname: bridge_hostname.to_string(),
        bridge_port: instance.bridge.client_port(),
        credentials: creds.client,
        ..Default::default()
    };
    let client = client::Client::new(client_config)?;

    let username = client.who_am_i().await;
    match username {
        Ok(_) => panic!("The request should not succeed"),
        Err(ClientError::Connection(ConnectionError::Ssl(error))) => {
            let error = error.ssl_error().unwrap().errors().first().unwrap();
            assert_eq!(error.reason_code(), 1048);
            assert_eq!(error.reason(), Some("tlsv1 alert unknown ca"));
            assert!(logs_contain("Failed to accept new client connection"));
            assert!(logs_contain("client_certificate:certificate verify failed"));
        }
        Err(other) => panic!("Incorrect error variant returned: {other:?}"),
    }

    drop(client);
    instance.halt().await?;
    Ok(())
}

// If the client presents a certificate with an empty common name, the bridge should reject it.
#[tokio::test]
#[tracing_test::traced_test]
async fn bridge_rejects_client_cert_empty_common_name() -> anyhow::Result<()> {
    let tempdir = tempfile::TempDir::new()?;
    let creds = create_credentials(tempdir.path(), "localhost", "siguldry-server", "").await?;
    let instance = InstanceBuilder::new().with_creds(creds).build().await?;

    let username = instance.client.who_am_i().await;
    match username {
        Ok(name) => panic!("The request should not succeed, but server responded with {name}"),
        Err(ClientError::Connection(ConnectionError::Protocol(error))) => {
            assert_eq!(error, ProtocolError::MissingCommonName);
        }
        Err(other) => panic!("Incorrect error variant returned: {other:?}"),
    }

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn unlock_gpg_key() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_gpg_key().build().await?;

    instance
        .client
        .unlock(
            keys::GPG_KEY_NAME.to_string(),
            keys::GPG_KEY_PASSWORD.to_string(),
        )
        .await?;

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn wrong_gpg_password() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_gpg_key().build().await?;

    let result = instance
        .client
        .unlock(keys::GPG_KEY_NAME.to_string(), "🪿🪿🦆".to_string())
        .await;
    // TODO: split out server-side errors from client request errors
    assert!(result.is_err_and(|err| matches!(err, ClientError::Server(ServerError::Internal))));

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn unlock_key_doesnt_exist() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().build().await?;

    let result = instance
        .client
        .unlock(
            "not-a-real-key".to_string(),
            "a boring password".to_string(),
        )
        .await;
    // TODO: split out server-side errors from client request errors
    assert!(result.is_err_and(|err| matches!(err, ClientError::Server(ServerError::Internal))));

    instance.halt().await?;
    Ok(())
}

/// List keys available
#[tokio::test]
#[tracing_test::traced_test]
async fn list_keys() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_all_keys().build().await?;

    let keys = instance.client.list_keys().await?;
    // GPG key + CA key + codesigning key + EC key
    assert_eq!(4, keys.len());

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn gpg_sign_inline() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_gpg_key().build().await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();

    instance
        .client
        .unlock(
            keys::GPG_KEY_NAME.to_string(),
            keys::GPG_KEY_PASSWORD.to_string(),
        )
        .await?;
    let mut key = instance
        .client
        .get_key(keys::GPG_KEY_NAME.to_string())
        .await?;
    assert_eq!(1, key.certificates.len());
    let certificate = key.certificates.pop().unwrap();
    let signature = instance
        .client
        .gpg_sign(
            keys::GPG_KEY_NAME.to_string(),
            GpgSignatureType::Inline,
            bytes::Bytes::from(data),
        )
        .await?;

    match certificate {
        siguldry::protocol::Certificate::Gpg {
            version: _version,
            certificate,
            fingerprint,
        } => {
            let keyring_path = instance.state_dir.path().join("gpg_sign_keyring.asc");
            std::fs::write(&keyring_path, certificate)?;
            let sig_path = instance.state_dir.path().join("gpg_sign_data.sig");
            std::fs::write(&sig_path, &signature)?;
            let mut command = tokio::process::Command::new("sq");
            let output = command
                .arg("verify")
                .arg(format!("--trust-root={}", &fingerprint))
                .arg(format!("--keyring={}", keyring_path.display()))
                .arg("--message")
                .arg(sig_path)
                .output()
                .await?;
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout)?;
            let stderr = String::from_utf8(output.stderr)?;
            assert_eq!(stdout, "🦡🦡🦡🦡🍄🍄");
            assert!(stderr.contains(&format!(
                "Authenticated signature made by {} ({} <{}>)",
                fingerprint,
                keys::GPG_KEY_NAME,
                keys::GPG_KEY_EMAIL
            )));
        }
        _ => panic!("unexpected key type"),
    }

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn gpg_sign_detached() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_gpg_key().build().await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();

    instance
        .client
        .unlock(
            keys::GPG_KEY_NAME.to_string(),
            keys::GPG_KEY_PASSWORD.to_string(),
        )
        .await?;
    let mut key = instance
        .client
        .get_key(keys::GPG_KEY_NAME.to_string())
        .await?;
    assert_eq!(1, key.certificates.len());
    let certificate = key.certificates.pop().unwrap();
    let signature = instance
        .client
        .gpg_sign(
            keys::GPG_KEY_NAME.to_string(),
            GpgSignatureType::Detached,
            bytes::Bytes::from(data),
        )
        .await?;

    match certificate {
        siguldry::protocol::Certificate::Gpg {
            version: _version,
            certificate,
            fingerprint,
        } => {
            let keyring_path = instance.state_dir.path().join("gpg_sign_keyring.asc");
            std::fs::write(&keyring_path, certificate)?;

            let data_path = instance.state_dir.path().join("gpg_sign_data");
            std::fs::write(&data_path, data)?;

            let sig_path = instance.state_dir.path().join("gpg_sign_data.sig");
            std::fs::write(&sig_path, &signature)?;
            let mut command = tokio::process::Command::new("sq");
            let output = command
                .arg("verify")
                .arg(format!("--trust-root={}", &fingerprint))
                .arg(format!("--keyring={}", keyring_path.display()))
                .arg(format!("--signature-file={}", sig_path.display()))
                .arg(data_path)
                .output()
                .await?;
            let stderr = String::from_utf8(output.stderr)?;
            assert!(output.status.success());
            assert!(stderr.contains(&format!(
                "Authenticated signature made by {} ({} <{}>)",
                fingerprint,
                keys::GPG_KEY_NAME,
                keys::GPG_KEY_EMAIL
            )));
        }
        _ => panic!("unexpected key type"),
    }

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn gpg_sign_cleartext() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_gpg_key().build().await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();

    instance
        .client
        .unlock(
            keys::GPG_KEY_NAME.to_string(),
            keys::GPG_KEY_PASSWORD.to_string(),
        )
        .await?;
    let mut key = instance
        .client
        .get_key(keys::GPG_KEY_NAME.to_string())
        .await?;
    assert_eq!(1, key.certificates.len());
    let key = key.certificates.pop().unwrap();

    let signature = instance
        .client
        .gpg_sign(
            keys::GPG_KEY_NAME.to_string(),
            GpgSignatureType::Cleartext,
            bytes::Bytes::from(data),
        )
        .await?;
    let signature_text = String::from_utf8(signature.to_vec())?;
    assert!(signature_text.contains(
        "-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

🦡🦡🦡🦡🍄🍄
-----BEGIN PGP SIGNATURE-----"
    ));

    match key {
        siguldry::protocol::Certificate::Gpg {
            version: _version,
            certificate,
            fingerprint,
        } => {
            let keyring_path = instance.state_dir.path().join("gpg_sign_keyring.asc");
            std::fs::write(&keyring_path, certificate)?;
            let sig_path = instance.state_dir.path().join("gpg_sign_data.sig");
            std::fs::write(&sig_path, &signature)?;
            let mut command = tokio::process::Command::new("sq");
            let output = command
                .arg("verify")
                .arg(format!("--trust-root={}", &fingerprint))
                .arg(format!("--keyring={}", keyring_path.display()))
                .arg("--message")
                .arg(sig_path)
                .output()
                .await?;
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout)?;
            let stderr = String::from_utf8(output.stderr)?;
            assert_eq!(stdout, "🦡🦡🦡🦡🍄🍄");
            assert!(stderr.contains(&format!(
                "Authenticated signature made by {} ({} <{}>)",
                fingerprint,
                keys::GPG_KEY_NAME,
                keys::GPG_KEY_EMAIL
            )));
        }
        _ => panic!("unexpected key type"),
    }

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn check_x509_certs() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .build()
        .await?;

    let mut ca_key = instance
        .client
        .get_key(keys::CA_KEY_NAME.to_string())
        .await?;
    let mut codesigning_key = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;
    match (
        ca_key.certificates.pop().unwrap(),
        codesigning_key.certificates.pop().unwrap(),
    ) {
        (
            siguldry::protocol::Certificate::X509 {
                certificate: ca_cert,
            },
            siguldry::protocol::Certificate::X509 {
                certificate: codesigning_cert,
            },
        ) => {
            let ca_path = instance.state_dir.path().join("ca.pem");
            std::fs::write(&ca_path, &ca_cert)?;
            let codesigning_path = instance.state_dir.path().join("codesigning.pem");
            std::fs::write(&codesigning_path, &codesigning_cert)?;
            // The CA should be self-signed
            let mut command = tokio::process::Command::new("openssl");
            let output = command
                .arg("verify")
                .arg("-CAfile")
                .arg(&ca_path)
                .arg(&ca_path)
                .output()
                .await?;
            assert!(output.status.success());

            // The CA has signed the codesigning certificate
            let mut command = tokio::process::Command::new("openssl");
            let output = command
                .arg("verify")
                .arg("-CAfile")
                .arg(&ca_path)
                .arg(&codesigning_path)
                .output()
                .await?;
            assert!(output.status.success());

            // And the CA isn't signed by codesigning
            let mut invalid_verify = tokio::process::Command::new("openssl");
            let output = invalid_verify
                .arg("verify")
                .arg("-CAfile")
                .arg(&codesigning_path)
                .arg(&ca_path)
                .output()
                .await?;
            assert!(!output.status.success());
        }
        _ => panic!("unexpected key type"),
    }

    instance.halt().await?;
    Ok(())
}

/// Get a signature that digests the data prior to signing.
#[tokio::test]
#[tracing_test::traced_test]
async fn digest_signature() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();

    instance
        .client
        .unlock(
            keys::CODESIGNING_KEY_NAME.to_string(),
            keys::CODESIGNING_KEY_PASSWORD.to_string(),
        )
        .await?;
    let key = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;

    let signature = instance
        .client
        .sign(
            keys::CODESIGNING_KEY_NAME.to_string(),
            DigestAlgorithm::Sha256,
            bytes::Bytes::from(data),
        )
        .await?;

    let pubkey_path = instance.state_dir.path().join("codesigning-pubkey.pem");
    std::fs::write(&pubkey_path, &key.public_key)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &signature)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-verify")
        .arg(pubkey_path)
        .arg("-signature")
        .arg(sig_path)
        .arg(data_path)
        .output()
        .await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!("Verified OK\n", stdout);

    instance.halt().await?;
    Ok(())
}

/// Get an EC signature on pre-hashed data.
#[tokio::test]
#[tracing_test::traced_test]
async fn ec_prehashed_signature() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_ec_key().build().await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let data_sum = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?.to_vec();
    let data_hex = hex::encode(&data_sum);

    instance
        .client
        .unlock(
            keys::EC_KEY_NAME.to_string(),
            keys::EC_KEY_PASSWORD.to_string(),
        )
        .await?;
    let key = instance
        .client
        .get_key(keys::EC_KEY_NAME.to_string())
        .await?;
    let signature = instance
        .client
        .sign_prehashed(
            keys::EC_KEY_NAME.to_string(),
            vec![(DigestAlgorithm::Sha256, data_hex)],
        )
        .await?
        .pop()
        .unwrap();

    let pubkey_path = instance.state_dir.path().join("ec-pubkey.pem");
    std::fs::write(&pubkey_path, &key.public_key)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &signature.signature)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    // Check the key is the expected format
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("ec")
        .arg("-pubin")
        .arg("-in")
        .arg(&pubkey_path)
        .arg("-text")
        .arg("-noout")
        .output()
        .await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("NIST CURVE: P-256"));

    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-verify")
        .arg(pubkey_path)
        .arg("-signature")
        .arg(sig_path)
        .arg(data_path)
        .output()
        .await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!("Verified OK\n", stdout);

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn hsm_ec_prehashed_signature() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_hsm_ec_key().build().await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let data_sum = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?.to_vec();
    let data_hex = hex::encode(&data_sum);

    instance
        .client
        .unlock(
            keys::HSM_EC_KEY_NAME.to_string(),
            keys::HSM_ACCESS_PASSWORD.to_string(),
        )
        .await?;
    let key = instance
        .client
        .get_key(keys::HSM_EC_KEY_NAME.to_string())
        .await?;
    let signature = instance
        .client
        .sign_prehashed(
            keys::HSM_EC_KEY_NAME.to_string(),
            vec![(DigestAlgorithm::Sha256, data_hex)],
        )
        .await?
        .pop()
        .unwrap();

    let pubkey_path = instance.state_dir.path().join("ec-pubkey.pem");
    std::fs::write(&pubkey_path, &key.public_key)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &signature.signature)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    // Check the key is the expected format
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("ec")
        .arg("-pubin")
        .arg("-in")
        .arg(&pubkey_path)
        .arg("-text")
        .arg("-noout")
        .output()
        .await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("NIST CURVE: P-256"));

    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-verify")
        .arg(pubkey_path)
        .arg("-signature")
        .arg(sig_path)
        .arg(data_path)
        .output()
        .await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!("Verified OK\n", stdout);

    instance.halt().await?;
    Ok(())
}

/// Get a signature on pre-hashed data.
#[tokio::test]
#[tracing_test::traced_test]
async fn prehashed_signature() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let data_sum = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?.to_vec();
    let data_hex = hex::encode(&data_sum);

    instance
        .client
        .unlock(
            keys::CODESIGNING_KEY_NAME.to_string(),
            keys::CODESIGNING_KEY_PASSWORD.to_string(),
        )
        .await?;
    let key = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;
    let signature = instance
        .client
        .sign_prehashed(
            keys::CODESIGNING_KEY_NAME.to_string(),
            vec![(DigestAlgorithm::Sha256, data_hex)],
        )
        .await?
        .pop()
        .unwrap();

    let pubkey_path = instance.state_dir.path().join("codesigning-pubkey.pem");
    std::fs::write(&pubkey_path, &key.public_key)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &signature.signature)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-verify")
        .arg(pubkey_path)
        .arg("-signature")
        .arg(sig_path)
        .arg(data_path)
        .output()
        .await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!("Verified OK\n", stdout);

    instance.halt().await?;
    Ok(())
}

/// Get a signature on pre-hashed data.
#[tokio::test]
#[tracing_test::traced_test]
async fn hsm_rsa_prehashed_signature() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_hsm_rsa_key().build().await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let data_sum = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?.to_vec();
    let data_hex = hex::encode(&data_sum);

    instance
        .client
        .unlock(
            keys::HSM_RSA_KEY_NAME.to_string(),
            keys::HSM_ACCESS_PASSWORD.to_string(),
        )
        .await?;
    let key = instance
        .client
        .get_key(keys::HSM_RSA_KEY_NAME.to_string())
        .await?;
    let signature = instance
        .client
        .sign_prehashed(
            keys::HSM_RSA_KEY_NAME.to_string(),
            vec![(DigestAlgorithm::Sha256, data_hex)],
        )
        .await?
        .pop()
        .unwrap();

    let pubkey_path = instance.state_dir.path().join("hsm-rsa-pubkey.pem");
    std::fs::write(&pubkey_path, &key.public_key)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &signature.signature)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-verify")
        .arg(pubkey_path)
        .arg("-signature")
        .arg(sig_path)
        .arg(data_path)
        .output()
        .await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!("Verified OK\n", stdout);

    instance.halt().await?;
    Ok(())
}

/// Get a digest signature with an RSA key whose password is bound by a PKCS#11 token.
#[tokio::test]
#[tracing_test::traced_test]
async fn hsm_rsa_prehashed_signature_with_pkcs11_binding() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_hsm_rsa_key()
        .with_pkcs11_binding()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();

    instance
        .client
        .unlock(
            keys::HSM_RSA_KEY_NAME.to_string(),
            keys::HSM_ACCESS_PASSWORD.to_string(),
        )
        .await?;
    let key = instance
        .client
        .get_key(keys::HSM_RSA_KEY_NAME.to_string())
        .await?;

    let signature = instance
        .client
        .sign(
            keys::HSM_RSA_KEY_NAME.to_string(),
            DigestAlgorithm::Sha256,
            bytes::Bytes::from(data),
        )
        .await?;

    let pubkey_path = instance.state_dir.path().join("hsm-rsa-pubkey.pem");
    std::fs::write(&pubkey_path, &key.public_key)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &signature)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-verify")
        .arg(pubkey_path)
        .arg("-signature")
        .arg(sig_path)
        .arg(data_path)
        .output()
        .await?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!("Verified OK\n", stdout);

    instance.halt().await?;
    Ok(())
}
