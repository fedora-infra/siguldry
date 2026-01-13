// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Performance benchmarks for end-to-end scenarios.

#![cfg(feature = "server")]

use std::{
    io::Write,
    net::SocketAddr,
    num::NonZeroU16,
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, bail};
use assert_cmd::cargo;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::Attribute,
    session::UserType,
    slot::Slot,
    types::AuthPin,
};
use siguldry::{bridge, client, config::Credentials, protocol::GpgSignatureType, server};
use tokio::{process::Command, task::JoinSet};
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
}

/// Builder for creating test instances with specific key configurations.
#[derive(Default)]
struct InstanceBuilder {
    creds: Option<Creds>,
    with_gpg_key: bool,
    with_ca_key: bool,
    with_codesigning_key: bool,
    with_ec_key: bool,
    with_hsm: bool,
}

#[allow(dead_code)]
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

    fn with_all_keys(mut self) -> Self {
        self.with_gpg_key = true;
        self.with_ca_key = true;
        self.with_codesigning_key = true;
        self.with_ec_key = true;
        self
    }

    #[allow(dead_code)]
    fn with_hsm(mut self) -> Self {
        self.with_hsm = true;
        self.with_ca_key = true;
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
        let user_pin = AuthPin::new("654321".into());
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
            pkcs11_bindings: vec![],
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
            Self::create_ca_key(&server_config_file)?;
        }

        if let Some((pkcs11, slot, user_pin)) = pkcs11 {
            Self::create_hsm_rsa_key(pkcs11, slot, &user_pin).await?;
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

    async fn create_hsm_rsa_key(
        pkcs11: Pkcs11,
        slot: Slot,
        user_pin: &AuthPin,
    ) -> anyhow::Result<()> {
        let id = Attribute::Id(vec![1]);
        let _ = pkcs11.open_rw_session(slot).and_then(|session| {
            session.login(UserType::User, Some(user_pin))?;
            let pubkey_template = [
                Attribute::Token(true),
                Attribute::Private(false),
                id.clone(),
                Attribute::ModulusBits(2048.into()),
            ];
            let privkey_template = [Attribute::Token(true), id.clone()];
            session.generate_key_pair(
                &Mechanism::RsaPkcsKeyPairGen,
                &pubkey_template,
                &privkey_template,
            )
        })?;

        Ok(())
    }

    fn create_ca_key(server_config_file: &Path) -> anyhow::Result<()> {
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
            Some(&format!("{}\n", keys::CA_KEY_PASSWORD)),
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

/// Benchmark the end-to-end connection speed.
///
/// The "who_am_i" command performs a single database lookup for the user and is done for all
/// connections anyway. This benchmark gives a reasonable idea of the time it takes, given no
/// meaningful latency, to establish a connection. Subtract the "command_roundtrip" benchmark
/// to get the connection time minus the "who_am_i" command.
fn connection(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let instance = runtime
        .block_on(async {
            let instance = InstanceBuilder::new().build().await?;

            Ok::<_, anyhow::Error>(instance)
        })
        .unwrap();
    let config = instance.client.config();

    criterion.bench_function("connection", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let client = client::Client::new(config.clone()).unwrap();
                client.who_am_i().await.unwrap();
            });
        });
    });

    _ = runtime.block_on(instance.halt());
}

/// Benchmark the end-to-end connection speed with 32 concurrent connections.
fn concurrent_connection(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let instance = runtime
        .block_on(async {
            let instance = InstanceBuilder::new().build().await?;
            Ok::<_, anyhow::Error>(instance)
        })
        .unwrap();
    let config = instance.client.config();

    criterion.bench_function("concurrent_connection", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let mut clients = tokio::task::JoinSet::new();
                for _ in 0..32 {
                    let client = client::Client::new(config.clone()).unwrap();
                    clients.spawn(async move {
                        client.who_am_i().await.unwrap();
                    });
                }
                clients.join_all().await;
            });
        });
    });

    _ = runtime.block_on(instance.halt());
}

/// Benchmark the time to send a request and receive a response, ignoring complex server-side work.
///
/// This starts a single connection and then repeatedly runs the "who_am_i" command to determine the
/// serialized command throughput.
fn command_roundtrip(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let instance = runtime
        .block_on(async {
            let instance = InstanceBuilder::new().build().await?;
            Ok::<_, anyhow::Error>(instance)
        })
        .unwrap();

    criterion.bench_function("command_roundtrip", |b| {
        b.iter(|| {
            runtime.block_on(async {
                instance.client.who_am_i().await.unwrap();
            });
        });
    });

    _ = runtime.block_on(instance.halt());
}

fn bench_command_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("command_throughput");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let instance = runtime
        .block_on(async {
            let instance = InstanceBuilder::new().build().await?;
            Ok::<_, anyhow::Error>(instance)
        })
        .unwrap();

    for size in [64, 128, 512_usize].iter() {
        group.throughput(criterion::Throughput::Elements(*size as u64));

        group.bench_with_input(BenchmarkId::new("whoami", *size), size, |b, size| {
            b.iter(|| {
                runtime.block_on(async {
                    let mut joinset = JoinSet::new();
                    for _ in 0..*size {
                        let client = instance.client.clone();
                        joinset.spawn(async move { client.who_am_i().await });
                    }
                    _ = joinset
                        .join_all()
                        .await
                        .into_iter()
                        .collect::<Result<Vec<String>, _>>()
                        .unwrap();
                });
            });
        });
    }

    _ = runtime.block_on(instance.halt());
}

fn gpg_sign_detached(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let instance = runtime
        .block_on(async {
            let instance = InstanceBuilder::new().with_gpg_key().build().await?;
            instance
                .client
                .unlock("test-gpg-key".to_string(), "🪿🪿🪿".to_string())
                .await?;
            Ok::<_, anyhow::Error>(instance)
        })
        .unwrap();
    let mut payload = vec![0_u8; 1024 * 32];
    openssl::rand::rand_bytes(&mut payload).unwrap();

    criterion.bench_function("gpg_sign_detached_rsa4k_32kb", |b| {
        b.iter(|| {
            runtime.block_on(async {
                instance
                    .client
                    .gpg_sign(
                        "test-gpg-key".to_string(),
                        GpgSignatureType::Detached,
                        bytes::Bytes::from(payload.clone()),
                    )
                    .await
                    .unwrap()
            });
        });
    });

    _ = runtime.block_on(instance.halt());
}

fn gpg_sign_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("gpg_sign_throughput");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let instance = runtime
        .block_on(async {
            let instance = InstanceBuilder::new().with_gpg_key().build().await?;
            instance
                .client
                .unlock("test-gpg-key".to_string(), "🪿🪿🪿".to_string())
                .await?;
            Ok::<_, anyhow::Error>(instance)
        })
        .unwrap();
    let mut payload = vec![0_u8; 1024 * 32];
    openssl::rand::rand_bytes(&mut payload).unwrap();

    for batch_size in [128, 512_usize].iter() {
        group.throughput(criterion::Throughput::Elements(*batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("gpg_sign", *batch_size),
            batch_size,
            |b, size| {
                b.iter(|| {
                    runtime.block_on(async {
                        let mut joinset = JoinSet::new();
                        for _ in 0..*size {
                            let client = instance.client.clone();
                            let payload = payload.clone();
                            joinset.spawn(async move {
                                client
                                    .gpg_sign(
                                        "test-gpg-key".to_string(),
                                        GpgSignatureType::Detached,
                                        bytes::Bytes::from(payload),
                                    )
                                    .await
                                    .unwrap()
                            });
                        }
                        _ = joinset.join_all().await;
                    });
                });
            },
        );
    }

    _ = runtime.block_on(instance.halt());
}

criterion_group!(
    name = base_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(30));
    targets = connection, concurrent_connection, command_roundtrip
);
criterion_group!(
    name = command_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(30));
    targets = bench_command_throughput
);
criterion_group!(
    name = signing_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(30));
    targets = gpg_sign_detached, gpg_sign_throughput
);
criterion_main!(base_benches, command_benches, signing_benches);
