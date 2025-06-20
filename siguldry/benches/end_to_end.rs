// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Performance benchmarks for end-to-end scenarios.

#![cfg(feature = "server")]

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::bail;
use assert_cmd::cargo::CommandCargoExt;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use siguldry::{bridge, client, config::Credentials, server};
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
            private_key: creds_directory.join("sigul.server.private_key.pem"),
            certificate: creds_directory.join("sigul.server.certificate.pem"),
            ca_certificate: creds_directory.join("sigul.ca.certificate.pem"),
        },
        bridge: Credentials {
            private_key: creds_directory.join("sigul.bridge.private_key.pem"),
            certificate: creds_directory.join("sigul.bridge.certificate.pem"),
            ca_certificate: creds_directory.join("sigul.ca.certificate.pem"),
        },
        client: Credentials {
            private_key: creds_directory.join("sigul.client.private_key.pem"),
            certificate: creds_directory.join("sigul.client.certificate.pem"),
            ca_certificate: creds_directory.join("sigul.ca.certificate.pem"),
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

async fn create_instance(creds: Option<Creds>) -> anyhow::Result<Instance> {
    // Unlike the server, which involves no DNS resolution from the client, the
    // bridge hostname needs to resolve and match the certificate it presents.
    let bridge_hostname = "localhost";
    let server_hostname = "sigul-server";
    let client_name = "sigul-client";
    let tempdir = tempfile::TempDir::new()?;
    let creds = if let Some(creds) = creds {
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
    let bridge = bridge::listen(bridge_config)
        .instrument(tracing::info_span!("bridge"))
        .await?;

    let server_config = server::config::Config {
        state_directory: tempdir.path().into(),
        bridge_hostname: bridge_hostname.to_string(),
        bridge_port: bridge.server_port(),
        credentials: creds.server.clone(),
        connection_pool_size: 32,
    };
    let server_config_file = tempdir.path().join("server.toml");
    std::fs::write(&server_config_file, toml::to_string_pretty(&server_config)?)?;
    let mut migrate_command = std::process::Command::cargo_bin("siguldry-server")?;
    let result = migrate_command
        .env("SIGULDRY_SERVER_CONFIG", &server_config_file)
        .args(["manage", "migrate"])
        .output()?;
    if !result.status.success() {
        panic!("failed to create test database");
    }
    let mut create_user_command = std::process::Command::cargo_bin("siguldry-server")?;
    let result = create_user_command
        .env("SIGULDRY_SERVER_CONFIG", &server_config_file)
        .args(["manage", "users", "add", "sigul-client"])
        .output()?;
    if !result.status.success() {
        panic!("failed to create test user");
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
    let client = client::Client::new(client_config)?;

    Ok(Instance {
        server,
        bridge,
        client,
        creds,
        state_dir: tempdir,
    })
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
            let instance = create_instance(None).await?;
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
}

/// Benchmark the end-to-end connection speed with 32 concurrent connections.
fn concurrent_connection(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let instance = runtime
        .block_on(async {
            let instance = create_instance(None).await?;
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
            let instance = create_instance(None).await?;
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
}

fn bench_command_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("command_throughput");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let instance = runtime
        .block_on(async {
            let instance = create_instance(None).await?;
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
criterion_main!(base_benches, command_benches);
