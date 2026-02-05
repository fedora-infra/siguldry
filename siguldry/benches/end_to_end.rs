// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Performance benchmarks for end-to-end scenarios.

#![cfg(feature = "server")]

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use siguldry::{client, protocol::GpgSignatureType};
use tokio::task::JoinSet;

use siguldry_test::InstanceBuilder;

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
