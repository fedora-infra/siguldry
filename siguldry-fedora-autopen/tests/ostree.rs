// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Integration tests for OSTree signing.

use std::path::{Path, PathBuf};

use anyhow::Context;
use siguldry_test::{InstanceBuilder, keys};

fn autopen_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target/debug/siguldry-fedora-autopen")
}

async fn ostree(args: &[&str]) -> anyhow::Result<String> {
    let output = tokio::process::Command::new("ostree")
        .args(args)
        .output()
        .await
        .context("Failed to spawn ostree; is it installed?")?;
    if !output.status.success() {
        anyhow::bail!(
            "ostree {args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

async fn init_repo_with_commit(
    repo_dir: &Path,
    content_dir: &Path,
    branch: &str,
) -> anyhow::Result<String> {
    tokio::fs::create_dir_all(repo_dir).await?;
    tokio::fs::create_dir_all(content_dir).await?;
    tokio::fs::write(content_dir.join("hello.txt"), b"hello, ostree\n").await?;

    ostree(&[
        &format!("--repo={}", repo_dir.display()),
        "init",
        "--mode=archive",
    ])
    .await?;

    let commit = ostree(&[
        &format!("--repo={}", repo_dir.display()),
        "commit",
        &format!("--branch={branch}"),
        &format!("--tree=dir={}", content_dir.display()),
        "--subject=test",
    ])
    .await?;

    Ok(commit.trim().to_string())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn process_ostree_compose() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_pgp_key()
        .auto_unlock_keys()
        .with_client_proxy()
        .build()
        .await?;

    // Find the OpenPGP cert that was auto-created for the PGP key.
    let key = instance
        .client
        .get_key(keys::PGP_KEY_NAME.to_string())
        .await?;
    let cert = key
        .openpgp_certificates()
        .first()
        .cloned()
        .context("PGP key has no OpenPGP certificate")?;

    let state = instance.state_dir.path();
    let repo_dir = state.join("ostree-repo");
    let content_dir = state.join("ostree-content");
    let reference = "fedora/test/x86_64/iot";
    let commit = init_repo_with_commit(&repo_dir, &content_dir, reference).await?;

    let proxy_socket = instance.client_proxy_socket();
    let config_path = state.join("fedora-autopen.toml");
    let config = format!(
        r#"
[amqp]
amqp_url = "amqp://example.com/%2Fpublic_pubsub"
[amqp.tls]
ca_certificate = "/dev/null"
private_key = "/dev/null"
certificate = "/dev/null"
[[amqp.bindings]]
exchange = "amq.topic"
routing_keys = []

[siguldry]
client_proxy_socket = "{proxy_socket}"

[koji]
url = "https://example.com"
instance = "primary"
readonly = true
tags = []

[koji.auth]
authmethod = "kerberos"
principal = "nobody@EXAMPLE.COM"

[[ostree]]
reference = "{reference}"
directory = "{repo_dir}"
siguldry_key = "{key_name}"
siguldry_openpgp_cert = "{cert_name}"
"#,
        proxy_socket = proxy_socket.display(),
        repo_dir = repo_dir.display(),
        key_name = keys::PGP_KEY_NAME,
        cert_name = cert.name,
    );
    tokio::fs::write(&config_path, config).await?;

    let message_path = state.join("message.json");
    let message = serde_json::json!({
        "body": {
            "arch": "x86_64",
            "commitid": commit,
            "compose_date": "20260501",
            "compose_id": "Fedora-IoT-45-20260501.0",
            "compose_label": "RC-20260501.0",
            "compose_path": "/mnt/koji/compose/iot/Fedora-IoT-45-20260501.0",
            "compose_respin": 0,
            "compose_type": "production",
            "local_repo_path": "/mnt/koji/compose/iot/repo/",
            "location": "https://example.com/compose",
            "ref": reference,
            "release_is_layered": false,
            "release_name": "Fedora-IoT",
            "release_short": "Fedora-IoT",
            "release_type": "ga",
            "release_version": "45",
            "repo_path": "https://example.com/repo",
            "variant": "IoT",
        },
        "headers": {
            "fedora_messaging_schema": "base.message",
            "fedora_messaging_severity": 20,
            "priority": 10,
            "sent-at": "2026-05-01T00:00:00+00:00",
        },
        "id": "f4b148e2-f492-43c4-9dc0-24e903f003fa",
        "priority": 10,
        "queue": null,
        "topic": "org.fedoraproject.prod.pungi.compose.ostree",
    });
    tokio::fs::write(&message_path, serde_json::to_vec_pretty(&message)?).await?;

    let output = tokio::process::Command::new(autopen_binary())
        .env_clear()
        .arg("--config")
        .arg(&config_path)
        .arg("process")
        .arg(&message_path)
        .output()
        .await
        .context("Failed to spawn siguldry-fedora-autopen; run `cargo build -p siguldry-fedora-autopen` first")?;
    assert!(
        output.status.success(),
        "siguldry-fedora-autopen process exited with {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let refs = ostree(&[&format!("--repo={}", repo_dir.display()), "refs"]).await?;
    assert!(
        refs.lines().any(|line| line.trim() == reference),
        "expected ref {reference} in refs list, got {refs}"
    );
    let revision = ostree(&[
        &format!("--repo={}", repo_dir.display()),
        "rev-parse",
        reference,
    ])
    .await?;
    assert_eq!(
        revision.trim(),
        commit,
        "ref does not point to signed commit"
    );

    // The commit should have GPG signature metadata attached.
    let show = ostree(&[&format!("--repo={}", repo_dir.display()), "show", &commit]).await?;
    assert!(
        show.to_lowercase().contains("signature"),
        "expected signature:\n{show}"
    );

    instance.halt().await?;
    Ok(())
}
