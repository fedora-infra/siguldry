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

use anyhow::bail;
use assert_cmd::cargo::CommandCargoExt;
use siguldry::{
    bridge, client,
    config::Credentials,
    error::{ClientError, ConnectionError, ProtocolError, ServerError},
    protocol::GpgSignatureType,
    server,
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

struct Instance {
    pub server: server::service::Listener,
    pub bridge: bridge::Listener,
    pub client: client::Client,
    pub creds: Creds,
    // Dropping TempDir cleans up the directory, but it needs to live to the end of the test.
    #[allow(dead_code)]
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

    let server_config = server::Config {
        state_directory: tempdir.path().into(),
        bridge_hostname: bridge_hostname.to_string(),
        bridge_port: bridge.server_port(),
        credentials: creds.server.clone(),
        user_password_length: NonZeroU16::new("🪿🪿🪿".len() as u16).expect("it's three geese"),
        pkcs11_bindings: vec![],
        connection_pool_size: 1,
        ..Default::default()
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
        .args(["manage", "users", "create", "sigul-client"])
        .output()?;
    if !result.status.success() {
        panic!("failed to create test user");
    }
    let mut create_gpg_key_command = std::process::Command::cargo_bin("siguldry-server")?;
    let mut child = create_gpg_key_command
        .env("SIGULDRY_SERVER_CONFIG", &server_config_file)
        .args([
            "manage",
            "gpg",
            "create",
            "sigul-client",
            "test-gpg-key",
            "admin@example.com",
        ])
        .stdin(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all("🪿🪿🪿\n".as_bytes())?;
    drop(stdin);
    let result = child.wait_with_output()?;
    if !result.status.success() {
        panic!("failed to create test key");
    }

    // Set up a CA
    let mut create_ca_key_command = std::process::Command::cargo_bin("siguldry-server")?;
    let mut child = create_ca_key_command
        .env("SIGULDRY_SERVER_CONFIG", &server_config_file)
        .args(["manage", "key", "create", "sigul-client", "test-ca-key"])
        .stdin(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all("🦀🦀🦀🦀\n".as_bytes())?;
    drop(stdin);
    let result = child.wait_with_output()?;
    if !result.status.success() {
        panic!("failed to create test key");
    }
    let mut sign_ca_key_command = std::process::Command::cargo_bin("siguldry-server")?;
    let mut child = sign_ca_key_command
        .env("SIGULDRY_SERVER_CONFIG", &server_config_file)
        .args([
            "manage",
            "key",
            "x509",
            "--user-name",
            "sigul-client",
            "--key-name",
            "test-ca-key",
            "--common-name",
            "test-ca-key",
            "--validity-days",
            "30",
            "certificate-authority",
        ])
        .stdin(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all("🦀🦀🦀🦀\n".as_bytes())?;
    drop(stdin);
    let result = child.wait_with_output()?;
    if !result.status.success() {
        panic!("failed to create test key");
    }

    // Create codesigning key
    let mut create_codesigning_key_command = std::process::Command::cargo_bin("siguldry-server")?;
    let mut child = create_codesigning_key_command
        .env("SIGULDRY_SERVER_CONFIG", &server_config_file)
        .args([
            "manage",
            "key",
            "create",
            "sigul-client",
            "test-codesigning-key",
        ])
        .stdin(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all("🪶🪶🪶🪶\n".as_bytes())?;
    drop(stdin);
    let result = child.wait_with_output()?;
    if !result.status.success() {
        panic!("failed to create test key");
    }
    let mut sign_codesigning_key_command = std::process::Command::cargo_bin("siguldry-server")?;
    let mut child = sign_codesigning_key_command
        .env("SIGULDRY_SERVER_CONFIG", &server_config_file)
        .args([
            "manage",
            "key",
            "x509",
            "--user-name",
            "sigul-client",
            "--key-name",
            "test-codesigning-key",
            "--common-name",
            "test-codesigning-key",
            "--validity-days",
            "30",
            "--certificate-authority",
            "test-ca-key",
            "code-signing",
        ])
        .stdin(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all("🦀🦀🦀🦀\n".as_bytes())?;
    drop(stdin);
    let result = child.wait_with_output()?;
    if !result.status.success() {
        panic!("failed to create test key");
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

#[tokio::test]
#[tracing_test::traced_test]
async fn basic_bridge_config() -> anyhow::Result<()> {
    let instance = create_instance(None).await?;
    let client = instance.client;

    for _ in 0..5 {
        let username = client.who_am_i().await.unwrap();
        assert_eq!(username, "sigul-client");
    }

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

// If the bridge presents a certificate signed by a different CA, the client should reject it.
#[tokio::test]
#[tracing_test::traced_test]
async fn client_rejects_bridge_cert() -> anyhow::Result<()> {
    let bridge_hostname = "localhost";
    let server_hostname = "sigul-server";
    let client_name = "sigul-client";
    let instance = create_instance(None).await?;

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
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

// If the client presents a certificate signed by a different CA, the bridge should reject it.
#[tokio::test]
#[tracing_test::traced_test]
async fn bridge_rejects_client_cert() -> anyhow::Result<()> {
    let bridge_hostname = "localhost";
    let server_hostname = "sigul-server";
    let client_name = "sigul-client";
    let instance = create_instance(None).await?;

    let tempdir = tempfile::TempDir::new()?;
    let mut creds = create_credentials(
        tempdir.path(),
        bridge_hostname,
        server_hostname,
        client_name,
    )
    .await?;
    creds.client.ca_certificate = instance.creds.client.ca_certificate;
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
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

// If the client presents a certificate with an empty common name, the bridge should reject it.
#[tokio::test]
#[tracing_test::traced_test]
async fn bridge_rejects_client_cert_empty_common_name() -> anyhow::Result<()> {
    let tempdir = tempfile::TempDir::new()?;
    let creds = create_credentials(tempdir.path(), "localhost", "sigul-server", "").await?;
    let instance = create_instance(Some(creds)).await?;
    let client = instance.client;

    let username = client.who_am_i().await;
    match username {
        Ok(name) => panic!("The request should not succeed, but server responded with {name}"),
        Err(ClientError::Connection(ConnectionError::Protocol(error))) => {
            assert_eq!(error, ProtocolError::MissingCommonName);
        }
        Err(other) => panic!("Incorrect error variant returned: {other:?}"),
    }

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn unlock_gpg_key() -> anyhow::Result<()> {
    let instance = create_instance(None).await?;
    let client = instance.client;

    client
        .unlock("test-gpg-key".to_string(), "🪿🪿🪿".to_string())
        .await?;

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn wrong_gpg_password() -> anyhow::Result<()> {
    let instance = create_instance(None).await?;
    let client = instance.client;

    let result = client
        .unlock("test-gpg-key".to_string(), "🪿🪿🦆".to_string())
        .await;
    // TODO: split out server-side errors from client request errors
    assert!(result.is_err_and(|err| matches!(err, ClientError::Server(ServerError::Internal))));

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn unlock_key_doesnt_exist() -> anyhow::Result<()> {
    let instance = create_instance(None).await?;
    let client = instance.client;

    let result = client
        .unlock(
            "not-a-real-key".to_string(),
            "a boring password".to_string(),
        )
        .await;
    // TODO: split out server-side errors from client request errors
    assert!(result.is_err_and(|err| matches!(err, ClientError::Server(ServerError::Internal))));

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn gpg_sign_inline() -> anyhow::Result<()> {
    let instance = create_instance(None).await?;
    let client = instance.client;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let key_name = "test-gpg-key";

    client
        .unlock(key_name.to_string(), "🪿🪿🪿".to_string())
        .await?;
    let mut keys = client.certificates(key_name.to_string()).await?;
    assert_eq!(1, keys.len());
    let key = keys.pop().unwrap();
    let signature = client
        .gpg_sign(
            key_name.to_string(),
            GpgSignatureType::Inline,
            bytes::Bytes::from(data),
        )
        .await?;

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
                "Authenticated signature made by {} ({} <admin@example.com>)",
                fingerprint, key_name
            )));
        }
        _ => panic!("unexpected key type"),
    }

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn gpg_sign_detached() -> anyhow::Result<()> {
    let instance = create_instance(None).await?;
    let client = instance.client;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let key_name = "test-gpg-key";

    client
        .unlock(key_name.to_string(), "🪿🪿🪿".to_string())
        .await?;
    let mut keys = client.certificates(key_name.to_string()).await?;
    assert_eq!(1, keys.len());
    let key = keys.pop().unwrap();
    let signature = client
        .gpg_sign(
            key_name.to_string(),
            GpgSignatureType::Detached,
            bytes::Bytes::from(data),
        )
        .await?;

    match key {
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
                "Authenticated signature made by {} ({} <admin@example.com>)",
                fingerprint, key_name
            )));
        }
        _ => panic!("unexpected key type"),
    }

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn gpg_sign_cleartext() -> anyhow::Result<()> {
    let instance = create_instance(None).await?;
    let client = instance.client;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let key_name = "test-gpg-key";

    client
        .unlock(key_name.to_string(), "🪿🪿🪿".to_string())
        .await?;
    let mut keys = client.certificates(key_name.to_string()).await?;
    assert_eq!(1, keys.len());
    let key = keys.pop().unwrap();

    let signature = client
        .gpg_sign(
            key_name.to_string(),
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
                "Authenticated signature made by {} ({} <admin@example.com>)",
                fingerprint, key_name
            )));
        }
        _ => panic!("unexpected key type"),
    }

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn check_x509_certs() -> anyhow::Result<()> {
    let instance = create_instance(None).await?;
    let client = instance.client;
    let ca_key_name = "test-ca-key";
    let codesigning_key_name = "test-codesigning-key";
    let ca_key = client
        .certificates(ca_key_name.to_string())
        .await?
        .pop()
        .unwrap();
    let codesigning_key = client
        .certificates(codesigning_key_name.to_string())
        .await?
        .pop()
        .unwrap();
    match (ca_key, codesigning_key) {
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

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}
