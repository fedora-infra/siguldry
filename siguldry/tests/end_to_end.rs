// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

#![cfg(feature = "server")]

use siguldry::{
    client::{self, ProxyClient},
    error::{ClientError, ConnectionError, ProtocolError, ServerError},
    protocol::{DigestAlgorithm, GpgSignatureType, KeyAlgorithm},
};

use siguldry_test::{InstanceBuilder, create_credentials, keys};

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
async fn client_proxy_unlock_gpg_key() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_gpg_key()
        .with_client_proxy()
        .build()
        .await?;
    let mut client_proxy = ProxyClient::new(instance.client_proxy_socket())?;

    tokio::task::spawn_blocking(move || {
        client_proxy.unlock(
            keys::GPG_KEY_NAME.to_string(),
            keys::GPG_KEY_PASSWORD.to_string(),
        )
    })
    .await??;

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

/// List keys through the client proxy
#[tokio::test]
#[tracing_test::traced_test]
async fn client_proxy_list_keys() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_all_keys()
        .with_client_proxy()
        .build()
        .await?;
    let mut client_proxy = ProxyClient::new(instance.client_proxy_socket())?;

    let keys = tokio::task::spawn_blocking(move || client_proxy.list_keys()).await??;
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
    assert!(
        matches!(key.key_algorithm, KeyAlgorithm::Rsa4K),
        "Expected key algorithm to be RSA-4096, but it was {:?}",
        key.key_algorithm
    );
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
async fn gpg_sign_detached_rfc9580() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .use_rfc9580_for_gpg()
        .with_gpg_ec_key()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();

    instance
        .client
        .unlock(
            keys::GPG_EC_KEY_NAME.to_string(),
            keys::GPG_EC_KEY_PASSWORD.to_string(),
        )
        .await?;
    let mut key = instance
        .client
        .get_key(keys::GPG_EC_KEY_NAME.to_string())
        .await?;
    assert!(
        matches!(key.key_algorithm, KeyAlgorithm::P256),
        "Expected key algorithm to be P256, but it was {:?}",
        key.key_algorithm
    );
    assert_eq!(1, key.certificates.len());
    let certificate = key.certificates.pop().unwrap();
    let signature = instance
        .client
        .gpg_sign(
            keys::GPG_EC_KEY_NAME.to_string(),
            GpgSignatureType::Detached,
            bytes::Bytes::from(data),
        )
        .await?;

    match certificate {
        siguldry::protocol::Certificate::Gpg {
            version,
            certificate,
            fingerprint,
        } => {
            assert_eq!(6, version, "Expected a v6 OpenPGP key");
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
                keys::GPG_EC_KEY_NAME,
                keys::GPG_EC_KEY_EMAIL
            )));
            let mut command = tokio::process::Command::new("sq");
            let output = command.arg("inspect").arg(keyring_path).output().await?;
            let stdout = String::from_utf8(output.stdout)?;
            assert!(output.status.success());
            assert!(stdout.contains("Public-key algo: ECDSA"));
            assert!(stdout.contains("Public-key size: 256 bits"));
        }
        _ => panic!("unexpected key type"),
    }

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn gpg_sign_detached_p256() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_gpg_ec_key().build().await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();

    instance
        .client
        .unlock(
            keys::GPG_EC_KEY_NAME.to_string(),
            keys::GPG_EC_KEY_PASSWORD.to_string(),
        )
        .await?;
    let mut key = instance
        .client
        .get_key(keys::GPG_EC_KEY_NAME.to_string())
        .await?;
    assert!(
        matches!(key.key_algorithm, KeyAlgorithm::P256),
        "Expected key algorithm to be P256, but it was {:?}",
        key.key_algorithm
    );
    assert_eq!(1, key.certificates.len());
    let certificate = key.certificates.pop().unwrap();
    let signature = instance
        .client
        .gpg_sign(
            keys::GPG_EC_KEY_NAME.to_string(),
            GpgSignatureType::Detached,
            bytes::Bytes::from(data),
        )
        .await?;

    match certificate {
        siguldry::protocol::Certificate::Gpg {
            version,
            certificate,
            fingerprint,
        } => {
            assert_eq!(4, version, "Expected a v4 OpenPGP key");
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
                keys::GPG_EC_KEY_NAME,
                keys::GPG_EC_KEY_EMAIL
            )));
            let mut command = tokio::process::Command::new("sq");
            let output = command.arg("inspect").arg(keyring_path).output().await?;
            let stdout = String::from_utf8(output.stdout)?;
            assert!(output.status.success());
            assert!(stdout.contains("Public-key algo: ECDSA"));
            assert!(stdout.contains("Public-key size: 256 bits"));
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
                name: _,
                certificate: ca_cert,
            },
            siguldry::protocol::Certificate::X509 {
                name: _,
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
    std::fs::write(&sig_path, signature.value())?;
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
    std::fs::write(&sig_path, signature.value())?;
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
async fn client_proxy_prehashed_signature() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_ec_key()
        .with_client_proxy()
        .build()
        .await?;
    let mut client_proxy = ProxyClient::new(instance.client_proxy_socket())?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let data_sum = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?.to_vec();
    let data_hex = hex::encode(&data_sum);
    let key = instance
        .client
        .get_key(keys::EC_KEY_NAME.to_string())
        .await?;

    let signature = tokio::task::spawn_blocking(move || {
        client_proxy.unlock(
            keys::EC_KEY_NAME.to_string(),
            keys::EC_KEY_PASSWORD.to_string(),
        )?;
        let signature = client_proxy.sign(
            keys::EC_KEY_NAME.to_string(),
            DigestAlgorithm::Sha256,
            data_hex,
        )?;
        Ok::<_, anyhow::Error>(signature)
    })
    .await??;

    let pubkey_path = instance.state_dir.path().join("ec-pubkey.pem");
    std::fs::write(&pubkey_path, &key.public_key)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, signature.value())?;
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
    std::fs::write(&sig_path, signature.value())?;
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
    std::fs::write(&sig_path, signature.value())?;
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
    std::fs::write(&sig_path, signature.value())?;
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
    std::fs::write(&sig_path, signature.value())?;
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

/// Import data from a sigul database and verify PGP signing works with the imported key.
///
/// This test requires you to run `cargo xtask generate-sigul-data` and have softhsm2
#[tokio::test]
#[tracing_test::traced_test]
async fn import_sigul_and_sign() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_sigul_import(None)
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();

    instance
        .client
        .unlock(
            keys::SIGUL_GPG_KEY_NAME.to_string(),
            keys::SIGUL_GPG_KEY_PASSWORD.to_string(),
        )
        .await?;

    let mut key = instance
        .client
        .get_key(keys::SIGUL_GPG_KEY_NAME.to_string())
        .await?;
    assert!(
        !key.certificates.is_empty(),
        "Imported key should have a certificate"
    );
    let certificate = key.certificates.pop().unwrap();

    let signature = instance
        .client
        .gpg_sign(
            keys::SIGUL_GPG_KEY_NAME.to_string(),
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
            let keyring_path = instance.state_dir.path().join("import_gpg_keyring.asc");
            std::fs::write(&keyring_path, certificate)?;

            let data_path = instance.state_dir.path().join("import_gpg_data");
            std::fs::write(&data_path, data)?;

            let sig_path = instance.state_dir.path().join("import_gpg_data.sig");
            std::fs::write(&sig_path, &signature)?;

            let mut command = tokio::process::Command::new("sq");
            let output = command
                .arg("verify")
                .arg(format!("--trust-root={}", &fingerprint))
                .arg(format!("--keyring={}", keyring_path.display()))
                .arg(format!("--signature-file={}", sig_path.display()))
                .arg(&data_path)
                .output()
                .await?;
            let stderr = String::from_utf8(output.stderr)?;
            assert!(
                output.status.success(),
                "Signature verification failed: {}",
                stderr
            );
            assert!(
                stderr.contains(&fingerprint),
                "Signature should be from the imported key"
            );
        }
        _ => panic!("Expected a GPG certificate from the imported key"),
    }

    instance.halt().await?;
    Ok(())
}

/// Import data from a sigul database, but only import the siguldry-user user and no keys.
///
/// This test requires you to run `cargo xtask generate-sigul-data` and have softhsm2
#[tokio::test]
#[tracing_test::traced_test]
async fn import_sigul_just_a_user() -> anyhow::Result<()> {
    // Skip sigul-user and autosigner, import siguldry-user and no keys
    let import_just_siguldry_user = Some(
        "n\n\
         n\n\
         y\n\
         n\n"
        .to_string(),
    );
    let instance = InstanceBuilder::new()
        .with_sigul_import(import_just_siguldry_user)
        .build()
        .await?;
    let keys = instance.client.list_keys().await?;
    assert_eq!(keys.len(), 0);
    let users = instance.client.list_users().await?;
    assert_eq!(vec!["siguldry-client".to_string()], users);

    instance.halt().await?;
    Ok(())
}

/// Import a subset of data from a sigul database and verify PGP signing works.
///
/// This test requires you to run `cargo xtask generate-sigul-data` and have softhsm2
#[tokio::test]
#[tracing_test::traced_test]
async fn import_sigul_just_gpg_key() -> anyhow::Result<()> {
    // Skip sigul-user and autosigner, import siguldry-user and no keys
    let import_subset = Some(format!(
        "n\n\
         n\n\
         y\n\
         y\n\
        {}",
        keys::SIGUL_GPG_KEY_PASSWORD,
    ));
    let instance = InstanceBuilder::new()
        .with_sigul_import(import_subset)
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();

    instance
        .client
        .unlock(
            keys::SIGUL_GPG_KEY_NAME.to_string(),
            keys::SIGUL_GPG_KEY_PASSWORD.to_string(),
        )
        .await?;

    let mut key = instance
        .client
        .get_key(keys::SIGUL_GPG_KEY_NAME.to_string())
        .await?;
    assert!(
        !key.certificates.is_empty(),
        "Imported key should have a certificate"
    );
    let certificate = key.certificates.pop().unwrap();

    let signature = instance
        .client
        .gpg_sign(
            keys::SIGUL_GPG_KEY_NAME.to_string(),
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
            let keyring_path = instance.state_dir.path().join("import_gpg_keyring.asc");
            std::fs::write(&keyring_path, certificate)?;

            let data_path = instance.state_dir.path().join("import_gpg_data");
            std::fs::write(&data_path, data)?;

            let sig_path = instance.state_dir.path().join("import_gpg_data.sig");
            std::fs::write(&sig_path, &signature)?;

            let mut command = tokio::process::Command::new("sq");
            let output = command
                .arg("verify")
                .arg(format!("--trust-root={}", &fingerprint))
                .arg(format!("--keyring={}", keyring_path.display()))
                .arg(format!("--signature-file={}", sig_path.display()))
                .arg(&data_path)
                .output()
                .await?;
            let stderr = String::from_utf8(output.stderr)?;
            assert!(
                output.status.success(),
                "Signature verification failed: {}",
                stderr
            );
            assert!(
                stderr.contains(&fingerprint),
                "Signature should be from the imported key"
            );
        }
        _ => panic!("Expected a GPG certificate from the imported key"),
    }

    instance.halt().await?;
    Ok(())
}

/// Import data from a sigul database and verify certificate names are correct.
///
/// This test requires you to run `cargo xtask generate-sigul-data` and have softhsm2
#[tokio::test]
#[tracing_test::traced_test]
async fn import_sigul_certificate_names_match() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_sigul_import(None)
        .build()
        .await?;

    let ca_key = instance
        .client
        .get_key(keys::SIGUL_CA_KEY_NAME.to_string())
        .await?;
    let ca_cert_names = ca_key
        .certificates
        .iter()
        .filter_map(|cert| match cert {
            siguldry::protocol::Certificate::X509 { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(vec![keys::SIGUL_CA_CERT_NAME], ca_cert_names);

    let rsa_key = instance
        .client
        .get_key(keys::SIGUL_RSA_KEY_NAME.to_string())
        .await?;
    let rsa_cert_names = rsa_key
        .certificates
        .iter()
        .filter_map(|cert| match cert {
            siguldry::protocol::Certificate::X509 { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(vec![keys::SIGUL_RSA_CERT_NAME], rsa_cert_names);

    instance.halt().await?;
    Ok(())
}
