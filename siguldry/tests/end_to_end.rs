// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

#![cfg(feature = "server")]

use siguldry::{
    client::{self, ProxyClient},
    error::{ClientError, ConnectionError, ProtocolError, ServerError},
    protocol::DigestAlgorithm,
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
    let instance = InstanceBuilder::new().with_pgp_key().build().await?;

    instance
        .client
        .unlock(
            keys::PGP_KEY_NAME.to_string(),
            keys::PGP_KEY_PASSWORD.to_string(),
        )
        .await?;

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn client_proxy_unlock_gpg_key() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_pgp_key()
        .with_client_proxy()
        .build()
        .await?;
    let mut client_proxy = ProxyClient::new(instance.client_proxy_socket())?;

    tokio::task::spawn_blocking(move || {
        client_proxy.unlock(
            keys::PGP_KEY_NAME.to_string(),
            keys::PGP_KEY_PASSWORD.to_string(),
        )
    })
    .await??;

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn wrong_gpg_password() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().with_pgp_key().build().await?;

    let result = instance
        .client
        .unlock(keys::PGP_KEY_NAME.to_string(), "🪿🪿🦆".to_string())
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
    // OpenPGP key + CA key + codesigning key + EC key
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
    // OpenPGP key + CA key + codesigning key + EC key
    assert_eq!(4, keys.len());

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

    let ca_key = instance
        .client
        .get_key(keys::CA_KEY_NAME.to_string())
        .await?;
    let codesigning_key = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;
    match (
        ca_key.x509_certificates().pop().unwrap(),
        codesigning_key.x509_certificates().pop().unwrap(),
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
