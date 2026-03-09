// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use siguldry_test::{InstanceBuilder, keys};

mod common;
use common::module_path;

/// Import data from a sigul database and verify OpenPGP signing works with the imported key.
///
/// This test requires you to run `cargo xtask generate-sigul-data` and have softhsm2
#[tokio::test]
#[tracing_test::traced_test]
async fn import_sigul_and_sign() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .auto_unlock_keys()
        .with_sigul_import(None)
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let data_path = instance.state_dir.path().join("data");
    tokio::fs::write(&data_path, data).await?;
    let sig_path = instance.state_dir.path().join("data.sig");

    let expected_pubkey = instance
        .client
        .get_key(keys::SIGUL_GPG_KEY_NAME.to_string())
        .await?;

    let certificate_path = instance.state_dir.path().join("signing_key.asc");
    let cert = expected_pubkey
        .openpgp_certificates()
        .first()
        .cloned()
        .unwrap();
    let _fingerprint = match cert {
        siguldry::protocol::Certificate::Pgp {
            version: _,
            certificate,
            fingerprint,
        } => {
            tokio::fs::write(&certificate_path, certificate.as_bytes()).await?;
            fingerprint
        }
        _ => panic!("was expecting a Pgp cert"),
    };
    let gnupg_home = instance.state_dir.path().join("gpghome");
    tokio::fs::create_dir(&gnupg_home).await?;
    let gpg_agent_conf = gnupg_home.join("gpg-agent.conf");
    tokio::fs::write(
        &gpg_agent_conf,
        "scdaemon-program /usr/bin/gnupg-pkcs11-scd\n",
    )
    .await?;

    let gpg_pkcs11_scd_conf = gnupg_home.join("gnupg-pkcs11-scd.conf");
    tokio::fs::write(
        &gpg_pkcs11_scd_conf,
        format!(
            "providers siguldry\nprovider-siguldry-library {}\nprovider-siguldry-allow-protected-auth\n",
            module_path().display()
        ),
    )
    .await?;

    let proxy_path = instance.client_proxy_socket();
    let output = tokio::process::Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .env("LIBSIGULDRY_PKCS11_PROXY_PATH", &proxy_path)
        .arg("--batch")
        .arg("--import")
        .arg(&certificate_path)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'gpg --import {}' failed:\nstdout: {}\nstderr: {}",
        certificate_path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let output = tokio::process::Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .env("LIBSIGULDRY_PKCS11_PROXY_PATH", &proxy_path)
        .arg("--card-status")
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'gpg --card-status' failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let output = tokio::process::Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .env("LIBSIGULDRY_PKCS11_PROXY_PATH", &proxy_path)
        .arg("--batch")
        .arg("--detach-sign")
        .arg("--output")
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'gpg --detach-sign' failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let output = tokio::process::Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .arg("--verify")
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'gpg --verify {} {}' failed:\nstdout: {}\nstderr: {}",
        sig_path.display(),
        data_path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let _ = tokio::process::Command::new("gpgconf")
        .env("GNUPGHOME", &gnupg_home)
        .arg("--kill")
        .arg("gpg-agent")
        .output()
        .await;
    instance.halt().await?;
    Ok(())
}

/// Import a subset of data from a sigul database and verify OpenPGP signing works.
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
        .auto_unlock_keys()
        .with_sigul_import(import_subset)
        .with_client_proxy()
        .build()
        .await?;

    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let data_path = instance.state_dir.path().join("data");
    tokio::fs::write(&data_path, data).await?;
    let sig_path = instance.state_dir.path().join("data.sig");

    let expected_pubkey = instance
        .client
        .get_key(keys::SIGUL_GPG_KEY_NAME.to_string())
        .await?;

    let certificate_path = instance.state_dir.path().join("signing_key.asc");
    let cert = expected_pubkey
        .openpgp_certificates()
        .first()
        .cloned()
        .unwrap();
    let _fingerprint = match cert {
        siguldry::protocol::Certificate::Pgp {
            version: _,
            certificate,
            fingerprint,
        } => {
            tokio::fs::write(&certificate_path, certificate.as_bytes()).await?;
            fingerprint
        }
        _ => panic!("was expecting a Pgp cert"),
    };
    let gnupg_home = instance.state_dir.path().join("gpghome");
    tokio::fs::create_dir(&gnupg_home).await?;
    let gpg_agent_conf = gnupg_home.join("gpg-agent.conf");
    tokio::fs::write(
        &gpg_agent_conf,
        "scdaemon-program /usr/bin/gnupg-pkcs11-scd\n",
    )
    .await?;

    let gpg_pkcs11_scd_conf = gnupg_home.join("gnupg-pkcs11-scd.conf");
    tokio::fs::write(
        &gpg_pkcs11_scd_conf,
        format!(
            "providers siguldry\nprovider-siguldry-library {}\nprovider-siguldry-allow-protected-auth\n",
            module_path().display()
        ),
    )
    .await?;

    let proxy_path = instance.client_proxy_socket();
    let output = tokio::process::Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .env("LIBSIGULDRY_PKCS11_PROXY_PATH", &proxy_path)
        .arg("--batch")
        .arg("--import")
        .arg(&certificate_path)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'gpg --import {}' failed:\nstdout: {}\nstderr: {}",
        certificate_path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let output = tokio::process::Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .env("LIBSIGULDRY_PKCS11_PROXY_PATH", &proxy_path)
        .arg("--card-status")
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'gpg --card-status' failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    eprintln!(
        "'gpg --card-status':\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let output = tokio::process::Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .env("LIBSIGULDRY_PKCS11_PROXY_PATH", &proxy_path)
        .arg("--batch")
        .arg("--detach-sign")
        .arg("--output")
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'gpg --detach-sign' failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let output = tokio::process::Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .arg("--verify")
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'gpg --verify {} {}' failed:\nstdout: {}\nstderr: {}",
        sig_path.display(),
        data_path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let _ = tokio::process::Command::new("gpgconf")
        .env("GNUPGHOME", &gnupg_home)
        .arg("--kill")
        .arg("gpg-agent")
        .output()
        .await;
    instance.halt().await?;
    Ok(())
}
