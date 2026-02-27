// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Tests for the supported signing mechanisms.

use std::path::PathBuf;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass},
    session::UserType,
    types::AuthPin,
};

use siguldry::protocol::{DigestAlgorithm, KeyAlgorithm};
use siguldry_test::{InstanceBuilder, keys};

// TODO escargo?
fn module_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../target/debug/libsiguldry_pkcs11.so")
}

fn initialize_module() -> anyhow::Result<Pkcs11> {
    let pkcs11 = Pkcs11::new(module_path())?;
    let args = CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK);
    pkcs11.initialize(args)?;
    Ok(pkcs11)
}

/// Convert a raw PKCS#11 ECDSA signature (r || s) to DER format for verification with openssl.
fn raw_ecdsa_to_der(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    let half = raw.len() / 2;
    let r = openssl::bn::BigNum::from_slice(raw.get(..half).unwrap())?;
    let s = openssl::bn::BigNum::from_slice(raw.get(half..).unwrap())?;
    let sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s)?;
    Ok(sig.to_der()?)
}

#[tokio::test]
#[tracing_test::traced_test]
async fn sign_sha256_rsa_pkcs() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let pin = AuthPin::from(keys::CODESIGNING_KEY_PASSWORD);
    let expected_pubkey = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;
    let expected_pubkey_der =
        openssl::rsa::Rsa::public_key_from_pem(expected_pubkey.public_key.as_bytes())?
            .public_key_to_der()?;

    let (pubkey, signature) = tokio::task::spawn_blocking(move || {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        let slot = slots
            .iter()
            .find(|slot| {
                if let Ok(info) = pkcs11.get_slot_info(**slot)
                    && info.slot_description() == keys::CODESIGNING_KEY_NAME
                {
                    true
                } else {
                    false
                }
            })
            .unwrap();
        let session = pkcs11.open_ro_session(*slot)?;
        session.login(UserType::User, Some(&pin))?;
        let mut key = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])?;
        assert_eq!(
            key.len(),
            1,
            "Each slot is expected to contain a single private key"
        );
        let key = key.pop().unwrap();

        let mut pubkey_object =
            session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])?;
        assert_eq!(
            pubkey_object.len(),
            1,
            "Each slot is expected to contain a single public key"
        );
        let pubkey_object = pubkey_object.pop().unwrap();
        let pubkey_attribute = session
            .get_attributes(pubkey_object, &[AttributeType::PublicKeyInfo])?
            .pop()
            .expect("Missing PublicKeyInfo attribute");
        let pubkey = match pubkey_attribute {
            Attribute::PublicKeyInfo(der) => der,
            attr => panic!("Got attribute {attr:?} instead of PublicKeyInfo"),
        };

        let signature = session.sign(&Mechanism::Sha256RsaPkcs, key, data)?;
        Ok::<_, anyhow::Error>((pubkey, signature))
    })
    .await??;

    assert_eq!(pubkey, expected_pubkey_der);
    let pubkey_path = instance.state_dir.path().join("codesigning.der");
    std::fs::write(&pubkey_path, &pubkey)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &signature)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-sha256")
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

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn sign_sha512_rsa_pkcs() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let pin = AuthPin::from(keys::CODESIGNING_KEY_PASSWORD);
    let expected_pubkey = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;
    let expected_pubkey_der =
        openssl::rsa::Rsa::public_key_from_pem(expected_pubkey.public_key.as_bytes())?
            .public_key_to_der()?;

    let (pubkey, signature) = tokio::task::spawn_blocking(move || {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        let slot = slots
            .iter()
            .find(|slot| {
                if let Ok(info) = pkcs11.get_slot_info(**slot)
                    && info.slot_description() == keys::CODESIGNING_KEY_NAME
                {
                    true
                } else {
                    false
                }
            })
            .unwrap();
        let session = pkcs11.open_ro_session(*slot)?;
        session.login(UserType::User, Some(&pin))?;
        let mut key = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])?;
        assert_eq!(
            key.len(),
            1,
            "Each slot is expected to contain a single private key"
        );
        let key = key.pop().unwrap();

        let mut pubkey_object =
            session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])?;
        assert_eq!(
            pubkey_object.len(),
            1,
            "Each slot is expected to contain a single public key"
        );
        let pubkey_object = pubkey_object.pop().unwrap();
        let pubkey_attribute = session
            .get_attributes(pubkey_object, &[AttributeType::PublicKeyInfo])?
            .pop()
            .expect("Missing PublicKeyInfo attribute");
        let pubkey = match pubkey_attribute {
            Attribute::PublicKeyInfo(der) => der,
            attr => panic!("Got attribute {attr:?} instead of PublicKeyInfo"),
        };

        let signature = session.sign(&Mechanism::Sha512RsaPkcs, key, data)?;
        Ok::<_, anyhow::Error>((pubkey, signature))
    })
    .await??;

    assert_eq!(pubkey, expected_pubkey_der);
    let pubkey_path = instance.state_dir.path().join("codesigning.der");
    std::fs::write(&pubkey_path, &pubkey)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &signature)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-sha512")
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

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn sign_sha256_ecdsa() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_ec_key()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let pin = AuthPin::from(keys::EC_KEY_PASSWORD);
    let expected_pubkey = instance
        .client
        .get_key(keys::EC_KEY_NAME.to_string())
        .await?;
    let expected_pubkey_der =
        openssl::ec::EcKey::public_key_from_pem(expected_pubkey.public_key.as_bytes())?
            .public_key_to_der()?;

    let (pubkey, signature) = tokio::task::spawn_blocking(move || {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        let slot = slots
            .iter()
            .find(|slot| {
                if let Ok(info) = pkcs11.get_slot_info(**slot)
                    && info.slot_description() == keys::EC_KEY_NAME
                {
                    true
                } else {
                    false
                }
            })
            .unwrap();
        let session = pkcs11.open_ro_session(*slot)?;
        session.login(UserType::User, Some(&pin))?;
        let mut key = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])?;
        assert_eq!(
            key.len(),
            1,
            "Each slot is expected to contain a single private key"
        );
        let key = key.pop().unwrap();

        let mut pubkey_object =
            session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])?;
        assert_eq!(
            pubkey_object.len(),
            1,
            "Each slot is expected to contain a single public key"
        );
        let pubkey_object = pubkey_object.pop().unwrap();
        let pubkey_attribute = session
            .get_attributes(pubkey_object, &[AttributeType::PublicKeyInfo])?
            .pop()
            .expect("Missing PublicKeyInfo attribute");
        let pubkey = match pubkey_attribute {
            Attribute::PublicKeyInfo(der) => der,
            attr => panic!("Got attribute {attr:?} instead of PublicKeyInfo"),
        };

        let signature = session.sign(&Mechanism::EcdsaSha256, key, data)?;
        Ok::<_, anyhow::Error>((pubkey, signature))
    })
    .await??;

    assert_eq!(pubkey, expected_pubkey_der);
    let pubkey_path = instance.state_dir.path().join("ec.der");
    std::fs::write(&pubkey_path, &pubkey)?;
    let sig_der = raw_ecdsa_to_der(&signature)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &sig_der)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-sha256")
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

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn sign_sha512_ecdsa() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_ec_key()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let pin = AuthPin::from(keys::EC_KEY_PASSWORD);
    let expected_pubkey = instance
        .client
        .get_key(keys::EC_KEY_NAME.to_string())
        .await?;
    let expected_pubkey_der =
        openssl::ec::EcKey::public_key_from_pem(expected_pubkey.public_key.as_bytes())?
            .public_key_to_der()?;

    let (pubkey, signature) = tokio::task::spawn_blocking(move || {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        let slot = slots
            .iter()
            .find(|slot| {
                if let Ok(info) = pkcs11.get_slot_info(**slot)
                    && info.slot_description() == keys::EC_KEY_NAME
                {
                    true
                } else {
                    false
                }
            })
            .unwrap();
        let session = pkcs11.open_ro_session(*slot)?;
        session.login(UserType::User, Some(&pin))?;
        let mut key = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])?;
        assert_eq!(
            key.len(),
            1,
            "Each slot is expected to contain a single private key"
        );
        let key = key.pop().unwrap();

        let mut pubkey_object =
            session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])?;
        assert_eq!(
            pubkey_object.len(),
            1,
            "Each slot is expected to contain a single public key"
        );
        let pubkey_object = pubkey_object.pop().unwrap();
        let pubkey_attribute = session
            .get_attributes(pubkey_object, &[AttributeType::PublicKeyInfo])?
            .pop()
            .expect("Missing PublicKeyInfo attribute");
        let pubkey = match pubkey_attribute {
            Attribute::PublicKeyInfo(der) => der,
            attr => panic!("Got attribute {attr:?} instead of PublicKeyInfo"),
        };

        let signature = session.sign(&Mechanism::EcdsaSha512, key, data)?;
        Ok::<_, anyhow::Error>((pubkey, signature))
    })
    .await??;

    assert_eq!(pubkey, expected_pubkey_der);
    let pubkey_path = instance.state_dir.path().join("ec.der");
    std::fs::write(&pubkey_path, &pubkey)?;
    let sig_der = raw_ecdsa_to_der(&signature)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &sig_der)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-sha512")
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

    Ok(())
}

/// Helper to sign data using the openssl CLI with the pkcs11-provider and verify the signature.
async fn openssl_provider_sign_and_verify(
    state_dir: &std::path::Path,
    digest: DigestAlgorithm,
    key_algorithm: KeyAlgorithm,
    key_name: &str,
    password: &str,
    pubkey_pem: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    let data_path = state_dir.join("data");
    std::fs::write(&data_path, data)?;

    let pubkey_path = state_dir.join("pubkey.pem");
    std::fs::write(&pubkey_path, pubkey_pem.as_bytes())?;

    let sig_path = state_dir.join("data.sig");
    let key_uri = format!("pkcs11:token={key_name};type=private");
    let proxy_path = state_dir.join("client-proxy.socket");

    let mut sign_command = tokio::process::Command::new("openssl");
    sign_command
        .env("PKCS11_PROVIDER_MODULE", module_path())
        .env("LIBSIGULDRY_PKCS11_PROXY_PATH", &proxy_path)
        .arg("pkeyutl")
        .arg("-sign")
        .arg("-rawin")
        .arg("-provider")
        .arg("pkcs11")
        .arg("-provider")
        .arg("default")
        .arg("-inkey")
        .arg(&key_uri)
        .arg("-in")
        .arg(&data_path)
        .arg("-out")
        .arg(&sig_path)
        .arg("-passin")
        .arg(format!("pass:{password}"))
        .arg("-pkeyopt")
        .arg(format!("digest:{digest}"));
    if matches!(key_algorithm, KeyAlgorithm::Rsa2K | KeyAlgorithm::Rsa4K) {
        sign_command.arg("-pkeyopt").arg("rsa_padding_mode:pkcs1");
    }
    let output = sign_command.output().await?;
    assert!(
        output.status.success(),
        "openssl pkeyutl -sign failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let mut verify_command = tokio::process::Command::new("openssl");
    let output = verify_command
        .arg("dgst")
        .arg(format!("-{digest}"))
        .arg("-verify")
        .arg(&pubkey_path)
        .arg("-signature")
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "openssl dgst -{digest} -verify failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!("Verified OK\n", stdout);

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn sign_sha256_rsa_pkcs_openssl_provider() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let expected_pubkey = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;

    openssl_provider_sign_and_verify(
        instance.state_dir.path(),
        DigestAlgorithm::Sha256,
        expected_pubkey.key_algorithm,
        keys::CODESIGNING_KEY_NAME,
        keys::CODESIGNING_KEY_PASSWORD,
        &expected_pubkey.public_key,
        data,
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn sign_sha512_rsa_pkcs_openssl_provider() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let expected_pubkey = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;

    openssl_provider_sign_and_verify(
        instance.state_dir.path(),
        DigestAlgorithm::Sha512,
        expected_pubkey.key_algorithm,
        keys::CODESIGNING_KEY_NAME,
        keys::CODESIGNING_KEY_PASSWORD,
        &expected_pubkey.public_key,
        data,
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn sign_sha256_ecdsa_openssl_provider() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_ec_key()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let expected_pubkey = instance
        .client
        .get_key(keys::EC_KEY_NAME.to_string())
        .await?;

    openssl_provider_sign_and_verify(
        instance.state_dir.path(),
        DigestAlgorithm::Sha256,
        expected_pubkey.key_algorithm,
        keys::EC_KEY_NAME,
        keys::EC_KEY_PASSWORD,
        &expected_pubkey.public_key,
        data,
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn sign_sha512_ecdsa_openssl_provider() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_ec_key()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let expected_pubkey = instance
        .client
        .get_key(keys::EC_KEY_NAME.to_string())
        .await?;

    openssl_provider_sign_and_verify(
        instance.state_dir.path(),
        DigestAlgorithm::Sha512,
        expected_pubkey.key_algorithm,
        keys::EC_KEY_NAME,
        keys::EC_KEY_PASSWORD,
        &expected_pubkey.public_key,
        data,
    )
    .await?;

    Ok(())
}

// Use Sequoia's cryptoki backend to sign using the pkcs11 module.
//
// Note: This test only works with a version of sequoia that supports
// PKCS11. Once it's released and Fedora updates, enable this test.
// You can test locally with a build from
// https://github.com/neverpanic/fosdem-rpm-pqc-signing-demo/
#[tokio::test]
#[tracing_test::traced_test]
#[ignore = "Sequoia doesn't yet support PKCS11"]
async fn sign_rsa4k_via_sequoia() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_gpg_key()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let data_path = instance.state_dir.path().join("data");
    tokio::fs::write(&data_path, data).await?;
    let sig_path = instance.state_dir.path().join("data.sig");

    let expected_pubkey = instance
        .client
        .get_key(keys::GPG_KEY_NAME.to_string())
        .await?;
    let certificate_path = instance.state_dir.path().join("signing_key.asc");
    tokio::fs::write(&certificate_path, expected_pubkey.public_key.as_bytes()).await?;
    let password_path = instance.state_dir.path().join("password");
    tokio::fs::write(&password_path, keys::GPG_KEY_PASSWORD.as_bytes()).await?;

    let sequoia_home = instance.state_dir.path().join("sequoia_home");
    let mut command = tokio::process::Command::new("sq");
    let output = command
        .env("SEQUOIA_HOME", &sequoia_home)
        .arg("--batch")
        .arg("cert")
        .arg("import")
        .arg(&certificate_path)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'sq --batch cert import {}' failed:\nstdout: {}\nstderr: {}",
        certificate_path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let mut command = tokio::process::Command::new("sq");
    let output = command
        .env("SEQUOIA_HOME", &sequoia_home)
        .arg("--batch")
        .arg("pki")
        .arg("link")
        .arg("add")
        .arg(format!("--cert={}", &expected_pubkey.handle))
        .arg("--all")
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'sq --batch pki link add --cert={} --all' failed:\nstdout: {}\nstderr: {}",
        &expected_pubkey.handle,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let mut command = tokio::process::Command::new("sq");
    let output = command
        .stdin(std::process::Stdio::null())
        .env("SEQUOIA_HOME", &sequoia_home)
        .env("RUST_LOG", "trace")
        .env(
            "LIBSIGULDRY_PKCS11_PROXY_PATH",
            instance.client_proxy_socket(),
        )
        .arg("--batch")
        .arg(format!("--password-file={}", password_path.display()))
        .arg("sign")
        .arg(format!("--signer={}", &expected_pubkey.handle))
        .arg(format!("--signature-file={}", sig_path.display()))
        .arg(&data_path)
        .output()
        .await?;

    assert!(
        output.status.success(),
        "'sq --batch sign --signer={} --signature-file={} {}' failed:\nstdout: {}\nstderr: {}",
        &expected_pubkey.handle,
        sig_path.display(),
        data_path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let mut command = tokio::process::Command::new("sq");
    let output = command
        .env("SEQUOIA_HOME", &sequoia_home)
        .arg("--batch")
        .arg("verify")
        .arg(format!("--signature-file={}", sig_path.display()))
        .arg(&data_path)
        .output()
        .await?;
    assert!(
        output.status.success(),
        "'sq --batch verify --signature-file={} {}' failed:\nstdout: {}\nstderr: {}",
        sig_path.display(),
        data_path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    instance.halt().await?;
    Ok(())
}

// Test that if a key has been configured to be auto-unlocked by the proxy
// it is marked wit the CKF_PROTECTED_AUTHENTICATION_PATH flag and works without a PIN.
#[tokio::test]
#[tracing_test::traced_test]
async fn sign_protected_authentication_path() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .auto_unlock_keys()
        .with_client_proxy()
        .build()
        .await?;
    let data = "🦡🦡🦡🦡🍄🍄".as_bytes();
    let expected_pubkey = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;
    let expected_pubkey_der =
        openssl::rsa::Rsa::public_key_from_pem(expected_pubkey.public_key.as_bytes())?
            .public_key_to_der()?;

    let (pubkey, signature) = tokio::task::spawn_blocking(move || {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        let slot = slots
            .iter()
            .find(|slot| {
                if let Ok(info) = pkcs11.get_slot_info(**slot)
                    && info.slot_description() == keys::CODESIGNING_KEY_NAME
                {
                    true
                } else {
                    false
                }
            })
            .unwrap();
        let token = pkcs11.get_token_info(*slot)?;
        assert!(token.protected_authentication_path(), "Key is configured to auto-unlock but isn't marked with protected authentication path flag");

        let session = pkcs11.open_ro_session(*slot)?;
        session.login(UserType::User, None)?;
        let mut key = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])?;
        assert_eq!(
            key.len(),
            1,
            "Each slot is expected to contain a single private key"
        );
        let key = key.pop().unwrap();

        let mut pubkey_object =
            session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])?;
        assert_eq!(
            pubkey_object.len(),
            1,
            "Each slot is expected to contain a single public key"
        );
        let pubkey_object = pubkey_object.pop().unwrap();
        let pubkey_attribute = session
            .get_attributes(pubkey_object, &[AttributeType::PublicKeyInfo])?
            .pop()
            .expect("Missing PublicKeyInfo attribute");
        let pubkey = match pubkey_attribute {
            Attribute::PublicKeyInfo(der) => der,
            attr => panic!("Got attribute {attr:?} instead of PublicKeyInfo"),
        };

        let signature = session.sign(&Mechanism::Sha256RsaPkcs, key, data)?;
        Ok::<_, anyhow::Error>((pubkey, signature))
    })
    .await??;

    assert_eq!(pubkey, expected_pubkey_der);
    let pubkey_path = instance.state_dir.path().join("codesigning.der");
    std::fs::write(&pubkey_path, &pubkey)?;
    let sig_path = instance.state_dir.path().join("data.sig");
    std::fs::write(&sig_path, &signature)?;
    let data_path = instance.state_dir.path().join("data");
    std::fs::write(&data_path, data)?;
    let mut command = tokio::process::Command::new("openssl");
    let output = command
        .arg("dgst")
        .arg("-sha256")
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

    Ok(())
}
