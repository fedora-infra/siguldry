// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Tests for all the non-signing bits of the PKCS #11 module; version information,
//! token info, mechanism listing, etc.

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error, RvError},
    mechanism::MechanismType,
    object::{Attribute, AttributeType, ObjectClass},
};

use siguldry::server::db;
use siguldry_test::{InstanceBuilder, keys};

mod common;
use common::{initialize_module, module_path};

#[tokio::test]
#[tracing_test::traced_test]
async fn initialize_module_locking_ok() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    tokio::task::spawn_blocking(|| {
        let pkcs11 = Pkcs11::new(module_path())?;
        let args = CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK);
        pkcs11.initialize(args)?;
        pkcs11.finalize()?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;

    instance.halt().await?;

    Ok(())
}

// The module should fail gracefully since it needs locking and OS threads.
#[test]
fn initialize_module_no_os_threads() -> anyhow::Result<()> {
    let pkcs11 = Pkcs11::new(module_path())?;
    let args = CInitializeArgs::new(CInitializeFlags::LIBRARY_CANT_CREATE_OS_THREADS);
    let result = pkcs11.initialize(args);
    assert!(result.is_err());
    pkcs11.finalize()?;

    Ok(())
}

// The module should fail gracefully since it needs OS threads.
#[test]
fn initialize_module_all_flags() -> anyhow::Result<()> {
    let pkcs11 = Pkcs11::new(module_path())?;
    let args = CInitializeArgs::new(CInitializeFlags::all());
    let result = pkcs11.initialize(args);
    assert!(result.is_err());
    pkcs11.finalize()?;

    Ok(())
}

// The module should initialize with empty flags as long as locking functions aren't provided.
// cryptoki doesn't appear to support providing locking functions so we can't really test that,
// unfortunately.
#[tokio::test]
#[tracing_test::traced_test]
async fn initialize_module_empty_flags() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    tokio::task::spawn_blocking(|| {
        let pkcs11 = Pkcs11::new(module_path())?;
        let args = CInitializeArgs::new(CInitializeFlags::empty());
        pkcs11.initialize(args)?;
        pkcs11.finalize()?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn get_info() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module()?;

        let info = pkcs11.get_library_info()?;
        assert_eq!(
            info.cryptoki_version().major(),
            3,
            "Major version 3 expected to be the default version"
        );
        assert_eq!(
            info.cryptoki_version().minor(),
            2,
            "Minor version 2 expected to be the default version"
        );
        assert_eq!(info.manufacturer_id(), "Fedora Infrastructure");
        assert_eq!(info.library_description(), "Siguldry PKCS#11 Library");
        assert_eq!(info.library_version().major(), 1);
        assert_eq!(info.library_version().minor(), 0);

        Ok::<_, anyhow::Error>(())
    })
    .await??;

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
async fn get_invalid_slot_info() -> anyhow::Result<()> {
    let _instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;

    let invalid_slot = tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module().unwrap();
        pkcs11.get_slot_info(42_u64.try_into().unwrap())
    })
    .await?;

    if let Err(error) = invalid_slot {
        assert!(matches!(error, Error::Pkcs11(RvError::SlotIdInvalid, _)));
    } else {
        panic!("Slot 42 should be invalid");
    }

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn list_slots() -> anyhow::Result<()> {
    let _instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;

    // The server should contain a CA and the RSA code-signing key, each private key is a slot.
    let slots = tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        Ok::<_, anyhow::Error>(slots)
    })
    .await??;
    assert_eq!(2, slots.len());

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn enumerate_slots() -> anyhow::Result<()> {
    let _instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    // The server should contain a CA and the RSA code-signing key, each private key is a slot.
    let mut slot_infos = tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        assert_eq!(2, slots.len());
        let slot_infos = slots
            .into_iter()
            .map(|slot| pkcs11.get_slot_info(slot))
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, anyhow::Error>(slot_infos)
    })
    .await??;

    let mut expected_descriptions = ["test-ca-key", "test-codesigning-key"];
    expected_descriptions.sort();
    slot_infos.sort_by(|a, b| a.slot_description().cmp(b.slot_description()));
    for (expected_description, slot_info) in expected_descriptions
        .into_iter()
        .zip(slot_infos.into_iter())
    {
        assert!(slot_info.token_present());
        assert_eq!("Fedora Infrastructure", slot_info.manufacturer_id());

        assert_eq!(1, slot_info.firmware_version().major());
        assert_eq!(0, slot_info.firmware_version().minor());

        assert_eq!(1, slot_info.hardware_version().major());
        assert_eq!(0, slot_info.hardware_version().minor());
        assert_eq!(expected_description, slot_info.slot_description());
    }

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn token_serial_numbers_are_handle_prefixes() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    let keys = instance.client.list_keys().await?;

    let serial_numbers = tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        assert_eq!(2, slots.len());
        let serial_numbers = slots
            .into_iter()
            .map(|slot| {
                pkcs11
                    .get_token_info(slot)
                    .map(|info| info.serial_number().to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, anyhow::Error>(serial_numbers)
    })
    .await??;

    for serial_number in serial_numbers.iter() {
        assert!(serial_number.len() <= 16);
        assert!(serial_number.len() >= 12);
        assert!(serial_number.chars().all(|c| c.is_ascii_hexdigit()),);
        assert!(keys.iter().any(|key| key.handle.starts_with(serial_number)));
    }

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn filter_slots() -> anyhow::Result<()> {
    // SAFETY: These tests must be run under nextest which ensures no one else
    // is reading or writing environment variables in this process.
    unsafe {
        std::env::set_var("LIBSIGULDRY_PKCS11_KEYS", keys::CODESIGNING_KEY_NAME);
    }

    // Expose two keys, but filter down to just 1 using the environment variable
    let _instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    let mut slot_infos = tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        assert_eq!(1, slots.len());
        let slot_infos = slots
            .into_iter()
            .map(|slot| pkcs11.get_slot_info(slot))
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, anyhow::Error>(slot_infos)
    })
    .await??;
    assert_eq!(1, slot_infos.len());

    let mut expected_descriptions = [keys::CODESIGNING_KEY_NAME];
    expected_descriptions.sort();
    slot_infos.sort_by(|a, b| a.slot_description().cmp(b.slot_description()));
    for (expected_description, slot_info) in expected_descriptions
        .into_iter()
        .zip(slot_infos.into_iter())
    {
        assert!(slot_info.token_present());
        assert_eq!("Fedora Infrastructure", slot_info.manufacturer_id());

        assert_eq!(1, slot_info.firmware_version().major());
        assert_eq!(0, slot_info.firmware_version().minor());

        assert_eq!(1, slot_info.hardware_version().major());
        assert_eq!(0, slot_info.hardware_version().minor());
        assert_eq!(expected_description, slot_info.slot_description());
    }

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn mechanism_list_for_rsa_key() -> anyhow::Result<()> {
    let _instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;

    let mechanism_list = tokio::task::spawn_blocking(|| {
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
        let mechanism_list = pkcs11.get_mechanism_list(*slot)?;
        Ok::<_, anyhow::Error>(mechanism_list)
    })
    .await??;

    // The module also should support SHA3 variants of below, but cryptoki doesn't expose those
    // in its MechanismType.
    assert!(
        mechanism_list.contains(&MechanismType::SHA256_RSA_PKCS),
        "Module should support the PKCS #1 v1.5 RSA signing with SHA256 hashing"
    );
    assert!(
        mechanism_list.contains(&MechanismType::SHA512_RSA_PKCS),
        "Module should support the PKCS #1 v1.5 RSA signing with SHA512 hashing"
    );

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn mechanism_list_for_p256_key() -> anyhow::Result<()> {
    let _instance = InstanceBuilder::new()
        .with_ec_key()
        .with_client_proxy()
        .build()
        .await?;

    let mechanism_list = tokio::task::spawn_blocking(|| {
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
        let mechanism_list = pkcs11.get_mechanism_list(*slot)?;
        Ok::<_, anyhow::Error>(mechanism_list)
    })
    .await??;

    // The module also should support SHA3 variants of below, but cryptoki doesn't expose those
    // in its MechanismType.
    assert!(
        mechanism_list.contains(&MechanismType::ECDSA_SHA256),
        "Module should support EcDSA signing with SHA256 hashing"
    );
    assert!(
        mechanism_list.contains(&MechanismType::ECDSA_SHA512),
        "Module should support EcDSA signing with SHA512 hashing"
    );

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn mechanism_list_for_ed25519_key() -> anyhow::Result<()> {
    let _instance = InstanceBuilder::new()
        .with_ed25519_key()
        .with_client_proxy()
        .build()
        .await?;

    let mechanism_list = tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        let slot = slots
            .iter()
            .find(|slot| {
                if let Ok(info) = pkcs11.get_slot_info(**slot)
                    && info.slot_description() == keys::ED25519_KEY_NAME
                {
                    true
                } else {
                    false
                }
            })
            .unwrap();
        let mechanism_list = pkcs11.get_mechanism_list(*slot)?;
        Ok::<_, anyhow::Error>(mechanism_list)
    })
    .await??;

    assert_eq!(
        mechanism_list,
        &[MechanismType::EDDSA],
        "Module should support pure EdDSA signing with Ed25519 keys"
    );

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn mechanism_list_for_ed448_key() -> anyhow::Result<()> {
    let _instance = InstanceBuilder::new()
        .with_ed448_key()
        .with_client_proxy()
        .build()
        .await?;

    let mechanism_list = tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        let slot = slots
            .iter()
            .find(|slot| {
                if let Ok(info) = pkcs11.get_slot_info(**slot)
                    && info.slot_description() == keys::ED448_KEY_NAME
                {
                    true
                } else {
                    false
                }
            })
            .unwrap();
        let mechanism_list = pkcs11.get_mechanism_list(*slot)?;
        Ok::<_, anyhow::Error>(mechanism_list)
    })
    .await??;

    assert_eq!(
        mechanism_list,
        &[MechanismType::EDDSA],
        "Module should support pure EdDSA signing with Ed448 keys"
    );

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn mechanism_list_for_mldsa65_key() -> anyhow::Result<()> {
    let _instance = InstanceBuilder::new()
        .with_mldsa65_key()
        .with_client_proxy()
        .build()
        .await?;

    let mechanism_list = tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        let slot = slots
            .iter()
            .find(|slot| {
                if let Ok(info) = pkcs11.get_slot_info(**slot)
                    && info.slot_description() == keys::MLDSA65_KEY_NAME
                {
                    true
                } else {
                    false
                }
            })
            .unwrap();
        let mechanism_list = pkcs11.get_mechanism_list(*slot)?;
        Ok::<_, anyhow::Error>(mechanism_list)
    })
    .await??;

    assert_eq!(
        mechanism_list,
        &[MechanismType::ML_DSA],
        "Module should support the standard (not prehashed) ML-DSA signing mechanism"
    );

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn mechanism_list_for_mldsa87_key() -> anyhow::Result<()> {
    let _instance = InstanceBuilder::new()
        .with_mldsa87_key()
        .with_client_proxy()
        .build()
        .await?;

    let mechanism_list = tokio::task::spawn_blocking(|| {
        let pkcs11 = initialize_module()?;
        let slots = pkcs11.get_all_slots()?;
        let slot = slots
            .iter()
            .find(|slot| {
                if let Ok(info) = pkcs11.get_slot_info(**slot)
                    && info.slot_description() == keys::MLDSA87_KEY_NAME
                {
                    true
                } else {
                    false
                }
            })
            .unwrap();
        let mechanism_list = pkcs11.get_mechanism_list(*slot)?;
        Ok::<_, anyhow::Error>(mechanism_list)
    })
    .await??;

    assert_eq!(
        mechanism_list,
        &[MechanismType::ML_DSA],
        "Module should support the standard (not prehashed) ML-DSA signing mechanism"
    );

    Ok(())
}

#[tokio::test]
#[tracing_test::traced_test]
async fn certificate_serial_numbers_are_der_encoded() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_codesigning_key()
        .with_client_proxy()
        .build()
        .await?;
    let key = instance
        .client
        .get_key(keys::CODESIGNING_KEY_NAME.to_string())
        .await?;
    let public_key = openssl::pkey::PKey::public_key_from_pem(key.public_key.as_bytes())?;
    let issuer_key = openssl::pkey::PKey::generate_ed25519()?;
    let mut name = openssl::x509::X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "Test")?;
    let name = name.build();
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(1)?;

    // Serial numbers are generated from random numbers typically, so we need to
    // craft some special certs. One thing in particular is that if the cert has
    // the first bit set it needs to be prepended by a 0 byte.
    let database = db::pool(
        &format!("sqlite://{}", instance.server_config.database().display()),
        false,
    )
    .await?;
    let mut connection = database.acquire().await?;
    let database_key = db::Key::get(&mut connection, keys::CODESIGNING_KEY_NAME).await?;
    let mut certificates = Vec::new();
    for (serial_hex, expected_der_hex) in [
        ("0", "020100"),
        ("7F", "02017f"),
        ("80", "02020080"),
        ("FF", "020200ff"),
        ("100", "02020100"),
        ("800000000000000001", "020a00800000000000000001"),
    ] {
        let serial = openssl::bn::BigNum::from_hex_str(serial_hex)?.to_asn1_integer()?;
        let mut certificate = openssl::x509::X509::builder()?;
        certificate.set_version(2)?;
        certificate.set_serial_number(&serial)?;
        certificate.set_subject_name(&name)?;
        certificate.set_issuer_name(&name)?;
        certificate.set_not_before(&not_before)?;
        certificate.set_not_after(&not_after)?;
        certificate.set_pubkey(&public_key)?;
        certificate.sign(&issuer_key, openssl::hash::MessageDigest::null())?;
        let certificate = certificate.build();
        db::PublicKeyMaterial::create(
            &mut connection,
            &database_key,
            format!("serial-number-{serial_hex}"),
            db::PublicKeyMaterialType::X509,
            String::from_utf8(certificate.to_pem()?)?,
        )
        .await?;
        certificates.push((certificate.to_der()?, hex::decode(expected_der_hex)?));
    }
    drop(connection);
    database.close().await;

    tokio::task::spawn_blocking(move || {
        let pkcs11 = initialize_module()?;
        let slot = pkcs11
            .get_all_slots()?
            .into_iter()
            .find(|slot| {
                pkcs11
                    .get_slot_info(*slot)
                    .is_ok_and(|info| info.slot_description() == keys::CODESIGNING_KEY_NAME)
            })
            .expect("Missing code-signing key slot");
        let session = pkcs11.open_ro_session(slot)?;
        for (certificate_der, serial_der) in certificates {
            let mut objects = session.find_objects(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::Value(certificate_der),
            ])?;
            assert_eq!(objects.len(), 1);
            let certificate = objects.pop().unwrap();
            assert_eq!(
                session.get_attributes(certificate, &[AttributeType::SerialNumber])?,
                vec![Attribute::SerialNumber(serial_der)],
            );
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;

    instance.halt().await?;
    Ok(())
}
