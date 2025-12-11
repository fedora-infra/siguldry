// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Tests for all the non-signing bits of the PKCS #11 module; version information,
//! token info, mechanism listing, etc.

use std::path::PathBuf;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error, RvError},
    mechanism::MechanismType,
};

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
