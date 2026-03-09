// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Common code for integration tests.

#![allow(unused)]

use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};

// TODO escargo?
pub fn module_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../target/debug/libsiguldry_pkcs11.so")
}

pub fn initialize_module() -> anyhow::Result<Pkcs11> {
    let pkcs11 = Pkcs11::new(module_path())?;
    let args = CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK);
    pkcs11.initialize(args)?;
    Ok(pkcs11)
}

/// Convert a raw PKCS#11 ECDSA signature (r || s) to DER format for verification with openssl.
pub fn raw_ecdsa_to_der(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    let half = raw.len() / 2;
    let r = openssl::bn::BigNum::from_slice(raw.get(..half).unwrap())?;
    let s = openssl::bn::BigNum::from_slice(raw.get(half..).unwrap())?;
    let sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s)?;
    Ok(sig.to_der()?)
}
