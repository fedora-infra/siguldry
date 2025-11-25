// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! All the cryptography-related operations are in this module.
//!
//! Sequoia is used for GPG signatures and for the symmetric encryption of keys managed by Siguldry.
//! OpenSSL is used for other signatures.

use std::{
    io::{Read, Write},
    process::Stdio,
};

use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    stack::Stack,
    symm::Cipher,
    x509::X509,
};
use sequoia_openpgp::{
    Profile,
    cert::CipherSuite,
    crypto::Password,
    packet,
    parse::{
        Parse,
        stream::{DecryptionHelper, DecryptorBuilder, VerificationHelper},
    },
    policy::StandardPolicy,
    serialize::{
        MarshalInto,
        stream::{Armorer, Encryptor, LiteralWriter, Message, Signer},
    },
    types::{KeyFlags, SymmetricAlgorithm},
};
use serde::{Deserialize, Serialize};

use crate::{protocol::KeyAlgorithm, server::config::Pkcs11Binding};

pub(crate) fn generate_password() -> anyhow::Result<Password> {
    let mut buf = [0; 128];
    openssl::rand::rand_bytes(buf.as_mut_slice())?;
    Ok(Password::from(openssl::base64::encode_block(&buf)))
}

pub fn create_encrypted_key(
    config: &super::Config,
    user_password: Password,
    algorithm: KeyAlgorithm,
) -> anyhow::Result<(String, Vec<u8>, String, String)> {
    let key_password = generate_password()?;
    let key = match algorithm {
        KeyAlgorithm::Rsa4K => PKey::from_rsa(Rsa::generate(4096)?)?,
        KeyAlgorithm::P256 => PKey::from_ec_key(EcKey::generate(
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
        )?)?,
    };
    let public_key_pem = String::from_utf8(key.public_key_to_pem()?)?;
    let private_key_pem = key_password.map(|key_password| {
        key.private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), key_password)
    })?;
    let private_key_pem = String::from_utf8(private_key_pem)?;
    let encrypted_password =
        encrypt_key_password(&config.pkcs11_bindings, user_password, key_password)?;
    let handle = format!(
        "{:X?}",
        openssl::hash::hash(MessageDigest::sha256(), &key.public_key_to_der()?)?
    );

    Ok((handle, encrypted_password, private_key_pem, public_key_pem))
}

/// A GPG key.
#[derive(Debug, Clone, PartialEq)]
pub struct GpgKey {
    cert: sequoia_openpgp::Cert,
    encrypted_password: Vec<u8>,
    user_password: Password,
}

impl GpgKey {
    pub fn from_armored_key(
        encrypted_key: &[u8],
        encrypted_password: Vec<u8>,
        user_password: Password,
    ) -> anyhow::Result<GpgKey> {
        let cert = sequoia_openpgp::Cert::from_bytes(encrypted_key)?;

        Ok(GpgKey {
            cert,
            encrypted_password,
            user_password,
        })
    }

    /// Create a new GPG key bound to the server.
    pub fn new<U: Into<packet::UserID>>(
        bindings: &[Pkcs11Binding],
        user_id: U,
        user_password: Password,
        profile: Profile,
        cipher: CipherSuite,
    ) -> anyhow::Result<GpgKey> {
        let key_password = generate_password()?;
        let encrypted_password =
            encrypt_key_password(bindings, user_password.clone(), key_password.clone())?;
        let (cert, _signature) = sequoia_openpgp::cert::CertBuilder::new()
            .set_profile(profile)?
            .set_cipher_suite(cipher)
            .add_userid(user_id)
            .set_primary_key_flags(KeyFlags::signing())
            //.add_signing_subkey()
            .set_password(Some(key_password))
            .generate()?;

        Ok(GpgKey {
            cert,
            encrypted_password,
            user_password,
        })
    }

    /// Get the encrypted, ASCII-armored private key.
    pub fn armored_key(&self) -> anyhow::Result<Vec<u8>> {
        self.cert.as_tsk().armored().to_vec()
    }

    pub fn public_key(&self) -> anyhow::Result<String> {
        Ok(String::from_utf8(
            self.cert
                .clone()
                .strip_secret_key_material()
                .armored()
                .to_vec()?,
        )?)
    }

    /// Get the hex GPG fingerprint.
    pub fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    pub fn encrypted_password(&self) -> &[u8] {
        &self.encrypted_password
    }

    pub fn sign(&self, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        let policy = &StandardPolicy::new();
        let signing_key = self
            .cert
            .keys()
            .secret()
            .with_policy(policy, None)
            .supported()
            .for_signing()
            .nth(0)
            .unwrap()
            .key()
            .clone()
            .into_keypair()
            .unwrap();
        // TODO probably want SignatureBuilder
        let mut sink = vec![];
        {
            let message = Message::new(&mut sink);
            let message = Signer::new(message, signing_key).unwrap().build().unwrap();
            let mut message = LiteralWriter::new(message).build().unwrap();
            message.write_all(blob).unwrap();
            message.finalize().unwrap();
        }

        Ok(sink)
    }
}

/// The intermediate data format for passwords.
///
/// A key password, used to decrypt the actual signing key, never leaves the server. Instead,
/// it's encrypted using a set of server-side RSA keys which are stored in a PKCS#11 token,
/// which is then encrypted with a user's access password.
///
/// This is serialized to JSON, which looks like:
///
/// `{"None": {"password": "my-password"}}`
///
/// or
///
/// `{"Pkcs11": {"key_fingerprint": "hexencodedsha256sum", "password": "-----BEGIN PKCS7-----..." `
#[derive(Debug, Clone, Serialize, Deserialize)]
enum BoundPassword {
    /// No binding was used.
    None { password: String },
    /// Secrets bound by asymmetric keys stored in a device accessible via PKCS#11.
    ///
    /// Secrets of this variant have been encrypted using OpenSSL's CMS interface and the
    /// results are PEM-encoded.
    ///
    /// Examples of key stores include SoftHSMv2 or any HSM that provides a PKCS#11 interface,
    /// Yubikeys via the libykcs11 library, and Trusted Platform Modules (TPMs) via the
    /// libtpm2_pkcs11 library. Creating and managing the key pairs is up to the administrator.
    Pkcs11WithCMS {
        /// The SHA256 digest of the key used in this binding.
        key_fingerprint: String,
        /// The key password that's been encrypted by the public key identified in `key_fingerprint`.
        /// The string contains a PEM-encoded CMS structure.
        password: String,
    },
}

// I think this is the JSON format used by sigul for pkcs11. It'll be a list for most entries,
// but some old ones are dictionaries. Additionally, sigul theoretically supports recursive
// binding but that does appear to actually be used. This structure will be useful for writing
// the migration script later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct SigulPkcs11BoundPassword {
    method: String,
    value: String,
    token: String,
}

/// Decrypt a key password to enable access to the key itself.
pub async fn decrypt_key_password(
    bindings: &[Pkcs11Binding],
    user_password: Password,
    data: &[u8],
) -> anyhow::Result<Password> {
    let key_bindings: Vec<BoundPassword> =
        symmetric_decrypt(user_password, data).map(|data| serde_json::from_slice(&data))??;

    for bound_password in key_bindings {
        match bound_password {
            BoundPassword::None { password } => return Ok(Password::from(password)),
            BoundPassword::Pkcs11WithCMS {
                key_fingerprint,
                password,
            } => {
                for binding in bindings.iter().filter(|binding| binding.can_unbind()) {
                    if let Ok(password) =
                        binding_decrypt(binding.clone(), password.clone().into_bytes())
                            .await
                            .map(Password::from)
                    {
                        return Ok(password);
                    } else {
                        tracing::debug!(
                            public_key = key_fingerprint,
                            key_uri = binding.private_key,
                            "Failed to unbind key password"
                        );
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!("Unable to unbind key password"))
}

/// Encrypt a key password for storage.
pub fn encrypt_key_password(
    bindings: &[Pkcs11Binding],
    user_password: Password,
    key_password: Password,
) -> anyhow::Result<Vec<u8>> {
    let mut bound_passwords = bindings
        .iter()
        .map(|binding| {
            tracing::info!(public_key=?binding.public_key, "Binding key password");
            key_password.map(|key| binding_encrypt(binding, key))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // If no bindings are configured, the key is only encrypted with the user password
    if bound_passwords.is_empty() {
        let none_binding = key_password.map(|p| {
            let password = String::from_utf8(p.to_vec())?;
            Ok::<_, anyhow::Error>(BoundPassword::None { password })
        })?;
        bound_passwords.push(none_binding);
    }

    symmetric_encrypt(
        user_password,
        serde_json::to_vec(&bound_passwords)?.as_slice(),
    )
}

/// Implement a helper for unsigned, symmetrically encrypted data for Sequoia.
struct SymmetricHelper {
    password: Password,
}

// Decrypt exclusively via symmetrically encrypted session keys.
impl DecryptionHelper for SymmetricHelper {
    fn decrypt(
        &mut self,
        _pkesks: &[sequoia_openpgp::packet::PKESK],
        symmetric_session_keys: &[sequoia_openpgp::packet::SKESK],
        _sym_algo: Option<sequoia_openpgp::types::SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(
            Option<sequoia_openpgp::types::SymmetricAlgorithm>,
            &sequoia_openpgp::crypto::SessionKey,
        ) -> bool,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Cert>> {
        for session_key in symmetric_session_keys {
            if session_key
                .decrypt(&self.password)
                .map(|(algorithm, session_key)| decrypt(algorithm, &session_key))
                .unwrap_or(false)
            {
                return Ok(None);
            }
        }
        Err(anyhow::anyhow!("Bad passphrase"))
    }
}

// A no-op verification helper implementation since the data is not expected to be signed.
impl VerificationHelper for SymmetricHelper {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        Ok(vec![])
    }

    fn check(
        &mut self,
        _structure: sequoia_openpgp::parse::stream::MessageStructure<'_>,
    ) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}

/// Encrypts some data with the given [`Password`] using GPG.
///
/// Returns the ASCII-armored, encrypted `key_passphrase`.
fn symmetric_encrypt(password: Password, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut buffer = vec![];
    {
        let message = Armorer::new(Message::new(&mut buffer)).build()?;
        let encryptor = Encryptor::with_passwords(message, Some(password))
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(encryptor).build()?;
        message.write_all(data)?;
        message.finalize()?;
    }

    Ok(buffer)
}

/// Decrypt data using GPG.
///
/// This is the inverse of [`symmetric_encrypt`]. Data is not expected to be signed and signatures are not checked.
fn symmetric_decrypt(password: Password, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let helper = SymmetricHelper { password };
    let mut decryptor = DecryptorBuilder::from_bytes(&data)?.with_policy(&policy, None, helper)?;
    let mut user_passphrase = vec![];
    decryptor.read_to_end(&mut user_passphrase)?;

    Ok(user_passphrase)
}

/// Encrypt some data using a [`Binding`] configuration.
///
/// The options here are primarily chosen because they match Sigul.
fn binding_encrypt(binding: &Pkcs11Binding, data: &[u8]) -> anyhow::Result<BoundPassword> {
    let certificate = std::fs::read_to_string(&binding.public_key)?;
    let certificate = X509::from_pem(certificate.as_bytes())?;
    let mut cert_stack = Stack::new()?;
    cert_stack.push(certificate)?;
    let encrypted = CmsContentInfo::encrypt(
        &cert_stack,
        data,
        Cipher::aes_256_cbc(),
        CMSOptions::empty(),
    )?;
    let pem = encrypted.to_pem()?;
    let certificate = cert_stack.pop().expect("we just pushed a cert");
    let key_fingerprint = format!("{:X?}", &certificate.digest(MessageDigest::sha256())?);
    Ok(BoundPassword::Pkcs11WithCMS {
        key_fingerprint,
        password: String::from_utf8(pem)?,
    })
}

/// Decrypt a bound password using a PIN-protected private key in a PKCS11 token.
async fn binding_decrypt(binding: Pkcs11Binding, data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let output = tokio::task::spawn_blocking(move || {
        let private_key = binding.private_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Binding configuration is missing the 'private_key' field and can't be used to decrypt"
            )
        })?;
        // In the future maybe we'll get openssl provider APIs? Alternatively, if Sequioa gets
        // PKCS#11 support, we could switch to using it in a migration.
        let mut command = std::process::Command::new("openssl");
        let mut child = command
            .args([
                "cms",
                "-decrypt",
                "-inform",
                "pem",
                "-provider",
                "pkcs11",
                "-passin",
                "stdin",
                "-inkey",
            ])
            .arg(private_key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("openssl-cms command missing stdin"))?;

        binding.pin.ok_or_else(||anyhow::anyhow!("Binding must include a PIN"))?.map(|pin| {
            stdin.write_all(pin)
        })?;
        stdin.write_all(b"\n")?;
        stdin.write_all(&data)?;
        drop(stdin);

        let output = child.wait_with_output()?;
        Ok::<_, anyhow::Error>(output)
    }).await??;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to decrypt data via PKCS#11 using openssl-cms (exited {:?}): {stderr}",
            output.status.code()
        ));
    }

    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use anyhow::Result;
    use tempfile::{NamedTempFile, TempDir};

    use super::*;

    // Generated passwords should be base64 encoded and 128 bytes of randomness.
    #[test]
    fn password_len() -> anyhow::Result<()> {
        let password = generate_password()?;
        let string = password.map(|p| String::from_utf8(p.to_vec()))?;
        let bytes = openssl::base64::decode_block(&string)?;
        assert_eq!(128, bytes.len());

        Ok(())
    }
    // Encrypting and then decrypting should give us the key back
    #[test]
    fn encrypt_decrypt() -> Result<()> {
        let user_passphrase = Password::from("this grants a user access to the key passphrase");
        let data = "this encrypts the private key";
        let encrypted_data = symmetric_encrypt(user_passphrase.clone(), data.as_bytes())?;
        let decrypted_data = symmetric_decrypt(user_passphrase, &encrypted_data)?;
        assert_eq!(data.as_bytes(), decrypted_data);
        Ok(())
    }

    // Ensure something encrypted with sq's CLI is decrypted by our implementation
    #[test]
    fn encrypt_with_sq_decrypt() -> Result<()> {
        let user_passphrase = "this grants a user access to the key passphrase".to_string();
        let data = "this encrypts the private key";
        let mut password_file = NamedTempFile::new()?;
        let mut message = NamedTempFile::new()?;
        password_file.write_all(user_passphrase.as_bytes())?;
        message.write_all(data.as_bytes())?;

        let mut command = std::process::Command::new("sq");
        let result = command
            .arg("encrypt")
            .arg(format!(
                "--with-password-file={}",
                password_file.path().display()
            ))
            .arg("--without-signature")
            .arg(message.path())
            .output()?;

        let retrieved_key_passphrase =
            symmetric_decrypt(Password::from(user_passphrase), &result.stdout)?;
        assert_eq!(data.as_bytes(), retrieved_key_passphrase);
        Ok(())
    }

    // Ensure something encrypted with our implementation is decryptable by sq's CLI
    #[test]
    fn encrypt_decrypt_with_sq() -> Result<()> {
        let user_passphrase = "this grants a user access to the key passphrase".to_string();
        let data = "this encrypts the private key";
        let encrypted_passphrase =
            symmetric_encrypt(Password::from(user_passphrase.as_bytes()), data.as_bytes())?;
        let mut password_file = NamedTempFile::new()?;
        let mut encrypted_message = NamedTempFile::new()?;
        password_file.write_all(user_passphrase.as_bytes())?;
        encrypted_message.write_all(&encrypted_passphrase)?;

        let mut command = std::process::Command::new("sq");
        let result = command
            .arg(format!(
                "--password-file={}",
                password_file.path().display()
            ))
            .arg("decrypt")
            .arg(encrypted_message.path())
            .output()?;
        assert_eq!(data.as_bytes(), result.stdout);

        Ok(())
    }

    #[derive(Debug)]
    struct SoftHsm {
        _conf_file: NamedTempFile,
        _directory: TempDir,
        bindings: Vec<Pkcs11Binding>,
    }

    // Set up a temporary SoftHSM token.
    //
    // Note that tests using this must alter their environment which is not thread safe.
    // Thus, you will see failures if you don't use nextest.
    fn setup_softhsm() -> anyhow::Result<SoftHsm> {
        let hsm_dir = TempDir::new()?;
        let softhsm_conf_file = NamedTempFile::new()?;
        let softhsm_conf = format!("directories.tokendir = {}\n", hsm_dir.path().display());
        std::fs::write(&softhsm_conf_file, softhsm_conf)?;
        let possible_softhsm_paths = [
            "/usr/lib64/softhsm/libsofthsm.so",
            "/usr/lib/softhsm/libsofthsm2.so",
        ];
        let mut softhsm_path = "";
        for path in possible_softhsm_paths {
            if std::fs::exists(path)? {
                softhsm_path = path;
                break;
            }
        }

        let mut command = Command::new("softhsm2-util");
        let output = command
            .env("SOFTHSM2_CONF", softhsm_conf_file.path())
            .args([
                "--init-token",
                "--slot=0",
                "--label=test",
                "--pin=secret-password",
                "--so-pin=1234",
            ])
            .output()?;
        if !output.status.success() {
            panic!(
                "Failed to initialize SoftHSM token: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let mut command = Command::new("pkcs11-tool");
        let output = command
            .env("SOFTHSM2_CONF", softhsm_conf_file.path())
            .arg(format!("--module={}", softhsm_path))
            .args([
                "--login",
                "--pin=secret-password",
                "--keypairgen",
                "--label=binding-key",
                "--key-type=rsa:4096",
                "--usage-decrypt",
                "--usage-sign",
                "--id=1",
            ])
            .output()?;
        if !output.status.success() {
            panic!(
                "Failed to create key in SoftHSM token: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let uri = "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;token=test;object=binding-key;id=%01;type=private";

        let cert_file = hsm_dir.path().join("cert0");
        let mut command = Command::new("openssl");
        let output = command
            .env("SOFTHSM2_CONF", softhsm_conf_file.path())
            .args([
                "req",
                "-x509",
                "-provider",
                "pkcs11",
                "-passin",
                "pass:secret-password",
                "-subj",
                "/CN=Test",
            ])
            .arg("-key")
            .arg(uri)
            .arg("-out")
            .arg(&cert_file)
            .output()?;
        if !output.status.success() {
            panic!(
                "Failed to create x509 certificate:  {:?}",
                String::from_utf8_lossy(&output.stderr)
            )
        }

        let mut command = Command::new("pkcs11-tool");
        let output = command
            .env("SOFTHSM2_CONF", softhsm_conf_file.path())
            .arg(format!("--module={}", softhsm_path))
            .args([
                "--login",
                "--pin=secret-password",
                "--type=cert",
                "--label=self-signed-cert",
                "--id=1",
            ])
            .arg(format!("--write-object={}", cert_file.display()))
            .output()?;
        if !output.status.success() {
            panic!(
                "Failed to add cert to SoftHSM token: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let binding = Pkcs11Binding {
            public_key: cert_file,
            private_key: Some(uri.to_string()),
            pin: Some(Password::from("secret-password")),
        };

        // Some other bindings we don't have keys for, but should still encrypt for.
        let mut bindings = vec![binding];
        for n in 1..5 {
            let pubkey_path = hsm_dir.path().join(format!("cert{}", n));
            let key_path = hsm_dir.path().join(format!("cert{}.key", n));
            let mut command = Command::new("openssl");
            command
                .args([
                    "req", "-x509", "-new", "-nodes", "-sha256", "-subj", "/CN=Test", "-days", "5",
                    "-newkey", "rsa:4096", "-keyout",
                ])
                .arg(&key_path)
                .arg("-out")
                .arg(&pubkey_path);
            let output = command.output()?;
            if !output.status.success() {
                panic!(
                    "Failed to create binding cert: {:?}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            bindings.push(Pkcs11Binding {
                public_key: pubkey_path,
                ..Default::default()
            });
        }

        // SAFETY:
        // These tests are required to run with nextest, which starts a new process for each test.
        // Using set_var is only safe if no other code is interacting with the environment variables,
        // which should be true under nextest. Refer to
        // https://nexte.st/docs/configuration/env-vars/#altering-the-environment-within-tests to ensure
        // this remains the case with current versions of Rust.
        //
        // The alternative approach is to use the default config and randomly generate key names, but
        // cleanup isn't as neat. Maybe one day softhsm will allow for config files via arguments.
        unsafe {
            std::env::set_var("SOFTHSM2_CONF", softhsm_conf_file.path());
        }
        Ok(SoftHsm {
            _conf_file: softhsm_conf_file,
            _directory: hsm_dir,
            bindings,
        })
    }

    /// Assert encrypting and then decrypting for bindings works.
    #[tokio::test]
    async fn encrypt_decrypt_binding() -> Result<()> {
        let softhsm = setup_softhsm()?;

        let binding = softhsm.bindings.first().unwrap();
        let bound_password = binding_encrypt(binding, b"some data")?;
        let decrypted_data = match bound_password {
            BoundPassword::None { password: _ } => {
                panic!("We should have encrypted it with a certificate")
            }
            BoundPassword::Pkcs11WithCMS {
                key_fingerprint: _,
                password,
            } => binding_decrypt(binding.to_owned(), password.into_bytes()).await,
        }?;

        assert_eq!(b"some data".as_slice(), decrypted_data);

        Ok(())
    }

    /// Assert the complete encryption/decryption process roundtrips as expected.
    #[tokio::test]
    async fn encrypt_decrypt_key_password() -> Result<()> {
        let softhsm = setup_softhsm()?;

        let key_password = Password::from("a secret that never leaves the server");
        let user_password = Password::from("some long password clients provide");
        let blob = encrypt_key_password(
            &softhsm.bindings,
            user_password.clone(),
            key_password.clone(),
        )?;
        let roundtrip_key_password =
            decrypt_key_password(&softhsm.bindings, user_password, &blob).await?;

        assert_eq!(key_password, roundtrip_key_password);

        Ok(())
    }

    // Assert if no bindings include keys, we get an error
    #[tokio::test]
    async fn encrypt_decrypt_key_password_binding_no_key() -> Result<()> {
        let softhsm = setup_softhsm()?;

        let key_password = Password::from("a secret that never leaves the server");
        let user_password = Password::from("some long password clients provide");
        let blob = encrypt_key_password(
            &softhsm.bindings,
            user_password.clone(),
            key_password.clone(),
        )?;
        let result =
            decrypt_key_password(softhsm.bindings.get(1..).unwrap(), user_password, &blob).await;
        assert!(result.is_err_and(|err| err.to_string().contains("Unable to unbind key password")));

        Ok(())
    }

    // We should get an error if the user password is incorrect
    #[tokio::test]
    async fn encrypt_decrypt_key_password_wrong_user_password() -> Result<()> {
        let softhsm = setup_softhsm()?;

        let key_password = Password::from("a secret that never leaves the server");
        let user_password = Password::from("some long password clients provide");
        let blob = encrypt_key_password(&softhsm.bindings, user_password, key_password.clone())?;
        let user_password = Password::from("the wrong password");
        let result =
            decrypt_key_password(softhsm.bindings.get(1..).unwrap(), user_password, &blob).await;
        assert!(result.is_err_and(|err| err.to_string().contains("Bad passphrase")));

        Ok(())
    }

    // Assert if no bindings are configured, just the user password is sufficient.
    #[tokio::test]
    async fn encrypt_decrypt_key_password_no_bindings() -> Result<()> {
        let key_password = Password::from("a secret that never leaves the server");
        let user_password = Password::from("some long password clients provide");
        let blob = encrypt_key_password(&[], user_password.clone(), key_password.clone())?;
        let roundtrip_key_password = decrypt_key_password(&[], user_password, &blob).await?;
        assert_eq!(key_password, roundtrip_key_password);
        Ok(())
    }
}
