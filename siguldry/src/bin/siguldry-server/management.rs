// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Implements the management commands for the siguldry-server CLI.

use std::path::PathBuf;

use anyhow::Context;
use cryptoki::types::AuthPin;
use rustix::termios::Termios;
use sequoia_openpgp::crypto::Password;
use siguldry::server::{
    Config, Pkcs11Binding,
    crypto::{self, binding::decrypt_key_password},
    db,
};
use tracing::instrument;

use crate::cli::{KeyCommands, ManagementCommands, UserCommands};

pub struct PromptPassword {
    termios: Option<Termios>,
    prompt: String,
}

impl PromptPassword {
    pub fn new(prompt: String) -> anyhow::Result<Self> {
        let stdin = rustix::stdio::stdin();
        let termios = if rustix::termios::isatty(stdin) {
            Some(rustix::termios::tcgetattr(stdin)?)
        } else {
            None
        };

        Ok(Self { termios, prompt })
    }

    pub fn prompt(self) -> anyhow::Result<Password> {
        let stdin = std::io::stdin();
        if let Some(termios) = &self.termios {
            let mut no_echo_termios = termios.clone();
            no_echo_termios.local_modes &= !rustix::termios::LocalModes::ECHO;
            no_echo_termios.local_modes |= rustix::termios::LocalModes::ECHONL;
            rustix::termios::tcsetattr(
                stdin,
                rustix::termios::OptionalActions::Now,
                &no_echo_termios,
            )?;
        }
        println!("{}", self.prompt);
        let password = std::io::stdin()
            .lines()
            .next()
            .expect("Password needs to be supplied")
            .map(Password::from)?;
        Ok(password)
    }
}

impl Drop for PromptPassword {
    fn drop(&mut self) {
        // Do what we can to restore the terminal settings
        let stdin = std::io::stdin();
        if let Some(termios) = &self.termios {
            _ = rustix::termios::tcsetattr(stdin, rustix::termios::OptionalActions::Now, termios);
        }
    }
}

fn password_from_file_or_prompt(
    prompt: &str,
    password_file: Option<PathBuf>,
    length: usize,
) -> anyhow::Result<Password> {
    let user_password = if let Some(password_file) = password_file {
        let password = std::fs::read_to_string(password_file)?;
        password
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("The password file can't be empty"))
            .map(Password::from)
    } else {
        let prompt = PromptPassword::new(prompt.to_string())?;
        prompt.prompt()
    }?;

    let password_length = user_password.map(|p| p.len());
    if length > password_length {
        return Err(anyhow::anyhow!(
            "Password must be {} bytes long (got {})",
            length,
            password_length
        ));
    }
    Ok(user_password)
}

#[instrument(skip_all)]
pub async fn manage(command: ManagementCommands, config: Config) -> anyhow::Result<()> {
    let db_pool = db::pool(
        config
            .database()
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Database path isn't valid UTF8"))?,
        false,
    )
    .await?;

    let mut conn = db_pool.begin().await?;
    match command {
        ManagementCommands::Key(key_commands) => match key_commands {
            KeyCommands::Create {
                algorithm,
                password_file,
                admin,
                name,
                openpgp_profile,
                x509_validity_days,
                x509_common_name,
                x509_ca_key_name,
                x509_ca_cert_name,
                x509_ca_password_file,
                x509_usage,
            } => {
                let x509_validity_days = std::num::NonZeroU32::new(x509_validity_days)
                    .ok_or_else(|| anyhow::anyhow!("X509 validity must be non-zero"))?;

                let user = db::User::get(&mut conn, &admin).await?;
                let prompt = format!(
                    "Enter a password to access the key (at least {} bytes): ",
                    config.user_password_length.get()
                );
                let user_password = password_from_file_or_prompt(
                    &prompt,
                    password_file,
                    config.user_password_length.get() as usize,
                )?;

                let x509_ca = if let Some(x509_ca) = x509_ca_key_name {
                    // todo user should also provide the cert name
                    let ca_key = db::Key::get(&mut conn, &x509_ca)
                        .await
                        .context("No key found for specified certificate authority")?;
                    let key_access = db::KeyAccess::get(&mut conn, &ca_key, &user)
                        .await
                        .context("User doesn't have access to the signing key")?;
                    let mut certs = db::PublicKeyMaterial::list(
                        &mut conn,
                        &ca_key,
                        db::PublicKeyMaterialType::X509,
                    )
                    .await?;

                    let cert = if let Some(ca_cert_name) = x509_ca_cert_name {
                        certs.into_iter().find(|c| c.name == ca_cert_name).ok_or_else(|| {
                            anyhow::anyhow!("No x509 certificate found for CA {x509_ca} with name {ca_cert_name}")
                        })?
                    } else {
                        certs.pop().ok_or_else(|| {
                            anyhow::anyhow!("No x509 certificate found for CA {x509_ca}")
                        })?
                    };

                    let mut pkcs11_bindings = config
                        .pkcs11_bindings
                        .iter()
                        .filter(|b| b.private_key.is_some())
                        .cloned()
                        .collect::<Vec<_>>();
                    for binding in pkcs11_bindings.iter_mut() {
                        let prompt = PromptPassword::new(format!(
                            "Please enter the user PIN for {}:",
                            &binding
                                .private_key
                                .as_ref()
                                .expect("filter for bindings with private key URIs")
                        ))?;
                        let pin = prompt.prompt()?;
                        binding.pin = Some(pin);
                    }
                    let prompt = format!("Enter the password to access the CA key {x509_ca}: ",);
                    let user_password =
                        password_from_file_or_prompt(&prompt, x509_ca_password_file, 0)?;
                    let key_password = decrypt_key_password(
                        &pkcs11_bindings,
                        user_password,
                        &key_access.encrypted_passphrase,
                    )
                    .await?;

                    Some((ca_key, key_password, cert))
                } else {
                    None
                };

                let encrypted_key = crypto::create_encrypted_key(
                    &config,
                    user_password,
                    algorithm,
                    openpgp_profile.into(),
                    x509_usage,
                    x509_common_name.unwrap_or_else(|| name.clone()),
                    x509_validity_days,
                    x509_ca,
                )?;
                let key = db::Key::create(
                    &mut conn,
                    &name,
                    &encrypted_key.handle,
                    algorithm,
                    &encrypted_key.private_key_pem,
                    &encrypted_key.public_key_pem,
                    None,
                    None,
                )
                .await?;
                db::KeyAccess::create(
                    &mut conn,
                    &key,
                    &user,
                    encrypted_key.encrypted_password,
                    true,
                )
                .await?;
                db::PublicKeyMaterial::create(
                    &mut conn,
                    &key,
                    format!("{}-x509", &name),
                    db::PublicKeyMaterialType::X509,
                    encrypted_key.x509_certificate,
                )
                .await?;
                db::PublicKeyMaterial::create(
                    &mut conn,
                    &key,
                    format!("{}-openpgp", &name),
                    db::PublicKeyMaterialType::OpenPgpCert,
                    encrypted_key.openpgp_certificate,
                )
                .await?;
            }
            KeyCommands::X509 {
                user_name,
                key_name,
                usage,
                common_name,
                validity_days,
                certificate_authority,
                ca_password_file,
            } => {
                let key = db::Key::get(&mut conn, &key_name)
                    .await
                    .context("No key with the specified name found")?;
                let user = db::User::get(&mut conn, &user_name)
                    .await
                    .context("The user doesn't exist")?;
                let (key_access, certificate_authority) = if let Some(ca) = certificate_authority {
                    let ca_key = db::Key::get(&mut conn, &ca)
                        .await
                        .context("No key found for specified certificate authority")?;
                    let key_access = db::KeyAccess::get(&mut conn, &ca_key, &user)
                        .await
                        .context("User doesn't have access to the signing key")?;
                    let mut certs = db::PublicKeyMaterial::list(
                        &mut conn,
                        &ca_key,
                        db::PublicKeyMaterialType::X509,
                    )
                    .await?;
                    let cert = certs
                        .pop()
                        .ok_or_else(|| anyhow::anyhow!("No x509 certificate found for CA {ca}"))?;
                    (key_access, Some((ca_key, cert)))
                } else {
                    let key_access = db::KeyAccess::get(&mut conn, &key, &user)
                        .await
                        .context("User doesn't have access to the signing key")?;
                    (key_access, None)
                };

                let mut pkcs11_bindings = config
                    .pkcs11_bindings
                    .iter()
                    .filter(|b| b.private_key.is_some())
                    .cloned()
                    .collect::<Vec<_>>();
                for binding in pkcs11_bindings.iter_mut() {
                    let prompt = PromptPassword::new(format!(
                        "Please enter the user PIN for {}:",
                        &binding
                            .private_key
                            .as_ref()
                            .expect("filter for bindings with private key URIs")
                    ))?;
                    let pin = prompt.prompt()?;
                    binding.pin = Some(pin);
                }
                let prompt = format!(
                    "Enter a password to access the key (at least {} bytes): ",
                    config.user_password_length.get()
                );
                let user_password = password_from_file_or_prompt(&prompt, ca_password_file, 0)?;
                let key_password = decrypt_key_password(
                    &pkcs11_bindings,
                    user_password,
                    &key_access.encrypted_passphrase,
                )
                .await?;

                let certificate = crypto::x509_certificate_for_key(
                    key.clone(),
                    certificate_authority,
                    key_password,
                    &config.certificate_subject,
                    usage,
                    &common_name,
                    validity_days,
                )?;

                let cert = db::PublicKeyMaterial::create(
                    &mut conn,
                    &key,
                    common_name,
                    db::PublicKeyMaterialType::X509,
                    certificate,
                )
                .await?;
                println!("Successfully signed certificate:\n{}", cert.data);
            }
            KeyCommands::List {} => {
                for key in db::Key::list(&mut conn).await? {
                    println!("{key}");
                }
            }
        },
        ManagementCommands::Users(user_commands) => match user_commands {
            UserCommands::Create { name } => {
                println!(
                    "Successfully created user '{}'",
                    db::User::create(&mut conn, &name).await?
                );
            }
            UserCommands::Delete { name } => {
                println!(
                    "Deleted {} user(s) from the database",
                    db::User::delete(&mut conn, &name).await?
                );
            }
            UserCommands::List {} => {
                for user in db::User::list(&mut conn).await? {
                    println!("{user}");
                }
            }
        },
        ManagementCommands::Pkcs11(pkcs11_commands) => match pkcs11_commands {
            crate::cli::Pkcs11Commands::Register {
                module,
                user_pin,
                password_file,
                slot_id,
                admin,
            } => {
                let user = db::User::get(&mut conn, &admin)
                    .await
                    .context("Specified admin user doesn't exist")?;
                let (key_password, token_user_pin) = if let Some(user_pin) = user_pin {
                    let password_content = std::fs::read_to_string(user_pin)?;
                    let password = password_content
                        .lines()
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("The user PIN file can't be empty"))?;
                    (Password::from(password), AuthPin::new(password.into()))
                } else {
                    let prompt = PromptPassword::new(
                        "Enter the user PIN to log into the PKCS#11 token: ".to_string(),
                    )?;
                    let password = prompt.prompt()?;
                    let token_user_pin = password.map(|password| {
                        AuthPin::new(
                            String::from_utf8(password.to_vec())
                                .expect("user PIN should be UTF-8 encoded")
                                .into(),
                        )
                    });
                    (password, token_user_pin)
                };
                let user_password = if let Some(password_file) = password_file {
                    let password = std::fs::read_to_string(password_file)?;
                    password
                        .lines()
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("The password file can't be empty"))
                        .map(Password::from)
                } else {
                    let prompt = PromptPassword::new(format!(
                        "Enter a password to access the key (at least {} bytes): ",
                        config.user_password_length.get()
                    ))?;
                    prompt.prompt()
                }?;
                let encrypted_passphrase = crypto::binding::encrypt_key_password(
                    &config.pkcs11_bindings,
                    user_password,
                    key_password,
                )
                .context("Failed to bind password")?;

                let token =
                    crypto::token::import_pkcs11_token(&mut conn, module, slot_id, token_user_pin)
                        .await
                        .context("Failed to import PKCS #11 token")?;
                let keys = db::Key::get_token_keys(&mut conn, &token).await?;
                for key in keys {
                    db::KeyAccess::create(
                        &mut conn,
                        &key,
                        &user,
                        encrypted_passphrase.clone(),
                        true,
                    )
                    .await?;
                    let certs = db::PublicKeyMaterial::list(
                        &mut conn,
                        &key,
                        db::PublicKeyMaterialType::X509,
                    )
                    .await?;
                    println!(
                        "Imported key {} with {} X509 certificate(s) associated with it",
                        key,
                        certs.len()
                    );
                }
            }
        },
        ManagementCommands::Migrate {} => db::migrate(&db_pool).await?,
        ManagementCommands::ImportSigul {
            sigul_data_directory,
            binding_uri,
        } => {
            let sigul_binding = if let Some(binding_uri) = binding_uri {
                let pin =
                    PromptPassword::new(format!("Please enter the user PIN for {binding_uri}:"))?
                        .prompt()?;
                Some(Pkcs11Binding {
                    certificate: PathBuf::new(),
                    private_key: Some(binding_uri),
                    pin: Some(pin),
                })
            } else {
                None
            };
            crate::import_sigul::migrate_sigul(
                &mut conn,
                &config.pkcs11_bindings,
                sigul_data_directory,
                sigul_binding,
            )
            .await?;
        }
    }
    conn.commit().await?;

    Ok(())
}

// Test various success/error paths for the CLI management commands
// In the future, there should be some end-to-end tests to check inputs/outputs.
#[cfg(test)]
mod tests {
    use std::{num::NonZeroU16, path::PathBuf, process::Command};

    use anyhow::Result;
    use cryptoki::{
        context::{CInitializeArgs, CInitializeFlags, Pkcs11},
        mechanism::Mechanism,
        object::Attribute,
        session::UserType,
        types::AuthPin,
    };
    use sequoia_openpgp::crypto::Password;
    use siguldry::{
        protocol::KeyAlgorithm,
        server::{Config, crypto::KeyUsage, db},
    };
    use tempfile::TempDir;

    use crate::cli::{
        KeyCommands, ManagementCommands, OpenPgpProfile, Pkcs11Commands, UserCommands,
    };

    use super::manage;

    /// Test configuration builder for management tests.
    struct TestConfig {
        temp_dir: TempDir,
        config: Config,
        module_path: String,
        user_pin: String,
    }

    impl TestConfig {
        /// Create a new test configuration with a temporary directory.
        async fn new(with_hsm: bool) -> Result<Self> {
            let temp_dir = TempDir::new()?;
            let config = Config {
                state_directory: temp_dir.path().to_path_buf(),
                bridge_hostname: "localhost".to_string(),
                bridge_port: 44333,
                connection_pool_size: 1,
                user_password_length: NonZeroU16::new(8).unwrap(),
                pkcs11_bindings: vec![],
                ..Default::default()
            };
            let module_path = "/usr/lib64/pkcs11/libkryoptic_pkcs11.so";
            let user_pin = "secret-password";
            if with_hsm {
                Self::setup_hsm(&temp_dir, module_path, user_pin).await?;
            }

            Ok(Self {
                temp_dir,
                config,
                module_path: module_path.to_string(),
                user_pin: user_pin.to_string(),
            })
        }

        async fn setup_hsm(temp_dir: &TempDir, module_path: &str, user_pin: &str) -> Result<()> {
            let hsm_config_path = temp_dir.path().join("kryoptic.toml");
            let hsm_db_path = temp_dir.path().join("kryoptic.sql");

            std::fs::write(
                &hsm_config_path,
                format!(
                    "[[slots]]\nslot = 1\ndbtype = \"sqlite\"\ndbargs = \"{}\"",
                    hsm_db_path.display()
                ),
            )?;

            // SAFETY: Tests must run with nextest (one process per test)
            unsafe {
                std::env::set_var("KRYOPTIC_CONF", &hsm_config_path);
                std::env::set_var("PKCS11_PROVIDER_MODULE", module_path);
            }

            let pkcs11 = Pkcs11::new(module_path)
                .map_err(|_| anyhow::anyhow!("Install the kryoptic PKCS#11 module"))?;
            pkcs11
                .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .map_err(|e| anyhow::anyhow!("Failed to initialize kryoptic: {}", e))?;

            let slot = pkcs11
                .get_slots_with_token()?
                .pop()
                .ok_or_else(|| anyhow::anyhow!("No slot available"))?;

            let so_pin = AuthPin::new("12345678".into());
            let user_pin = AuthPin::new(user_pin.into());

            pkcs11.init_token(slot, &so_pin, "test-token")?;
            pkcs11.open_rw_session(slot).and_then(|session| {
                session.login(UserType::So, Some(&so_pin))?;
                session.init_pin(&user_pin)?;

                // Create an RSA key pair
                session.generate_key_pair(
                    &Mechanism::RsaPkcsKeyPairGen,
                    &[
                        Attribute::Id(vec![1]),
                        Attribute::Label(b"test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::Verify(true),
                        Attribute::Encrypt(true),
                        Attribute::ModulusBits(4096.into()),
                    ],
                    &[
                        Attribute::Id(vec![1]),
                        Attribute::Label(b"test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                        Attribute::Decrypt(true),
                    ],
                )?;

                // Annoyingly it doesn't seem possible to convert a named curve Nid to ASN.1 in
                // OpenSSL, so we manually create it from the OID for NIST P-256.
                let p256_oid = asn1::oid!(1, 2, 840, 10045, 3, 1, 7);
                let p256_oid_bytes = asn1::write_single(&p256_oid).unwrap();
                session.generate_key_pair(
                    &Mechanism::EccKeyPairGen,
                    &[
                        Attribute::Id(vec![2]),
                        Attribute::Label(b"ec-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::EcParams(p256_oid_bytes),
                        Attribute::Verify(true),
                    ],
                    &[
                        Attribute::Id(vec![2]),
                        Attribute::Label(b"ec-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                    ],
                )
            })?;
            pkcs11.finalize()?;

            let rsa_key_uri = "pkcs11:model=v1;manufacturer=Kryoptic%20Project;token=test-token;id=%01;object=test-key;type=private";
            let cert_file = temp_dir.path().join("cert.pem");
            let output = Command::new("openssl")
                .env("KRYOPTIC_CONF", &hsm_config_path)
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
                .arg(rsa_key_uri)
                .arg("-out")
                .arg(&cert_file)
                .output()?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to create x509 certificate: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            let output = Command::new("pkcs11-tool")
                .env("KRYOPTIC_CONF", &hsm_config_path)
                .arg(format!("--module={}", module_path))
                .args([
                    "--login",
                    "--pin=secret-password",
                    "--type=cert",
                    "--label=test-cert",
                    "--id=1",
                ])
                .arg(format!("--write-object={}", cert_file.display()))
                .output()?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to add cert to token: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            Ok(())
        }

        /// Run database migrations to set up the schema.
        async fn migrate(&self) -> Result<()> {
            manage(ManagementCommands::Migrate {}, self.config.clone()).await
        }

        /// Create a user in the database.
        async fn create_user(&self, name: &str) -> Result<()> {
            manage(
                ManagementCommands::Users(UserCommands::Create {
                    name: name.to_string(),
                }),
                self.config.clone(),
            )
            .await
        }

        fn config(&self) -> &Config {
            &self.config
        }
    }

    #[tokio::test]
    async fn user_create_and_delete() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;

        test.create_user("delete-me").await?;
        manage(
            ManagementCommands::Users(UserCommands::Delete {
                name: "delete-me".to_string(),
            }),
            test.config().clone(),
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn user_delete_nonexistent() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;

        // TODO: should this return non-zero?
        manage(
            ManagementCommands::Users(UserCommands::Delete {
                name: "nonexistent".to_string(),
            }),
            test.config().clone(),
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn user_create_duplicate_fails() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("duplicate-user").await?;

        let result = test.create_user("duplicate-user").await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn key_create_rsa4k() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("key-admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "secret-password\n")?;

        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some(password_file),
                admin: "key-admin".to_string(),
                name: "test-rsa-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            test.config().clone(),
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn key_create_p256() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("ec-admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "secret-password\n")?;

        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::P256,
                password_file: Some(password_file),
                admin: "ec-admin".to_string(),
                name: "test-ec-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            test.config().clone(),
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn key_create_password_too_short() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("key-admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "short\n")?;

        let result = manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some(password_file),
                admin: "key-admin".to_string(),
                name: "test-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            test.config().clone(),
        )
        .await;

        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn key_create_nonexistent_admin() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "secret-password\n")?;

        let result = manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some(password_file),
                admin: "nonexistent-user".to_string(),
                name: "test-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            test.config().clone(),
        )
        .await;

        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn x509_self_signed_ca() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "secret-password\n")?;

        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some(password_file.clone()),
                admin: "admin".to_string(),
                name: "ca-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            test.config().clone(),
        )
        .await?;
        manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "ca-key".to_string(),
                usage: KeyUsage::CertificateAuthority,
                common_name: "Test CA".to_string(),
                validity_days: std::num::NonZeroU32::new(30).unwrap(),
                certificate_authority: None,
                ca_password_file: Some(password_file),
            }),
            test.config().clone(),
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn x509_ca_signed_codesigning() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;

        let ca_password_file = test.temp_dir.path().join("ca_password");
        std::fs::write(&ca_password_file, "ca-password\n")?;

        let key_password_file = test.temp_dir.path().join("key_password");
        std::fs::write(&key_password_file, "key-password\n")?;

        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some(ca_password_file.clone()),
                admin: "admin".to_string(),
                name: "ca-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            test.config().clone(),
        )
        .await?;
        manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "ca-key".to_string(),
                usage: KeyUsage::CertificateAuthority,
                common_name: "Test CA".to_string(),
                validity_days: std::num::NonZeroU32::new(365).unwrap(),
                certificate_authority: None,
                ca_password_file: Some(ca_password_file.clone()),
            }),
            test.config().clone(),
        )
        .await?;

        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some(key_password_file),
                admin: "admin".to_string(),
                name: "codesigning-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            test.config().clone(),
        )
        .await?;
        manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "codesigning-key".to_string(),
                usage: KeyUsage::CodeSigning,
                common_name: "Test Code Signing".to_string(),
                validity_days: std::num::NonZeroU32::new(30).unwrap(),
                certificate_authority: Some("ca-key".to_string()),
                ca_password_file: Some(ca_password_file),
            }),
            test.config().clone(),
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn x509_wrong_password_fails() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "correct-password\n")?;
        let wrong_password_file = test.temp_dir.path().join("wrong_password");
        std::fs::write(&wrong_password_file, "wrong-password\n")?;

        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some(password_file),
                admin: "admin".to_string(),
                name: "test-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            test.config().clone(),
        )
        .await?;
        let result = manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "test-key".to_string(),
                usage: KeyUsage::CertificateAuthority,
                common_name: "Test".to_string(),
                validity_days: std::num::NonZeroU32::new(30).unwrap(),
                certificate_authority: None,
                ca_password_file: Some(wrong_password_file),
            }),
            test.config().clone(),
        )
        .await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn x509_nonexistent_ca_fails() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "secret-password\n")?;

        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some(password_file.clone()),
                admin: "admin".to_string(),
                name: "test-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            test.config().clone(),
        )
        .await?;
        let result = manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "test-key".to_string(),
                usage: KeyUsage::CodeSigning,
                common_name: "Test".to_string(),
                validity_days: std::num::NonZeroU32::new(30).unwrap(),
                certificate_authority: Some("nonexistent-ca".to_string()),
                ca_password_file: Some(password_file),
            }),
            test.config().clone(),
        )
        .await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn migrate_creates_database() -> Result<()> {
        let test = TestConfig::new(false).await?;

        let db_path = test.config().database();
        assert!(!db_path.exists());
        manage(ManagementCommands::Migrate {}, test.config().clone()).await?;
        assert!(db_path.exists());

        Ok(())
    }

    #[tokio::test]
    async fn migrate_is_idempotent() -> Result<()> {
        let test = TestConfig::new(false).await?;

        manage(ManagementCommands::Migrate {}, test.config().clone()).await?;
        manage(ManagementCommands::Migrate {}, test.config().clone()).await?;

        Ok(())
    }

    #[tokio::test]
    async fn pkcs11_register_token() -> Result<()> {
        let test = TestConfig::new(true).await?;

        test.migrate().await?;
        test.create_user("token-admin").await?;

        let user_pin_file = test.temp_dir.path().join("user_pin");
        std::fs::write(&user_pin_file, format!("{}\n", test.user_pin))?;
        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "key-access-password\n")?;

        manage(
            ManagementCommands::Pkcs11(Pkcs11Commands::Register {
                module: test.module_path.clone().into(),
                user_pin: Some(user_pin_file),
                password_file: Some(password_file),
                slot_id: None,
                admin: "token-admin".to_string(),
            }),
            test.config().clone(),
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn pkcs11_register_nonexistent_admin() -> Result<()> {
        let test = TestConfig::new(true).await?;
        test.migrate().await?;

        let user_pin_file = test.temp_dir.path().join("user_pin");
        std::fs::write(&user_pin_file, format!("{}\n", test.user_pin))?;
        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "key-access-password\n")?;

        let result = manage(
            ManagementCommands::Pkcs11(Pkcs11Commands::Register {
                module: test.module_path.clone().into(),
                user_pin: Some(user_pin_file),
                password_file: Some(password_file),
                slot_id: None,
                admin: "nonexistent-admin".to_string(),
            }),
            test.config().clone(),
        )
        .await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn pkcs11_register_wrong_pin() -> Result<()> {
        let test = TestConfig::new(true).await?;

        test.migrate().await?;
        test.create_user("token-admin").await?;

        let user_pin_file = test.temp_dir.path().join("user_pin");
        std::fs::write(&user_pin_file, "wrong-pin\n")?;
        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "key-access-password\n")?;

        let result = manage(
            ManagementCommands::Pkcs11(Pkcs11Commands::Register {
                module: test.module_path.clone().into(),
                user_pin: Some(user_pin_file),
                password_file: Some(password_file),
                slot_id: None,
                admin: "token-admin".to_string(),
            }),
            test.config().clone(),
        )
        .await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn pkcs11_register_invalid_module() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;

        let user_pin_file = test.temp_dir.path().join("user_pin");
        std::fs::write(&user_pin_file, "pin\n")?;
        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "password\n")?;

        let result = manage(
            ManagementCommands::Pkcs11(Pkcs11Commands::Register {
                module: "/path/does/not/exist/module.so".into(),
                user_pin: Some(user_pin_file),
                password_file: Some(password_file),
                slot_id: None,
                admin: "admin".to_string(),
            }),
            test.config().clone(),
        )
        .await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn password_file_empty() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "password\n")?;
        let empty_password_file = test.temp_dir.path().join("password");
        std::fs::write(&empty_password_file, "")?;

        let commands = [
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some("/path/does/not/exist".into()),
                admin: "admin".to_string(),
                name: "test-rsa-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            ManagementCommands::Pkcs11(Pkcs11Commands::Register {
                module: PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so"),
                user_pin: Some(empty_password_file.clone()),
                password_file: Some(password_file.clone()),
                slot_id: None,
                admin: "admin".to_string(),
            }),
            ManagementCommands::Pkcs11(Pkcs11Commands::Register {
                module: PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so"),
                user_pin: Some(password_file.clone()),
                password_file: Some(empty_password_file.clone()),
                slot_id: None,
                admin: "admin".to_string(),
            }),
        ];

        for command in commands {
            let result = manage(command, test.config().clone()).await;
            assert!(result.is_err());
        }

        Ok(())
    }

    #[tokio::test]
    async fn password_file_doesnt_exist() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;
        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "password\n")?;

        let commands = [
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                password_file: Some("/path/does/not/exist".into()),
                admin: "admin".to_string(),
                name: "test-rsa-key".to_string(),
                openpgp_profile: OpenPgpProfile::RFC4880,
                x509_validity_days: 42,
                x509_common_name: None,
                x509_ca_key_name: None,
                x509_ca_cert_name: None,
                x509_ca_password_file: None,
                x509_usage: KeyUsage::CodeSigning,
            }),
            ManagementCommands::Pkcs11(Pkcs11Commands::Register {
                module: PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so"),
                user_pin: Some(password_file.clone()),
                password_file: Some("/path/does/not/exist".into()),
                slot_id: None,
                admin: "admin".to_string(),
            }),
            ManagementCommands::Pkcs11(Pkcs11Commands::Register {
                module: PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so"),
                user_pin: Some("/path/does/not/exist".into()),
                password_file: Some(password_file.clone()),
                slot_id: None,
                admin: "admin".to_string(),
            }),
        ];

        for command in commands {
            let result = manage(command, test.config().clone()).await;
            assert!(result.is_err());
        }

        Ok(())
    }

    #[tokio::test]
    async fn password_file_multiline_uses_first_line() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(
            &password_file,
            "first-line-password\nsecond-line\nthird-line\n",
        )?;

        let commands = [ManagementCommands::Key(KeyCommands::Create {
            algorithm: KeyAlgorithm::Rsa4K,
            password_file: Some(password_file.clone()),
            admin: "admin".to_string(),
            name: "test-rsa-key".to_string(),
            openpgp_profile: OpenPgpProfile::RFC4880,
            x509_validity_days: 42,
            x509_common_name: None,
            x509_ca_key_name: None,
            x509_ca_cert_name: None,
            x509_ca_password_file: None,
            x509_usage: KeyUsage::CodeSigning,
        })];

        for command in commands {
            manage(command, test.config().clone()).await?;
        }
        let pool = db::pool(test.config().database().as_os_str().to_str().unwrap(), true).await?;
        let mut conn = pool.begin().await?;
        let user = db::User::get(&mut conn, "admin").await?;
        for key in db::Key::list(&mut conn).await? {
            let key_access = db::KeyAccess::get(&mut conn, &key, &user).await?;
            let result = siguldry::server::crypto::binding::decrypt_key_password(
                &test.config().pkcs11_bindings,
                Password::from("first-line-password\nsecond-line\nthird-line\n"),
                &key_access.encrypted_passphrase,
            )
            .await;
            assert!(result.is_err());
            let _ = siguldry::server::crypto::binding::decrypt_key_password(
                &test.config().pkcs11_bindings,
                Password::from("first-line-password"),
                &key_access.encrypted_passphrase,
            )
            .await?;
        }

        Ok(())
    }
}
