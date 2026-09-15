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

/// Set the binding pin for the available private key.
///
/// If no bindings are configured, this is a no-op.
fn set_binding_pin(config: &mut Config, pin_file: Option<PathBuf>) -> anyhow::Result<()> {
    let binding_count = config
        .pkcs11_bindings
        .iter()
        .filter(|binding| binding.private_key.is_some())
        .count();

    if pin_file.is_some() && binding_count > 1 {
        // We could try the pin for all configured private keys, but that's dangerous since tokens usually lock up after
        // a certain number of incorrect guesses.
        return Err(anyhow::anyhow!(
            "You can't provide a PIN via file with more than one binding private key configured"
        ));
    }

    for binding in config
        .pkcs11_bindings
        .iter_mut()
        .filter(|binding| binding.private_key.is_some())
    {
        let prompt = format!(
            "Please enter the user PIN for {}:",
            binding
                .private_key
                .as_ref()
                .expect("filter for bindings with private key URIs")
        );
        let binding_pin = password_from_file_or_prompt(&prompt, pin_file.clone(), 0)?;

        if binding_pin.map(|p| !p.is_empty()) {
            binding.pin = Some(binding_pin);
        } else {
            eprintln!("Skipping key as empty password was provided");
        }
    }

    Ok(())
}

#[instrument(skip_all)]
pub async fn manage(command: ManagementCommands, mut config: Config) -> anyhow::Result<()> {
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
                x509_options,
                openpgp_options,
                openpgp_hybrid_pair,
            } => {
                // Lots of wonky error handling for OpenPGP hybrid keys.
                let hybrid_pair_algorithm = if openpgp_hybrid_pair {
                    Some(algorithm.openpgp_hybrid_pair_algorithm().ok_or_else(|| anyhow::anyhow!("Keys using {} cannot be part of an OpenPGP hybrid pair (see RFC 9980 for valid combinations)", algorithm))?)
                } else {
                    None
                };
                if openpgp_hybrid_pair && x509_options.x509_cert_name.is_some() {
                    return Err(anyhow::anyhow!(
                        "X.509 certificates for OpenPGP hybrid pairs must be done after creation on a per-key basis"
                    ));
                }

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

                let x509_params = if x509_options.x509_cert_name.is_some() {
                    Some(crypto::X509CertificateParameters {
                        usage: x509_options.x509_usage,
                        common_name: x509_options
                            .x509_common_name
                            .clone()
                            .unwrap_or_else(|| name.clone()),
                        validity_days: x509_options.x509_validity_days,
                    })
                } else {
                    None
                };

                let openpgp_params = match (
                    openpgp_options.openpgp_cert_name.as_ref(),
                    openpgp_options.openpgp_user_id.as_ref(),
                ) {
                    (Some(_), Some(user_id)) => Some(crypto::OpenPgpCertificateParameters {
                        user_id: user_id.clone().into(),
                        profile: openpgp_options.openpgp_profile.into(),
                        hash_algorithm: openpgp_options.openpgp_hash_algorithm.into(),
                        validity_days: openpgp_options.openpgp_validity_days,
                    }),
                    (Some(_), None) => {
                        return Err(anyhow::anyhow!(
                            "An OpenPGP user ID is required to create a certificate"
                        ));
                    }
                    (None, _) => None,
                };
                let (encrypted_key, hybrid_encrypted_key) = crypto::create_encrypted_key(
                    &config,
                    user_password,
                    algorithm,
                    hybrid_pair_algorithm,
                    x509_params,
                    openpgp_params,
                )?;
                let key = db::Key::create(
                    &mut conn,
                    &name,
                    &encrypted_key.handle,
                    algorithm,
                    Some(&encrypted_key.key_material),
                    &encrypted_key.public_key_pem,
                    None,
                    None,
                )
                .await?;
                if let Some(certificate) = encrypted_key.x509_certificate {
                    db::PublicKeyMaterial::create(
                        &mut conn,
                        &key,
                        x509_options
                            .x509_cert_name
                            .expect("X.509 certificate generation requires a name"),
                        db::PublicKeyMaterialType::X509,
                        certificate,
                    )
                    .await?;
                }
                if let Some(certificate) = encrypted_key.openpgp_certificate {
                    db::PublicKeyMaterial::create(
                        &mut conn,
                        &key,
                        openpgp_options
                            .openpgp_cert_name
                            .clone()
                            .expect("OpenPGP certificate generation requires a name"),
                        db::PublicKeyMaterialType::OpenPgpCert,
                        certificate,
                    )
                    .await?;
                }
                db::KeyAccess::create(
                    &mut conn,
                    &key,
                    &user,
                    encrypted_key.encrypted_password,
                    true,
                )
                .await?;

                if let (Some(hybrid_encrypted_key), Some(algorithm)) =
                    (hybrid_encrypted_key, hybrid_pair_algorithm)
                {
                    let hybrid_key = db::Key::create(
                        &mut conn,
                        format!("{name}-{}", algorithm.as_str()).as_str(),
                        &hybrid_encrypted_key.handle,
                        algorithm,
                        Some(&hybrid_encrypted_key.key_material),
                        &hybrid_encrypted_key.public_key_pem,
                        None,
                        None,
                    )
                    .await?;
                    db::KeyAccess::create(
                        &mut conn,
                        &hybrid_key,
                        &user,
                        hybrid_encrypted_key.encrypted_password,
                        true,
                    )
                    .await?;
                    if let Some(certificate) = hybrid_encrypted_key.openpgp_certificate {
                        db::PublicKeyMaterial::create(
                            &mut conn,
                            &hybrid_key,
                            openpgp_options
                                .openpgp_cert_name
                                .expect("OpenPGP certificate generation requires a name"),
                            db::PublicKeyMaterialType::OpenPgpCert,
                            certificate,
                        )
                        .await?;
                    }
                    let result = key.associate_hybrid(&mut conn, &hybrid_key).await?;
                    if result.rows_affected() != 1 {
                        return Err(anyhow::anyhow!(
                            "An unexpected number of database rows ({}) were affected by the update",
                            result.rows_affected()
                        ));
                    }
                }
            }
            KeyCommands::X509 {
                user_name,
                key_name,
                x509_options,
                ca_key_name,
                ca_cert_name,
                ca_password_file,
                pkcs11_binding_pin,
            } => {
                let key = db::Key::get(&mut conn, &key_name)
                    .await
                    .context("No key with the specified name found")?;
                let user = db::User::get(&mut conn, &user_name)
                    .await
                    .context("The user doesn't exist")?;
                let cert_name = x509_options
                    .x509_cert_name
                    .ok_or_else(|| anyhow::anyhow!("An X.509 certificate name is required"))?;
                let common_name = x509_options
                    .x509_common_name
                    .unwrap_or_else(|| key.name.clone());

                let (key_access, certificate_authority) = if let Some(ca) = ca_key_name {
                    let ca_key = db::Key::get(&mut conn, &ca)
                        .await
                        .context("No key found for specified certificate authority")?;
                    let key_access = db::KeyAccess::get(&mut conn, &ca_key, &user)
                        .await
                        .with_context(|| format!("User doesn't have access to the certificate authority signing key {}", ca_key.name))?;
                    let mut certs = db::PublicKeyMaterial::list(
                        &mut conn,
                        &ca_key,
                        db::PublicKeyMaterialType::X509,
                    )
                    .await?;
                    let cert = if let Some(ca_cert_name) = ca_cert_name {
                        certs
                            .into_iter()
                            .find(|cert| cert.name == ca_cert_name)
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "No x509 certificate found for CA {ca} with name {ca_cert_name}"
                                )
                            })?
                    } else {
                        certs.pop().ok_or_else(|| {
                            anyhow::anyhow!("No x509 certificate found for CA {ca}")
                        })?
                    };
                    (key_access, Some((ca_key, cert)))
                } else {
                    let key_access = db::KeyAccess::get(&mut conn, &key, &user)
                        .await
                        .with_context(|| {
                            format!(
                                "User doesn't have access to the key {} for a self-signature",
                                key.name
                            )
                        })?;
                    (key_access, None)
                };

                set_binding_pin(&mut config, pkcs11_binding_pin)?;
                let user_password = password_from_file_or_prompt(
                    "Enter the password to access the signing key: ",
                    ca_password_file,
                    0,
                )?;
                let key_password = decrypt_key_password(
                    &config.pkcs11_bindings,
                    user_password,
                    &key_access.encrypted_passphrase,
                )
                .await?;

                let certificate = crypto::x509_certificate_for_key(
                    &config,
                    key.clone(),
                    certificate_authority,
                    key_password,
                    x509_options.x509_usage,
                    &common_name,
                    x509_options.x509_validity_days,
                )?;

                let cert = db::PublicKeyMaterial::create(
                    &mut conn,
                    &key,
                    cert_name,
                    db::PublicKeyMaterialType::X509,
                    certificate,
                )
                .await?;
                println!("Successfully signed certificate:\n{}", cert.data);
            }
            KeyCommands::Openpgp {
                user_name,
                key_name,
                password_file,
                pkcs11_binding_pin,
                openpgp_options,
            } => {
                let key = db::Key::get(&mut conn, &key_name)
                    .await
                    .context("No key with the specified name found")?;
                let user = db::User::get(&mut conn, &user_name)
                    .await
                    .context("The user doesn't exist")?;
                let cert_name = openpgp_options
                    .openpgp_cert_name
                    .ok_or_else(|| anyhow::anyhow!("An OpenPGP certificate name is required"))?;
                let user_id = openpgp_options
                    .openpgp_user_id
                    .ok_or_else(|| anyhow::anyhow!("An OpenPGP user ID is required"))?;
                let key_access = db::KeyAccess::get(&mut conn, &key, &user)
                    .await
                    .context("User doesn't have access to the key")?;

                let hybrid = if let Some(hybrid_key) = key.find_hybrid(&mut conn).await? {
                    // Check for access to its key pair before trying to unlock anything
                    let hybrid_key_access = db::KeyAccess::get(&mut conn, &hybrid_key, &user)
                        .await
                        .context("User doesn't have access to the key's hybrid pair")?;
                    Some((hybrid_key, hybrid_key_access))
                } else {
                    None
                };

                set_binding_pin(&mut config, pkcs11_binding_pin)?;
                let user_password = password_from_file_or_prompt(
                    "Enter the password to access the key: ",
                    password_file,
                    0,
                )?;
                let key_password = decrypt_key_password(
                    &config.pkcs11_bindings,
                    user_password.clone(),
                    &key_access.encrypted_passphrase,
                )
                .await?;
                let hybrid_with_password =
                    if let Some((hybrid_key, hybrid_key_access)) = hybrid.as_ref() {
                        let hybrid_key_password = decrypt_key_password(
                            &config.pkcs11_bindings,
                            user_password,
                            &hybrid_key_access.encrypted_passphrase,
                        )
                        .await?;
                        Some((hybrid_key, hybrid_key_password))
                    } else {
                        None
                    };

                let certificate = crypto::openpgp_cert_for_key(
                    &config,
                    (&key, key_password),
                    hybrid_with_password,
                    user_id.into(),
                    openpgp_options.openpgp_profile.into(),
                    openpgp_options.openpgp_hash_algorithm.into(),
                    openpgp_options.openpgp_validity_days,
                )?;
                let cert = db::PublicKeyMaterial::create(
                    &mut conn,
                    &key,
                    cert_name.clone(),
                    db::PublicKeyMaterialType::OpenPgpCert,
                    certificate.clone(),
                )
                .await?;
                if let Some((hybrid_key, _)) = hybrid {
                    let _ = db::PublicKeyMaterial::create(
                        &mut conn,
                        &hybrid_key,
                        cert_name,
                        db::PublicKeyMaterialType::OpenPgpCert,
                        certificate.clone(),
                    )
                    .await?;
                }
                println!("Successfully created OpenPGP certificate:\n{}", cert.data);
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
            UserCommands::GrantKeyAccess {
                pkcs11_binding_pin,
                key,
                existing_user,
                existing_user_password_file,
                user,
                user_password_file,
            } => {
                let key = db::Key::get(&mut conn, &key)
                    .await
                    .context("Failed to look up key")?;
                let existing_user = db::User::get(&mut conn, &existing_user)
                    .await
                    .context("Failed to look up existing user")?;
                let existing_key_access = db::KeyAccess::get(&mut conn, &key, &existing_user)
                    .await
                    .context("Failed to look up existing user's key access")?;
                let hybrid_key_with_password =
                    if let Some(hybrid_key) = key.find_hybrid(&mut conn).await? {
                        let hybrid_key_access =
                            db::KeyAccess::get(&mut conn, &hybrid_key, &existing_user)
                                .await
                                .context("User doesn't have access to the key's hybrid pair")?;
                        Some((hybrid_key, hybrid_key_access))
                    } else {
                        None
                    };

                let new_user = db::User::get(&mut conn, &user)
                    .await
                    .context("Failed to look up user being granted access")?;

                if !config.pkcs11_bindings.is_empty() {
                    let binding = config
                        .pkcs11_bindings
                        .iter_mut()
                        .find(|b| b.private_key.is_some())
                        .ok_or_else(|| {
                            anyhow::anyhow!("At least one pkcs11 binding needs a private key")
                        })?;
                    let prompt = format!(
                        "Please enter the PKCS11 binding PIN for {}:",
                        binding
                            .private_key
                            .as_ref()
                            .expect("filter for bindings with private key URIs")
                    );
                    let pin = password_from_file_or_prompt(&prompt, pkcs11_binding_pin, 0)?;
                    binding.pin = Some(pin);
                }
                let existing_user_password = password_from_file_or_prompt(
                    "Please enter the existing user's password:",
                    existing_user_password_file,
                    0,
                )?;
                let user_password = password_from_file_or_prompt(
                    "Please enter the new user's password:",
                    user_password_file,
                    config.user_password_length.get().into(),
                )?;

                let key_password = crypto::binding::decrypt_key_password(
                    &config.pkcs11_bindings,
                    existing_user_password.clone(),
                    &existing_key_access.encrypted_passphrase,
                )
                .await?;
                let new_encrypted_passphrase = crypto::binding::encrypt_key_password(
                    &config.pkcs11_bindings,
                    user_password.clone(),
                    key_password,
                )?;
                db::KeyAccess::create(&mut conn, &key, &new_user, new_encrypted_passphrase, false)
                    .await
                    .context("Failed to create new access record")?;

                if let Some((key, hybrid_access)) = hybrid_key_with_password {
                    let key_password = crypto::binding::decrypt_key_password(
                        &config.pkcs11_bindings,
                        existing_user_password.clone(),
                        &hybrid_access.encrypted_passphrase,
                    )
                    .await?;
                    let new_encrypted_passphrase = crypto::binding::encrypt_key_password(
                        &config.pkcs11_bindings,
                        user_password,
                        key_password,
                    )?;
                    db::KeyAccess::create(
                        &mut conn,
                        &key,
                        &new_user,
                        new_encrypted_passphrase,
                        false,
                    )
                    .await
                    .context("Failed to create new access record")?;
                }

                println!(
                    "Successfully granted user {} access to {}",
                    new_user.name, key.name
                );
            }
            UserCommands::RevokeKeyAccess { key, user } => {
                let key = db::Key::get(&mut conn, &key).await?;
                let user = db::User::get(&mut conn, &user).await?;
                let mut deleted = db::KeyAccess::delete(&mut conn, &key, &user).await?;
                if let Some(hybrid_key) = key.find_hybrid(&mut conn).await? {
                    deleted += db::KeyAccess::delete(&mut conn, &hybrid_key, &user).await?;
                }
                if deleted == 0 {
                    println!("User did not have key access");
                } else {
                    println!(
                        "Removed {deleted} access record(s) from {} for {}",
                        key.name, user.name
                    );
                }
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
                &config,
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
    use std::{
        num::{NonZeroU16, NonZeroU32},
        path::PathBuf,
        process::Command,
    };

    use anyhow::Result;
    use cryptoki::{
        context::{CInitializeArgs, CInitializeFlags, Pkcs11},
        mechanism::Mechanism,
        object::Attribute,
        session::UserType,
        types::AuthPin,
    };
    use openssl::nid::Nid;
    use sequoia_openpgp::{Cert, crypto::Password, parse::Parse, types::PublicKeyAlgorithm};
    use siguldry::{
        protocol::KeyAlgorithm,
        server::{Config, crypto::KeyUsage, db},
    };
    use tempfile::TempDir;

    use crate::cli::{
        KeyCommands, ManagementCommands, OpenPgpHashAlgorithm, OpenPgpOptions, OpenPgpProfile,
        Pkcs11Commands, UserCommands, X509Options,
    };

    use super::{manage, set_binding_pin};

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
    async fn key_create_plain_keys() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("key-admin").await?;
        let pool = db::pool(test.config().database().to_str().unwrap(), true).await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "very-secret\n")?;

        for algorithm in [
            KeyAlgorithm::Rsa2K,
            KeyAlgorithm::Rsa4K,
            KeyAlgorithm::P256,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::Ed448,
            KeyAlgorithm::Mldsa65,
            KeyAlgorithm::Mldsa87,
        ] {
            let name = format!("plain-{}", algorithm.as_str());
            manage(
                ManagementCommands::Key(KeyCommands::Create {
                    algorithm,
                    openpgp_hybrid_pair: false,
                    password_file: Some(password_file.clone()),
                    admin: "key-admin".to_string(),
                    name: name.clone(),
                    x509_options: Default::default(),
                    openpgp_options: Default::default(),
                }),
                test.config().clone(),
            )
            .await?;

            let mut conn = pool.begin().await?;
            let key = db::Key::get(&mut conn, &name).await?;
            assert_eq!(key.key_algorithm, algorithm);
            assert_eq!(key.hybrid_pair_id, None);
        }

        Ok(())
    }

    #[tokio::test]
    async fn key_create_plain_keys_with_x509() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("key-admin").await?;
        let pool = db::pool(test.config().database().to_str().unwrap(), true).await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "very-secret\n")?;

        for algorithm in [
            KeyAlgorithm::Rsa2K,
            KeyAlgorithm::Rsa4K,
            KeyAlgorithm::P256,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::Ed448,
            KeyAlgorithm::Mldsa65,
            KeyAlgorithm::Mldsa87,
        ] {
            let name = format!("plain-{}", algorithm.as_str());
            manage(
                ManagementCommands::Key(KeyCommands::Create {
                    algorithm,
                    openpgp_hybrid_pair: false,
                    password_file: Some(password_file.clone()),
                    admin: "key-admin".to_string(),
                    name: name.clone(),
                    x509_options: X509Options {
                        x509_cert_name: Some("x509-cert".to_string()),
                        ..Default::default()
                    },
                    openpgp_options: Default::default(),
                }),
                test.config().clone(),
            )
            .await?;

            let mut conn = pool.begin().await?;
            let key = db::Key::get(&mut conn, &name).await?;
            assert_eq!(key.key_algorithm, algorithm);
            assert_eq!(key.hybrid_pair_id, None);
            let x509 =
                db::PublicKeyMaterial::list(&mut conn, &key, db::PublicKeyMaterialType::X509)
                    .await?;
            assert_eq!(x509.first().unwrap().name, "x509-cert");
            let cert = openssl::x509::X509::from_pem(x509.first().unwrap().data.as_bytes())?;
            assert_eq!(
                &cert
                    .subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .unwrap()
                    .data()
                    .to_string()?,
                &name
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn key_create_plain_keys_with_openpgp() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("key-admin").await?;
        let pool = db::pool(test.config().database().to_str().unwrap(), true).await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "very-secret\n")?;

        for (algorithm, openpgp_profile, expected_algorithm) in [
            (
                KeyAlgorithm::Rsa2K,
                OpenPgpProfile::RFC4880,
                PublicKeyAlgorithm::RSAEncryptSign,
            ),
            (
                KeyAlgorithm::Rsa4K,
                OpenPgpProfile::RFC4880,
                PublicKeyAlgorithm::RSAEncryptSign,
            ),
            (
                KeyAlgorithm::P256,
                OpenPgpProfile::RFC4880,
                PublicKeyAlgorithm::ECDSA,
            ),
            (
                KeyAlgorithm::Ed25519,
                OpenPgpProfile::RFC9580,
                PublicKeyAlgorithm::Ed25519,
            ),
            (
                KeyAlgorithm::Ed448,
                OpenPgpProfile::RFC9580,
                PublicKeyAlgorithm::Ed448,
            ),
        ] {
            let name = format!("plain-{}", algorithm.as_str());
            manage(
                ManagementCommands::Key(KeyCommands::Create {
                    algorithm,
                    openpgp_hybrid_pair: false,
                    password_file: Some(password_file.clone()),
                    admin: "key-admin".to_string(),
                    name: name.clone(),
                    x509_options: Default::default(),
                    openpgp_options: OpenPgpOptions {
                        openpgp_cert_name: Some("openpgp-cert".to_string()),
                        openpgp_user_id: Some("Nobody <someone@example.com>".to_string()),
                        openpgp_validity_days: 0,
                        openpgp_profile,
                        openpgp_hash_algorithm: Default::default(),
                    },
                }),
                test.config().clone(),
            )
            .await?;

            let mut conn = pool.begin().await?;
            let key = db::Key::get(&mut conn, &name).await?;
            assert_eq!(key.key_algorithm, algorithm);
            assert_eq!(key.hybrid_pair_id, None);
            let openpgp = db::PublicKeyMaterial::list(
                &mut conn,
                &key,
                db::PublicKeyMaterialType::OpenPgpCert,
            )
            .await?;
            assert_eq!(openpgp.first().unwrap().name, "openpgp-cert");
            let cert = Cert::from_bytes(openpgp.first().unwrap().data.as_bytes())?;
            assert_eq!(cert.primary_key().key().pk_algo(), expected_algorithm);
        }

        Ok(())
    }

    #[tokio::test]
    async fn key_create_openpgp_hybrid_keys() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("key-admin").await?;
        let pool = db::pool(test.config().database().to_str().unwrap(), true).await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "very-secret\n")?;

        for (algorithm, expected_hybrid_algorithm) in [
            (KeyAlgorithm::Ed25519, KeyAlgorithm::Mldsa65),
            (KeyAlgorithm::Ed448, KeyAlgorithm::Mldsa87),
            (KeyAlgorithm::Mldsa65, KeyAlgorithm::Ed25519),
            (KeyAlgorithm::Mldsa87, KeyAlgorithm::Ed448),
        ] {
            let name = format!("hybrid-{}", algorithm.as_str());
            manage(
                ManagementCommands::Key(KeyCommands::Create {
                    algorithm,
                    openpgp_hybrid_pair: true,
                    password_file: Some(password_file.clone()),
                    admin: "key-admin".to_string(),
                    name: name.clone(),
                    x509_options: Default::default(),
                    openpgp_options: Default::default(),
                }),
                test.config().clone(),
            )
            .await?;

            let mut conn = pool.begin().await?;
            let key = db::Key::get(&mut conn, &name).await?;
            let hybrid_key = key
                .find_hybrid(&mut conn)
                .await?
                .expect("Hybrid key should be created");
            assert_eq!(key.key_algorithm, algorithm);
            assert_eq!(hybrid_key.key_algorithm, expected_hybrid_algorithm);
            assert_eq!(key.hybrid_pair_id, Some(hybrid_key.id));
            assert_eq!(hybrid_key.hybrid_pair_id, Some(key.id));

            assert!(
                db::PublicKeyMaterial::list(
                    &mut conn,
                    &key,
                    db::PublicKeyMaterialType::OpenPgpCert,
                )
                .await?
                .is_empty()
            );
            assert!(
                db::PublicKeyMaterial::list(
                    &mut conn,
                    &hybrid_key,
                    db::PublicKeyMaterialType::OpenPgpCert,
                )
                .await?
                .is_empty()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn key_create_openpgp_hybrid_keys_with_certs() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("key-admin").await?;
        let pool = db::pool(test.config().database().to_str().unwrap(), true).await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "very-secret\n")?;

        for (algorithm, expected_hybrid_algorithm, expected_pgp_algorithm) in [
            (
                KeyAlgorithm::Ed25519,
                KeyAlgorithm::Mldsa65,
                PublicKeyAlgorithm::MLDSA65_Ed25519,
            ),
            (
                KeyAlgorithm::Ed448,
                KeyAlgorithm::Mldsa87,
                PublicKeyAlgorithm::MLDSA87_Ed448,
            ),
            (
                KeyAlgorithm::Mldsa65,
                KeyAlgorithm::Ed25519,
                PublicKeyAlgorithm::MLDSA65_Ed25519,
            ),
            (
                KeyAlgorithm::Mldsa87,
                KeyAlgorithm::Ed448,
                PublicKeyAlgorithm::MLDSA87_Ed448,
            ),
        ] {
            let name = format!("hybrid-{}", algorithm.as_str());
            manage(
                ManagementCommands::Key(KeyCommands::Create {
                    algorithm,
                    openpgp_hybrid_pair: true,
                    password_file: Some(password_file.clone()),
                    admin: "key-admin".to_string(),
                    name: name.clone(),
                    x509_options: Default::default(),
                    openpgp_options: OpenPgpOptions {
                        openpgp_cert_name: Some("openpgp-cert".to_string()),
                        openpgp_user_id: Some("Nobody <someone@example.com>".to_string()),
                        openpgp_validity_days: 0,
                        openpgp_profile: OpenPgpProfile::RFC9580,
                        openpgp_hash_algorithm: Default::default(),
                    },
                }),
                test.config().clone(),
            )
            .await?;

            let mut conn = pool.begin().await?;
            let key = db::Key::get(&mut conn, &name).await?;
            let hybrid_key = key
                .find_hybrid(&mut conn)
                .await?
                .expect("Hybrid key should be created");
            assert_eq!(key.key_algorithm, algorithm);
            assert_eq!(hybrid_key.key_algorithm, expected_hybrid_algorithm);
            assert_eq!(key.hybrid_pair_id, Some(hybrid_key.id));
            assert_eq!(hybrid_key.hybrid_pair_id, Some(key.id));

            let certs = db::PublicKeyMaterial::list(
                &mut conn,
                &key,
                db::PublicKeyMaterialType::OpenPgpCert,
            )
            .await?;
            let hybrid_certs = db::PublicKeyMaterial::list(
                &mut conn,
                &hybrid_key,
                db::PublicKeyMaterialType::OpenPgpCert,
            )
            .await?;

            for (c1, c2) in certs.iter().zip(hybrid_certs.iter()) {
                assert_eq!(c1.data, c2.data);
                let cert = Cert::from_bytes(c1.data.as_bytes())?;
                assert_eq!(cert.primary_key().key().pk_algo(), expected_pgp_algorithm);
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn key_create_openpgp_hybrid_keys_invalid_algorithm() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("key-admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "very-secret\n")?;

        for algorithm in [KeyAlgorithm::Rsa2K, KeyAlgorithm::Rsa4K, KeyAlgorithm::P256] {
            let name = format!("invalid-hybrid-{}", algorithm.as_str());
            let error = manage(
                ManagementCommands::Key(KeyCommands::Create {
                    algorithm,
                    openpgp_hybrid_pair: true,
                    password_file: Some(password_file.clone()),
                    admin: "key-admin".to_string(),
                    name: name.clone(),
                    x509_options: Default::default(),
                    openpgp_options: Default::default(),
                }),
                test.config().clone(),
            )
            .await
            .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("cannot be part of an OpenPGP hybrid pair")
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn hybrid_key_access_is_granted_and_revoked_together() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("key-admin").await?;
        test.create_user("key-user").await?;
        let pool = db::pool(test.config().database().to_str().unwrap(), true).await?;

        let admin_password_file = test.temp_dir.path().join("admin-password");
        std::fs::write(&admin_password_file, "very-secret\n")?;
        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Ed25519,
                openpgp_hybrid_pair: true,
                password_file: Some(admin_password_file.clone()),
                admin: "key-admin".to_string(),
                name: "grant-hybrid".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
            }),
            test.config().clone(),
        )
        .await?;

        let user_password_file = test.temp_dir.path().join("user-password");
        std::fs::write(&user_password_file, "even-more-secret\n")?;
        manage(
            ManagementCommands::Users(UserCommands::GrantKeyAccess {
                pkcs11_binding_pin: None,
                key: "grant-hybrid".to_string(),
                existing_user: "key-admin".to_string(),
                existing_user_password_file: Some(admin_password_file),
                user: "key-user".to_string(),
                user_password_file: Some(user_password_file),
            }),
            test.config().clone(),
        )
        .await?;

        {
            let mut conn = pool.begin().await?;
            let user = db::User::get(&mut conn, "key-user").await?;
            for name in ["grant-hybrid", "grant-hybrid-mldsa65"] {
                let key = db::Key::get(&mut conn, name).await?;
                let access = db::KeyAccess::get(&mut conn, &key, &user).await?;
                siguldry::server::crypto::binding::decrypt_key_password(
                    &[],
                    Password::from("even-more-secret"),
                    &access.encrypted_passphrase,
                )
                .await?;
            }
        }

        manage(
            ManagementCommands::Users(UserCommands::RevokeKeyAccess {
                key: "grant-hybrid-mldsa65".to_string(),
                user: "key-user".to_string(),
            }),
            test.config().clone(),
        )
        .await?;

        let mut conn = pool.begin().await?;
        let user = db::User::get(&mut conn, "key-user").await?;
        for name in ["grant-hybrid", "grant-hybrid-mldsa65"] {
            let key = db::Key::get(&mut conn, name).await?;
            assert!(matches!(
                db::KeyAccess::get(&mut conn, &key, &user).await,
                Err(sqlx::Error::RowNotFound)
            ));
        }

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
                openpgp_hybrid_pair: false,
                password_file: Some(password_file),
                admin: "key-admin".to_string(),
                name: "test-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
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
                openpgp_hybrid_pair: false,
                password_file: Some(password_file),
                admin: "nonexistent-user".to_string(),
                name: "test-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
            }),
            test.config().clone(),
        )
        .await;

        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn openpgp_certificate() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "secret-password\n")?;
        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                openpgp_hybrid_pair: false,
                password_file: Some(password_file.clone()),
                admin: "admin".to_string(),
                name: "openpgp-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
            }),
            test.config().clone(),
        )
        .await?;
        manage(
            ManagementCommands::Key(KeyCommands::Openpgp {
                user_name: "admin".to_string(),
                key_name: "openpgp-key".to_string(),
                password_file: Some(password_file),
                pkcs11_binding_pin: None,
                openpgp_options: OpenPgpOptions {
                    openpgp_cert_name: Some("openpgp-cert".to_string()),
                    openpgp_user_id: Some("Test Signing <sign@example.com>".to_string()),
                    openpgp_validity_days: 30,
                    openpgp_profile: OpenPgpProfile::RFC4880,
                    openpgp_hash_algorithm: OpenPgpHashAlgorithm::SHA512,
                },
            }),
            test.config().clone(),
        )
        .await?;

        let pool = db::pool(test.config().database().to_str().unwrap(), true).await?;
        let mut conn = pool.begin().await?;
        let key = db::Key::get(&mut conn, "openpgp-key").await?;
        let certs =
            db::PublicKeyMaterial::list(&mut conn, &key, db::PublicKeyMaterialType::OpenPgpCert)
                .await?;
        assert_eq!(certs.len(), 1);
        assert_eq!(certs.first().unwrap().name, "openpgp-cert");

        Ok(())
    }

    #[tokio::test]
    async fn hybrid_openpgp_certificate() -> Result<()> {
        let test = TestConfig::new(false).await?;
        test.migrate().await?;
        test.create_user("admin").await?;

        let password_file = test.temp_dir.path().join("password");
        std::fs::write(&password_file, "secret-password\n")?;
        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Ed25519,
                openpgp_hybrid_pair: true,
                password_file: Some(password_file.clone()),
                admin: "admin".to_string(),
                name: "openpgp-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
            }),
            test.config().clone(),
        )
        .await?;
        manage(
            ManagementCommands::Key(KeyCommands::Openpgp {
                user_name: "admin".to_string(),
                key_name: "openpgp-key".to_string(),
                password_file: Some(password_file),
                pkcs11_binding_pin: None,
                openpgp_options: OpenPgpOptions {
                    openpgp_cert_name: Some("openpgp-cert".to_string()),
                    openpgp_user_id: Some("Test Signing <sign@example.com>".to_string()),
                    openpgp_validity_days: 30,
                    openpgp_profile: OpenPgpProfile::RFC9580,
                    openpgp_hash_algorithm: OpenPgpHashAlgorithm::SHA512,
                },
            }),
            test.config().clone(),
        )
        .await?;

        let pool = db::pool(test.config().database().to_str().unwrap(), true).await?;
        let mut conn = pool.begin().await?;
        let key = db::Key::get(&mut conn, "openpgp-key").await?;
        let hybrid_key = key
            .find_hybrid(&mut conn)
            .await?
            .expect("Hybrid key should be created");

        let certs =
            db::PublicKeyMaterial::list(&mut conn, &key, db::PublicKeyMaterialType::OpenPgpCert)
                .await?;
        let hybrid_certs = db::PublicKeyMaterial::list(
            &mut conn,
            &hybrid_key,
            db::PublicKeyMaterialType::OpenPgpCert,
        )
        .await?;

        for (c1, c2) in certs.iter().zip(hybrid_certs.iter()) {
            assert_eq!(c1.data, c2.data);
            let cert = Cert::from_bytes(c1.data.as_bytes())?;
            assert_eq!(
                cert.primary_key().key().pk_algo(),
                PublicKeyAlgorithm::MLDSA65_Ed25519
            );
        }

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
                openpgp_hybrid_pair: false,
                password_file: Some(password_file.clone()),
                admin: "admin".to_string(),
                name: "ca-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
            }),
            test.config().clone(),
        )
        .await?;
        manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "ca-key".to_string(),
                x509_options: X509Options {
                    x509_cert_name: Some("ca-cert".to_string()),
                    x509_usage: KeyUsage::CertificateAuthority,
                    x509_common_name: Some("Test CA".to_string()),
                    x509_validity_days: NonZeroU32::new(30).unwrap(),
                },
                ca_key_name: None,
                ca_cert_name: None,
                ca_password_file: Some(password_file),
                pkcs11_binding_pin: None,
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
                openpgp_hybrid_pair: false,
                password_file: Some(ca_password_file.clone()),
                admin: "admin".to_string(),
                name: "ca-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
            }),
            test.config().clone(),
        )
        .await?;
        manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "ca-key".to_string(),
                x509_options: X509Options {
                    x509_cert_name: Some("ca-cert".to_string()),
                    x509_usage: KeyUsage::CertificateAuthority,
                    x509_common_name: Some("Test CA".to_string()),
                    x509_validity_days: NonZeroU32::new(30).unwrap(),
                },
                ca_key_name: None,
                ca_cert_name: None,
                ca_password_file: Some(ca_password_file.clone()),
                pkcs11_binding_pin: None,
            }),
            test.config().clone(),
        )
        .await?;

        manage(
            ManagementCommands::Key(KeyCommands::Create {
                algorithm: KeyAlgorithm::Rsa4K,
                openpgp_hybrid_pair: false,
                password_file: Some(key_password_file),
                admin: "admin".to_string(),
                name: "codesigning-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
            }),
            test.config().clone(),
        )
        .await?;
        manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "codesigning-key".to_string(),
                x509_options: X509Options {
                    x509_cert_name: Some("codesigning-cert".to_string()),
                    x509_usage: KeyUsage::CodeSigning,
                    x509_common_name: Some("Test Code Signing".to_string()),
                    x509_validity_days: NonZeroU32::new(30).unwrap(),
                },
                ca_key_name: Some("ca-key".to_string()),
                ca_cert_name: Some("ca-cert".to_string()),
                ca_password_file: Some(ca_password_file),
                pkcs11_binding_pin: None,
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
                openpgp_hybrid_pair: false,
                password_file: Some(password_file),
                admin: "admin".to_string(),
                name: "test-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
            }),
            test.config().clone(),
        )
        .await?;
        let result = manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "test-key".to_string(),
                x509_options: X509Options {
                    x509_cert_name: Some("test-cert".to_string()),
                    x509_usage: KeyUsage::CertificateAuthority,
                    x509_common_name: Some("Test".to_string()),
                    x509_validity_days: NonZeroU32::new(30).unwrap(),
                },
                ca_key_name: None,
                ca_cert_name: None,
                ca_password_file: Some(wrong_password_file),
                pkcs11_binding_pin: None,
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
                openpgp_hybrid_pair: false,
                password_file: Some(password_file.clone()),
                admin: "admin".to_string(),
                name: "test-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
            }),
            test.config().clone(),
        )
        .await?;
        let result = manage(
            ManagementCommands::Key(KeyCommands::X509 {
                user_name: "admin".to_string(),
                key_name: "test-key".to_string(),
                x509_options: X509Options {
                    x509_cert_name: Some("test-cert".to_string()),
                    x509_usage: KeyUsage::CodeSigning,
                    x509_common_name: Some("Test".to_string()),
                    x509_validity_days: NonZeroU32::new(30).unwrap(),
                },
                ca_key_name: Some("nonexistent-ca".to_string()),
                ca_cert_name: None,
                ca_password_file: Some(password_file),
                pkcs11_binding_pin: None,
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
                openpgp_hybrid_pair: false,
                password_file: Some("/path/does/not/exist".into()),
                admin: "admin".to_string(),
                name: "test-rsa-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
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
                openpgp_hybrid_pair: false,
                password_file: Some("/path/does/not/exist".into()),
                admin: "admin".to_string(),
                name: "test-rsa-key".to_string(),
                x509_options: Default::default(),
                openpgp_options: Default::default(),
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
            openpgp_hybrid_pair: false,
            password_file: Some(password_file.clone()),
            admin: "admin".to_string(),
            name: "test-rsa-key".to_string(),
            x509_options: Default::default(),
            openpgp_options: Default::default(),
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

    #[test]
    fn set_binding_pin_from_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pin_file = temp_dir.path().join("binding_pin");
        std::fs::write(&pin_file, "very-secret\n")?;

        let mut config = Config {
            pkcs11_bindings: vec![siguldry::server::Pkcs11Binding {
                certificate: temp_dir.path().join("cert.pem"),
                private_key: Some("pkcs11:object=test-key;type=private".to_string()),
                pin: None,
            }],
            ..Default::default()
        };

        set_binding_pin(&mut config, Some(pin_file))?;

        let pin = config
            .pkcs11_bindings
            .first()
            .unwrap()
            .pin
            .as_ref()
            .expect("binding PIN should be read from the file");
        assert!(pin.map(|bytes| **bytes == *b"very-secret"));

        Ok(())
    }

    #[test]
    fn set_binding_pin_rejects_pin_file_with_multiple_bindings() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pin_file = temp_dir.path().join("binding_pin");
        std::fs::write(&pin_file, "which-token-is-this-pin-for?\n")?;

        let binding = |id: &str| siguldry::server::Pkcs11Binding {
            certificate: temp_dir.path().join("cert.pem"),
            private_key: Some(format!("pkcs11:object=test-key-{id};type=private")),
            pin: None,
        };
        let mut config = Config {
            pkcs11_bindings: vec![binding("a"), binding("b")],
            ..Default::default()
        };

        let result = set_binding_pin(&mut config, Some(pin_file));
        assert!(result.is_err());

        Ok(())
    }
}
