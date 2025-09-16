// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Implements the management commands for the siguldry-server CLI.

use std::path::PathBuf;

use anyhow::Context;
use openssl::{
    asn1::{self, Asn1Integer},
    hash::MessageDigest,
    nid::Nid,
    x509,
};
use rustix::termios::Termios;
use sequoia_openpgp::{cert::CipherSuite, crypto::Password, Profile};
use siguldry::server::{
    crypto::{self, create_encrypted_key, decrypt_key_password},
    db, Config,
};
use tracing::instrument;

use crate::cli::{GpgCommands, KeyCommands, KeyUsage, ManagementCommands, UserCommands};

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
    )
    .await?;

    let mut conn = db_pool.begin().await?;
    match command {
        ManagementCommands::Gpg(gpg_commands) => match gpg_commands {
            GpgCommands::Create {
                password_file,
                admin,
                name,
                email,
            } => {
                let user = db::User::get(&mut conn, &admin).await?;
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

                let password_length = user_password.map(|p| p.len());
                if config.user_password_length.get() as usize > password_length {
                    return Err(anyhow::anyhow!(
                        "Password must be {} bytes long (got {})",
                        config.user_password_length,
                        password_length
                    ));
                }

                let bound_key = crypto::GpgKey::new(
                    &config.pkcs11_bindings,
                    format!("{name} <{email}>"),
                    user_password,
                    Profile::RFC4880,
                    CipherSuite::RSA4k,
                )?;
                let armored_private_key = bound_key.armored_key()?;
                let armored_private_key = String::from_utf8(armored_private_key)?;
                let public_key = bound_key.public_key()?;

                let key = db::Key::create(
                    &mut conn,
                    &name,
                    &bound_key.fingerprint(),
                    db::KeyAlgorithm::Rsa4K,
                    db::KeyLocation::SequoiaSoftkey,
                    &armored_private_key,
                    &public_key,
                )
                .await?;
                db::KeyAccess::create(
                    &mut conn,
                    &key,
                    &user,
                    bound_key.encrypted_password().to_vec(),
                    true,
                )
                .await?;

                println!("Successfully created key {key} with {user} as the key administrator");
            }
            GpgCommands::List {} => {
                for key in db::Key::list(&mut conn).await? {
                    match key.key_location {
                        db::KeyLocation::SequoiaSoftkey => println!("{key}"),
                        db::KeyLocation::Encrypted | db::KeyLocation::Pkcs11 => {}
                        _ => eprintln!("Key {} stored in unknown location", key.name),
                    }
                }
            }
        },
        ManagementCommands::Key(key_commands) => match key_commands {
            KeyCommands::Create {
                password_file,
                admin,
                name,
            } => {
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

                let (handle, encrypted_password, private_key, public_key) =
                    create_encrypted_key(&config, user_password, db::KeyAlgorithm::P256)?;
                let key = db::Key::create(
                    &mut conn,
                    &name,
                    &handle,
                    db::KeyAlgorithm::P256,
                    db::KeyLocation::Encrypted,
                    &private_key,
                    &public_key,
                )
                .await?;
                db::KeyAccess::create(&mut conn, &key, &user, encrypted_password, true).await?;
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
                let signing_key = db::Key::get(
                    &mut conn,
                    certificate_authority.as_ref().unwrap_or(&key_name),
                )
                .await
                .context("No key found for specified certificate authority")?;
                let signing_key_access = db::KeyAccess::get(&mut conn, &signing_key, &user)
                    .await
                    .context("User doesn't have access to the signing key")?;

                if key.key_location != db::KeyLocation::Encrypted
                    || signing_key.key_location != db::KeyLocation::Encrypted
                {
                    return Err(anyhow::anyhow!(
                        "Only keys encrypted in the database can be signed via this tool"
                    ));
                }

                let mut builder = x509::X509Builder::new()?;
                let pubkey = openssl::pkey::PKey::public_key_from_pem(key.public_key.as_bytes())?;
                builder.set_pubkey(&pubkey)?;

                let mut serial_number = [0; 20];
                openssl::rand::rand_bytes(&mut serial_number)?;
                let mut serial_number = openssl::bn::BigNum::from_slice(&serial_number)?;
                serial_number.set_negative(false);
                builder.set_serial_number(Asn1Integer::from_bn(&serial_number)?.as_ref())?;

                let mut subject_name = x509::X509NameBuilder::new()?;
                subject_name
                    .append_entry_by_nid(Nid::COUNTRYNAME, &config.certificate_subject.country)?;
                subject_name.append_entry_by_nid(
                    Nid::STATEORPROVINCENAME,
                    &config.certificate_subject.state_or_province,
                )?;
                subject_name
                    .append_entry_by_nid(Nid::LOCALITYNAME, &config.certificate_subject.locality)?;
                subject_name.append_entry_by_nid(
                    Nid::ORGANIZATIONNAME,
                    &config.certificate_subject.organization,
                )?;
                subject_name.append_entry_by_nid(
                    Nid::ORGANIZATIONALUNITNAME,
                    &config.certificate_subject.organizational_unit,
                )?;
                subject_name.append_entry_by_nid(Nid::COMMONNAME, &common_name)?;
                let subject_name = subject_name.build();
                builder.set_subject_name(&subject_name)?;

                let issuer = if let Some(ca) = &certificate_authority {
                    let ca_key = db::Key::get(&mut conn, ca)
                        .await
                        .context("No key found for specified certificate authority")?;
                    let mut certs = db::PublicKeyMaterial::list(
                        &mut conn,
                        &ca_key,
                        db::PublicKeyMaterialType::X509,
                    )
                    .await?;
                    let cert = certs
                        .pop()
                        .ok_or_else(|| anyhow::anyhow!("No x509 certificate found for CA {ca}"))?;
                    let ca_cert = x509::X509::from_pem(cert.data.as_bytes())?;
                    Some(ca_cert)
                } else {
                    None
                };
                let issuer_name = issuer
                    .as_ref()
                    .map_or(subject_name.as_ref(), |ca| ca.subject_name());
                builder.set_issuer_name(issuer_name)?;

                builder.set_not_before(asn1::Asn1Time::days_from_now(0)?.as_ref())?;
                builder
                    .set_not_after(asn1::Asn1Time::days_from_now(validity_days.get())?.as_ref())?;

                let mut basic_constraints = x509::extension::BasicConstraints::new();
                basic_constraints.critical().pathlen(0);
                if let KeyUsage::CertificateAuthority = usage {
                    basic_constraints.ca();
                }
                builder.append_extension(basic_constraints.build()?)?;

                match usage {
                    KeyUsage::CodeSigning => {
                        builder.append_extension(
                            x509::extension::KeyUsage::new()
                                .critical()
                                .digital_signature()
                                .build()?,
                        )?;
                        builder.append_extension(
                            x509::extension::ExtendedKeyUsage::new()
                                .code_signing()
                                .build()?,
                        )?;
                    }
                    KeyUsage::CertificateAuthority => {
                        builder.append_extension(
                            x509::extension::KeyUsage::new()
                                .critical()
                                .key_cert_sign()
                                .crl_sign()
                                .build()?,
                        )?;
                    }
                };

                let subj_key_id = x509::extension::SubjectKeyIdentifier::new();
                let context = builder.x509v3_context(issuer.as_ref().map(|i| i.as_ref()), None);
                builder.append_extension(subj_key_id.build(&context)?)?;

                let prompt = format!(
                    "Enter a password to access the key (at least {} bytes): ",
                    config.user_password_length.get()
                );
                let user_password = password_from_file_or_prompt(&prompt, ca_password_file, 0)?;
                let key_password = decrypt_key_password(
                    &config.pkcs11_bindings,
                    user_password,
                    &signing_key_access.encrypted_passphrase,
                )
                .await?;
                let private_key = key_password.map(|passphrase| {
                    openssl::pkey::PKey::private_key_from_pem_passphrase(
                        signing_key.key_material.as_bytes(),
                        passphrase,
                    )
                })?;
                builder.sign(&private_key, MessageDigest::sha512())?;
                let certificate = builder.build();
                let certificate = String::from_utf8(certificate.to_pem()?)?;

                let cert = db::PublicKeyMaterial::create(
                    &mut conn,
                    &key,
                    db::PublicKeyMaterialType::X509,
                    certificate,
                )
                .await?;
                println!("Successfully signed certificate:\n{}", cert.data);
            }
            KeyCommands::List {} => {
                for key in db::Key::list(&mut conn).await? {
                    match key.key_location {
                        db::KeyLocation::SequoiaSoftkey => {}
                        db::KeyLocation::Encrypted | db::KeyLocation::Pkcs11 => {
                            println!("{key}");
                        }
                        _ => eprintln!("Key {} stored in unknown location", key.name),
                    }
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
        ManagementCommands::Migrate {} => db::migrate(&db_pool).await?,
    }
    conn.commit().await?;

    Ok(())
}
