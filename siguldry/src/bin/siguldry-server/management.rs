// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Implements the management commands for the siguldry-server CLI.

use std::{io::Write, os::unix::fs::OpenOptionsExt};

use rustix::termios::Termios;
use sequoia_openpgp::{cert::CipherSuite, crypto::Password, Profile};
use siguldry::server::{
    crypto::{self, create_encrypted_file_key},
    db, Config,
};
use tracing::instrument;

use crate::cli::{GpgCommands, KeyCommands, ManagementCommands, UserCommands};

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
                let path = config
                    .gpg_keystore()?
                    .join(format!("{}.asc", bound_key.fingerprint()));
                let mut file = std::fs::File::options()
                    .mode(0o600)
                    .create_new(true)
                    .write(true)
                    .open(path)?;
                file.write_all(&bound_key.armored_key()?)?;

                let key = db::Key::create(
                    &mut conn,
                    &name,
                    db::KeyType::Rsa4K,
                    db::KeyLocation::SequoiaSoftkey,
                    &bound_key.fingerprint(),
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
        },
        ManagementCommands::Key(key_commands) => match key_commands {
            KeyCommands::Create {
                password_file,
                admin,
                name,
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

                let (handle, encrypted_password) =
                    create_encrypted_file_key(&config, user_password, db::KeyType::P256)?;
                let key = db::Key::create(
                    &mut conn,
                    &name,
                    db::KeyType::P256,
                    db::KeyLocation::EncryptedFile,
                    &handle,
                )
                .await?;
                db::KeyAccess::create(&mut conn, &key, &user, encrypted_password, true).await?;
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
