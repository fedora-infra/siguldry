// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Define the command-line interface.
//!
//! This is where subcommands, the arguments, and their types are defined.

use std::{num::NonZeroU32, path::PathBuf};

use clap::Parser;
use siguldry::protocol::KeyAlgorithm;

/// The siguldry signing server.
///
/// This includes a command to run the server, along with a set of management commands.
/// These include applying database migrations, creating new remote users, providing PINs
/// to the server at runtime to unlock PKCS#11 tokens, managing signing keys, and so on.
///
/// To begin, you'll need to provide a configuration file. For an example of the current
/// format, consult the `config` subcommand.
///
/// Once you have a valid configuration, create a new database using the `manage migrate` subcommand.
///
/// Finally, create a remote user with the `manage users add` subcommand.
///
/// Be aware that management commands should be run with the same user the service runs as.
#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    /// The path to the server's configuration file.
    ///
    /// If no path is provided, the defaults are used. To view the service configuration,
    /// run the `config` subcommand.
    #[arg(long, short, env = "SIGULDRY_SERVER_CONFIG")]
    pub config: Option<PathBuf>,

    /// A set of one or more comma-separated directives to filter logs.
    ///
    /// The general format is "target_name[span_name{field=value}]=level" where level is
    /// one of TRACE, DEBUG, INFO, WARN, ERROR.
    ///
    /// Details: https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives
    #[arg(
        long,
        env = "SIGULDRY_SERVER_LOG",
        default_value = "WARN,siguldry=INFO"
    )]
    pub log_filter: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Run the service.
    Listen {
        /// The directory containing the service's secrets.
        ///
        /// Any file referenced in the configuration that are not absolute paths are
        /// expected to be in this directory.
        ///
        /// When run under systemd, providing a `ImportCredential=`,
        /// `LoadCredentialEncrypted=`, or `LoadCredential=` directive will
        /// set the environment variable automatically for you.
        #[arg(long, env = "CREDENTIALS_DIRECTORY")]
        credentials_directory: PathBuf,
    },

    EnterPin {
        /// The path to the Unix socket of the server. The socket is located in the server's
        /// RUNTIME_DIRECTORY under the "pin_entry" directory.
        #[arg(long, short)]
        socket: PathBuf,
    },

    /// See the current server configuration.
    Config {
        /// The directory containing the service's secrets.
        ///
        /// Any file referenced in the configuration that are not absolute paths are
        /// expected to be in this directory.
        ///
        /// When run under systemd, providing a `ImportCredential=`,
        /// `LoadCredentialEncrypted=`, or `LoadCredential=` directive will
        /// set the environment variable automatically for you.
        #[arg(
            long,
            env = "CREDENTIALS_DIRECTORY",
            default_value = "/etc/credstore.encrypted/"
        )]
        credentials_directory: PathBuf,
    },

    /// Perform management tasks on the server.
    #[command(subcommand)]
    Manage(ManagementCommands),
}

#[derive(clap::Subcommand, Debug)]
pub enum ManagementCommands {
    /// Manage GPG signing keys.
    #[command(subcommand)]
    Gpg(GpgCommands),

    /// Manage non-GPG signing keys and certificates.
    #[command(subcommand)]
    Key(KeyCommands),

    /// Register and unregister PKCS#11 tokens to use for signing.
    #[command(subcommand)]
    Pkcs11(Pkcs11Commands),

    /// Manage remote users.
    ///
    /// Remote users can perform non-destructive actions such as creating keys and requesting
    /// signatures. Users authenticate via client TLS certificates. It is up to you to handle
    /// issuing and revoking those certificates after you create or remove a user. Users with
    /// valid certificates that are not explicitly added are rejected.
    #[command(subcommand)]
    Users(UserCommands),

    /// Apply any database migrations.
    ///
    /// This should be run on first use to create an empty database. This should also be run after
    /// upgrading to a new version; it is a no-op if no new migrations are available.
    Migrate {},
}

#[derive(clap::Subcommand, Debug)]
pub enum GpgCommands {
    /// Generate a new signing key.
    Create {
        /// A file containing the password needed to unlock and use the key.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        ///
        /// Additional users can be granted access to this key with different passwords.
        #[arg(short, long, default_value = None)]
        password_file: Option<PathBuf>,
        /// The Siguldy username of the key administrator. This user can grant access to other users.
        admin: String,
        /// The name of the key in Siguldry.
        name: String,
        /// The email to use for the GPG user id.
        email: String,
    },
    /// List available GPG keys.
    List {},
}

#[derive(clap::Subcommand, Debug)]
pub enum Pkcs11Commands {
    /// Register a PKCS#11 token with the server.
    ///
    /// Siguldry expects you to manage the token externally via tools like pkcs11-tool.
    /// Objects with the same ID are imported together; there should be a public, private,
    /// and certificate object for each ID.
    Register {
        /// The absolute path to the PKCS#11 module to use when accessing this token,
        #[arg(long, default_value = "/usr/lib64/pkcs11/opensc-pkcs11.so")]
        module: PathBuf,
        /// A file containing the user PIN needed to log into the token.
        ///
        /// The file should include the PIN on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        ///
        /// This PIN will be encrypted using the user's key access password.
        #[arg(short, long, default_value = None)]
        user_pin: Option<PathBuf>,
        /// A file containing the key access password needed to unlock and use the key.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        ///
        /// Additional users can be granted access to this key with different passwords.
        #[arg(short, long, default_value = None)]
        password_file: Option<PathBuf>,

        /// The slot ID containing the token to import.
        ///
        /// Refer to, for example, pkcs11-tool --list-slots. If not provided, the first slot found is used.
        #[arg(short, long, default_value = None)]
        slot_id: Option<u64>,

        /// The Siguldy username of the key administrator. This user can grant access to other users.
        admin: String,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum KeyCommands {
    /// Generate a new signing key.
    Create {
        /// The key algorithm to use.
        #[arg(short, long, value_enum, default_value_t)]
        algorithm: KeyAlgorithm,
        /// A file containing the password needed to unlock and use the key.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        ///
        /// Additional users can be granted access to this key with different passwords.
        #[arg(short, long, default_value = None)]
        password_file: Option<PathBuf>,
        /// The Siguldy username of the key administrator. This user can grant access to other users.
        admin: String,
        /// The name of the key in Siguldry.
        name: String,
    },

    /// Create an x509 certificate for a key.
    X509 {
        /// The user to authenticate as; this user must have access to the key used to sign the certificate.
        #[arg(short, long)]
        user_name: String,
        /// The name of the key in Siguldry to create a certificate for.
        #[arg(short, long)]
        key_name: String,
        /// The Common Name field to use in the certificate; the remaining portions of the subject are
        /// specified in the server configuration.
        #[arg(short, long)]
        common_name: String,
        /// The length of time the certificate is valid for in days (starts from the current time).
        #[arg(long)]
        validity_days: NonZeroU32,
        /// The name of the key to use when signing the key's x509 certificate.
        ///
        /// For certificate authorities, leave this blank to self-sign.
        #[arg(long)]
        certificate_authority: Option<String>,
        /// A file containing the password needed to unlock and use the certificate authority's key.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        #[arg(long, default_value = None)]
        ca_password_file: Option<PathBuf>,
        /// The purpose of the key.
        #[arg(value_enum)]
        usage: KeyUsage,
    },
    /// List available keys.
    List {},
}

#[derive(Debug, Clone, Copy, Default, PartialEq, clap::ValueEnum)]
#[non_exhaustive]
pub enum KeyUsage {
    #[default]
    CodeSigning,
    CertificateAuthority,
}

#[derive(clap::Subcommand, Debug)]
pub enum UserCommands {
    /// Add a new user to the database.
    ///
    /// Users need to be in the database to perform any remote operations.
    Create {
        /// The username of the new user.
        ///
        /// The name must be unique. Additionally, you must issue a client certificate with this
        /// name in the CommonName field to authenticate as this user.
        name: String,
    },
    /// Remove a user from the database.
    ///
    /// Users that are not in the database are not allowed to perform any operations on the server,
    /// regardless of whether their certificate is valid or not.
    Delete {
        /// The username of the user to delete.
        name: String,
    },
    /// List all users in the database.
    List {},
}
