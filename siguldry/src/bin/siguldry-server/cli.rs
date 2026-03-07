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

/// The OpenPGP profile of the key
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum OpenPgpProfile {
    /// RFC9580, published in 2024, defines "v6" OpenPGP.
    RFC9580,

    /// RFC4880, published in 2007, defines "v4" OpenPGP.
    #[default]
    RFC4880,
}

impl From<OpenPgpProfile> for sequoia_openpgp::Profile {
    fn from(value: OpenPgpProfile) -> Self {
        match value {
            OpenPgpProfile::RFC9580 => sequoia_openpgp::Profile::RFC9580,
            OpenPgpProfile::RFC4880 => sequoia_openpgp::Profile::RFC4880,
        }
    }
}

#[derive(clap::Subcommand, Debug)]
pub enum ManagementCommands {
    /// Manage signing keys and certificates.
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

    /// Import data from a Sigul server.
    ImportSigul {
        /// The PKCS#11 URI for a private key capable of unbinding the Sigul keys if you
        /// use binding on the Sigul server.
        ///
        /// This should be the value provided in your Sigul server's [binding] section.
        /// For example, "pkcs11:serial=abc123;id=%01;type=private".
        #[arg(short, long)]
        binding_uri: Option<String>,

        /// The location of Sigul's data directory.
        sigul_data_directory: PathBuf,
    },

    /// Apply any database migrations.
    ///
    /// This should be run on first use to create an empty database. This should also be run after
    /// upgrading to a new version; it is a no-op if no new migrations are available.
    Migrate {},
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
        #[arg(long, default_value = None)]
        user_pin: Option<PathBuf>,
        /// A file containing the key access password needed to unlock and use the key.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        ///
        /// Additional users can be granted access to this key with different passwords.
        #[arg(long, default_value = None)]
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
    ///
    /// Note that all keys are created with an OpenPGP certificate and an X509 certificate. If you
    /// only plan to use the key for OpenPGP signatures you can safely use the default X509
    /// settings; similarly if you don't plan on using the key for OpenPGP you can safely use the
    /// default OpenPGP settings.
    ///
    /// For OpenPGP certificates, the server configuration file contains the user ID (email,
    /// typically) to use. Similarly, the X509 subject is configured in the server configuration
    /// file except for the common name.
    Create {
        /// The key algorithm to use.
        #[arg(short, long, value_enum, default_value_t)]
        algorithm: KeyAlgorithm,

        /// The OpenPGP standard to use; until you're certain all clients support the modern
        /// RFC9580 profile, it's best to stick with the default RFC4880 profile.
        ///
        /// Note that all keys are created with an OpenPGP certificate. If you don't plan to use this key
        /// for OpenPGP signatures the defaults are fine.
        #[arg(long, value_enum, default_value_t)]
        openpgp_profile: OpenPgpProfile,

        /// The length of time the X509 certificate is valid for in days (starts from the current time).
        #[arg(long, default_value = "730", value_parser = clap::value_parser!(u32).range(1..))]
        x509_validity_days: u32,

        /// The Common Name field to use in the certificate; the remaining portions of the subject are
        /// specified in the server configuration.
        ///
        /// If not provided, the default is the key's name.
        #[arg(long, default_value = None)]
        x509_common_name: Option<String>,

        /// The name of the key to use when signing the key's x509 certificate.
        ///
        /// If this is not provided, the certificate will be self-signed.
        #[arg(long, default_value = None)]
        x509_ca_key_name: Option<String>,

        /// The name of the certificate associated with the --x509-ca-key-name.
        ///
        /// Keys may have multiple certificates associated with them. If unspecified, the
        /// most recently created certificate associated with the key is used.
        #[arg(long, default_value = None)]
        x509_ca_cert_name: Option<String>,

        /// A file containing the password needed to unlock and use the certificate authority's key.
        ///
        /// This is not needed for self-signed certificates.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided AND the --x509-certificate-authority argument has been provided,
        /// The user is prompted to provide the password via stdin.
        #[arg(long, default_value = None)]
        x509_ca_password_file: Option<PathBuf>,

        /// The planned usage of the key.
        #[arg(long, value_enum, default_value_t)]
        x509_usage: siguldry::server::crypto::KeyUsage,

        /// A file containing the password needed to unlock and use the key.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        ///
        /// Additional users can be granted access to this key with different passwords.
        #[arg(long, default_value = None)]
        password_file: Option<PathBuf>,

        /// The Siguldy username of the key administrator. This user can grant access to other users.
        admin: String,

        /// The name of the key in Siguldry.
        name: String,
    },

    /// Create additional x509 certificates for a key.
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
        usage: siguldry::server::crypto::KeyUsage,
    },
    /// List available keys.
    List {},
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
