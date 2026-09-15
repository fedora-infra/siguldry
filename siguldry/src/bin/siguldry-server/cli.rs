// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Define the command-line interface.
//!
//! This is where subcommands, the arguments, and their types are defined.

use std::{num::NonZeroU32, path::PathBuf};

use clap::Parser;
use siguldry::{protocol::KeyAlgorithm, server::crypto::KeyUsage};

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

    /// Emit logs when new tracing spans are created, and when they are closed.
    ///
    /// This is useful in debugging scenarios to trace functions and tasks, but can lead to rather
    /// verbose logs.
    #[arg(long)]
    pub span_events: bool,

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

/// The hash algorithm to use for the OpenPGP certificate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum OpenPgpHashAlgorithm {
    SHA256,
    #[default]
    SHA512,
    SHA3_256,
    SHA3_512,
}

impl From<OpenPgpHashAlgorithm> for sequoia_openpgp::types::HashAlgorithm {
    fn from(value: OpenPgpHashAlgorithm) -> Self {
        match value {
            OpenPgpHashAlgorithm::SHA256 => sequoia_openpgp::types::HashAlgorithm::SHA256,
            OpenPgpHashAlgorithm::SHA512 => sequoia_openpgp::types::HashAlgorithm::SHA512,
            OpenPgpHashAlgorithm::SHA3_256 => sequoia_openpgp::types::HashAlgorithm::SHA3_256,
            OpenPgpHashAlgorithm::SHA3_512 => sequoia_openpgp::types::HashAlgorithm::SHA3_512,
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct X509Options {
    /// The name to give to the new X.509 certificate in Siguldry.
    ///
    /// This needs to be unique with respect to the key.
    #[arg(long)]
    pub x509_cert_name: Option<String>,

    /// The Common Name field to use in the certificate; the remaining portions of the subject are
    /// specified in the server configuration.
    ///
    /// If not provided, the default is the name of the key.
    #[arg(long, requires = "x509_cert_name")]
    pub x509_common_name: Option<String>,

    /// The length of time the certificate is valid for in days (starts from the current time).
    ///
    /// The default is 730 days.
    #[arg(long, requires = "x509_cert_name", default_value = "730")]
    pub x509_validity_days: NonZeroU32,

    /// The planned usage of the key's X.509 certificate.
    #[arg(
        long,
        value_enum,
        requires = "x509_cert_name",
        default_value_t = KeyUsage::CodeSigning
    )]
    pub x509_usage: siguldry::server::crypto::KeyUsage,
}

impl Default for X509Options {
    fn default() -> Self {
        Self {
            x509_cert_name: Default::default(),
            x509_common_name: Default::default(),
            x509_validity_days: NonZeroU32::new(730).expect("Use a non-zero default"),
            x509_usage: Default::default(),
        }
    }
}

#[derive(clap::Args, Debug, Default)]
pub struct OpenPgpOptions {
    /// The name to give to the new OpenPGP certificate.
    #[arg(long, requires = "openpgp_user_id")]
    pub openpgp_cert_name: Option<String>,

    /// The user ID to use for the OpenPGP certificate.
    ///
    /// This is typically an email like "Signing Key <signing@example.com>".
    #[arg(long, requires = "openpgp_cert_name")]
    pub openpgp_user_id: Option<String>,

    /// The length of time the OpenPGP certificate is valid for in days.
    ///
    /// The default, zero, means no expiration date.
    #[arg(long, default_value = "0")]
    pub openpgp_validity_days: u32,

    /// The OpenPGP standard to use.
    ///
    /// For new key types, including ML-DSA, the RFC9580 profile is required.
    #[arg(
        long,
        value_enum,
        default_value_t = OpenPgpProfile::RFC4880,
        requires = "openpgp_cert_name",
    )]
    pub openpgp_profile: OpenPgpProfile,

    /// The hash algorithm to use in the OpenPGP certificate's signature.
    #[arg(
        long,
        value_enum,
        default_value_t = OpenPgpHashAlgorithm::SHA512,
        requires = "openpgp_cert_name",
    )]
    pub openpgp_hash_algorithm: OpenPgpHashAlgorithm,
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
    /// Remote users can perform limited actions like listing keys they can access, unlocking those
    /// keys, and requesting signatures using unlocked keys. Users authenticate via client TLS
    /// certificates. It is up to you to handle issuing and revoking those certificates after you
    /// create or remove a user. Users with valid certificates that are not present in the database
    /// are rejected.
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
    /// This creates a key pair and optionally, if the x509 or openpgp parameters are provided,
    /// X.509 and OpenPGP certificates respectively. Not all key types are supported by all OpenPGP
    /// profiles. In particular, OpenPGP only supports ML-DSA keys as part of a hybrid pair, so
    /// attempts to create an OpenPGP certificate for a plain ML-DSA key will fail.
    ///
    /// Once a key pair is generated, you can create an X509 certificate for it with the "x509" key
    /// subcommand or an OpenPGP certificate with the "openpgp" subcommand. Keys can be used for
    /// both X509 and OpenPGP as long as the key type is valid for both.
    Create {
        /// The key algorithm to use.
        #[arg(short, long, value_enum, default_value_t, ignore_case = true)]
        algorithm: KeyAlgorithm,

        /// Create a hybrid key pair that meets the requirements for Sequoia OpenPGP.
        ///
        /// OpenPGP hybrid key pairs are actually two separate keys with several special
        /// requirements.  Keys using ML-DSA-65 must be paired with an Ed25519 key, and keys using
        /// ML-DSA-87 must be paired with an Ed448 key. Additionally, OpenPGP tooling exposed these
        /// two keys as a single key to users, so the tooling expects the keys to use the same
        /// password to access them.
        ///
        /// When this flag is passed, two keys are created with the same password, and the other
        /// key's name is the same as this key's name with the algorithm as a suffix. Other
        /// management commands like issuing OpenPGP certificates and granting or removing user
        /// access take into account that it's part of a hybrid pair and will operate on both keys,
        /// and either key can be referenced in those commands.
        ///
        /// As an example, if the key name provided is "my-signing-key" and the algorithm is
        /// ML-DSA-87, a second key will be created named "my-signing-key-ed448".
        #[arg(long)]
        openpgp_hybrid_pair: bool,

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

        #[command(flatten)]
        x509_options: X509Options,

        #[command(flatten)]
        openpgp_options: OpenPgpOptions,
    },

    /// Create an x509 certificates for a key.
    #[command(group(clap::ArgGroup::new("x509_certificate").required(true).args(["x509_cert_name"])))]
    X509 {
        /// The user to authenticate as; this user must have access to the key used to sign the certificate.
        #[arg(short, long)]
        user_name: String,

        /// The name of the key in Siguldry to create a certificate for.
        #[arg(short, long)]
        key_name: String,

        #[command(flatten)]
        x509_options: X509Options,

        /// The name of the key to use when signing the key's x509 certificate.
        ///
        /// Leave this, and other --ca-* options blank to self-sign.
        #[arg(long, default_value = None, requires = "ca_cert_name")]
        ca_key_name: Option<String>,

        /// The name of the certificate associated with the key specified in --ca-key-name.
        ///
        /// Keys may have multiple certificates associated with them. If unspecified, the
        /// most recently created certificate associated with the key is used.
        #[arg(long, default_value = None, requires = "ca_key_name")]
        ca_cert_name: Option<String>,

        /// A file containing the password needed to unlock and use the certificate authority's key.
        ///
        /// If this is a self-signed certificate, the password for the key specified in --key-name is
        /// required.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        #[arg(long, default_value = None)]
        ca_password_file: Option<PathBuf>,

        /// A file containing the PIN for the PKCS#11 token used in binding (if any).
        ///
        /// The file should include the PIN on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin (if binding is configured).
        #[arg(long, default_value = None)]
        pkcs11_binding_pin: Option<PathBuf>,
    },

    /// Create an OpenPGP certificate for a key.
    ///
    /// Not all key types supported by Siguldry can be used for OpenPGP. At this time,
    /// OpenPGP does not allow plain ML-DSA keys, for example.
    ///
    /// Note that if you plan to use this key from a client via gnupg-pkcs11-scd, you
    /// must also create an X509 certificate for the key pair, or the key will NOT be
    /// discovered.
    #[command(group(clap::ArgGroup::new("openpgp_certificate").required(true).args(["openpgp_cert_name"])))]
    Openpgp {
        /// The user to authenticate as; this user must have access to the key.
        #[arg(short, long)]
        user_name: String,

        /// The name of the key in Siguldry to create an OpenPGP certificate for.
        #[arg(short, long)]
        key_name: String,

        /// A file containing the password needed to unlock and use the key.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        #[arg(long, default_value = None)]
        password_file: Option<PathBuf>,

        /// A file containing the PIN for the PKCS#11 token used in binding (if any).
        ///
        /// The file should include the PIN on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin (if binding is configured).
        #[arg(long, default_value = None)]
        pkcs11_binding_pin: Option<PathBuf>,

        #[command(flatten)]
        openpgp_options: OpenPgpOptions,
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

    /// Grant a user access to a key.
    ///
    /// This command requires a number of credentials, which are read from stdin in the following
    /// order if files are not provided:
    ///
    /// 1. PKCS#11 PIN (if needed).
    /// 2. Existing user's access password.
    /// 3. New user's password.
    ///
    /// Note: if the key was created with "--openpgp-hybrid-pair", granting access to either key
    /// in the pair grants the user access to both keys.
    GrantKeyAccess {
        /// A file containing the PIN for the PKCS#11 token used in binding (if any).
        ///
        /// The file should include the PIN on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin (if binding is configured).
        #[arg(long, default_value = None)]
        pkcs11_binding_pin: Option<PathBuf>,
        /// The name of the key to grant the user access to.
        key: String,
        /// The name of the user who already has access to the key.
        ///
        /// You will need their access passphrase to grant the user access.
        existing_user: String,
        /// A file containing the key access passphrase of the existing user.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        #[arg(long, default_value = None)]
        existing_user_password_file: Option<PathBuf>,
        /// The name of the user who is being granted access to the key.
        user: String,
        /// A file containing the key access passphrase of the new user.
        ///
        /// The file should include the password on the first line and the file should include a newline.
        /// If this option is not provided, input is read from stdin.
        #[arg(long, default_value = None)]
        user_password_file: Option<PathBuf>,
    },

    /// Remove a user's access to a key.
    ///
    /// Note: if the key was created with "--openpgp-hybrid-pair", removing access to either key
    /// in the pair removes the user's access to both keys.
    RevokeKeyAccess {
        /// The name of the key to revoke access from.
        key: String,
        /// The name of the user whose access should be revoked.
        user: String,
    },

    /// List all users in the database.
    List {},
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_algorithm_is_case_insensitive() {
        for (value, expected) in [
            ("RSA2K", KeyAlgorithm::Rsa2K),
            ("RSA4K", KeyAlgorithm::Rsa4K),
            ("P256", KeyAlgorithm::P256),
            ("ED25519", KeyAlgorithm::Ed25519),
            ("ED448", KeyAlgorithm::Ed448),
            ("MLDSA65", KeyAlgorithm::Mldsa65),
            ("MLDSA87", KeyAlgorithm::Mldsa87),
        ] {
            for value in [value, value.to_lowercase().as_str()] {
                let cli = Cli::try_parse_from([
                    "siguldry-server",
                    "manage",
                    "key",
                    "create",
                    "--algorithm",
                    value,
                    "admin",
                    "key-name",
                ])
                .unwrap();

                match cli.command {
                    Command::Manage(ManagementCommands::Key(KeyCommands::Create {
                        algorithm,
                        ..
                    })) => assert_eq!(algorithm, expected),
                    _ => panic!("Incorrect command"),
                }
            }
        }
    }
}
