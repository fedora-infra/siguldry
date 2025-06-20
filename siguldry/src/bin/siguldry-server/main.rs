// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use siguldry::{
    config::load_config,
    server::{config::Config, db, service::Server},
};
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, EnvFilter};

// The path, relative to $XDG_CONFIG_HOME, of the default config file location.
const DEFAULT_CONFIG: &str = "siguldry/server.toml";

/// The siguldry signing server.
///
/// This includes a command to run the server, along with a set of management commands.
/// These include applying database migrations, creating new remote users, and so on.
///
/// To begin, you'll need to provide a configuration file. For an example of the current
/// format, consult the `config` subcommand.
///
/// Once you have a valid configuration, create a new database using the `manage migrate` subcommand.
///
/// Finally, create a remote user with the `manage users add` subcommand.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The path to the server's configuration file.
    ///
    /// If no path is provided, the defaults are used. To view the service configuration,
    /// run the `config` subcommand.
    #[arg(long, short, env = "SIGULDRY_SERVER_CONFIG")]
    config: Option<PathBuf>,

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
enum Command {
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
enum ManagementCommands {
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
enum UserCommands {
    Add {
        /// The username of the new user.
        ///
        /// The name must be unique. Additionally, you must issue a client certificate with this
        /// name in the CommonName field to authenticate as this user.
        name: String,
    },
    Remove {
        /// The username of the user to delete.
        name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();

    // Unfortunately we can't use clap's value_parser since EnvFilter does not
    // implement Clone.
    let log_filter = EnvFilter::builder().parse(&opts.log_filter).context(
        "SIGULDRY_SERVER_LOG contains an invalid log directive; refer to \
            https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/\
            filter/struct.EnvFilter.html#directives for format details.",
    )?;
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");

    let mut config = load_config::<Config>(opts.config, PathBuf::from(DEFAULT_CONFIG).as_path())?;

    match opts.command {
        Command::Listen {
            credentials_directory,
        } => {
            config
                .credentials
                .with_credentials_dir(&credentials_directory)?;

            let root_span = tracing::info_span!("server");
            async move {
                let server = Server::new(config).await?;
                let server = server.run();
                tokio::spawn(signal_handler(server.halt_token()));

                server.wait_to_finish().await?;
                Ok::<_, anyhow::Error>(())
            }
            .instrument(root_span)
            .await?;
        }
        Command::Config {
            credentials_directory,
        } => {
            println!("# This is the current configuration\n\n{config}\n# This concludes the configuration.\n");
            _ = config.credentials.with_credentials_dir(&credentials_directory).inspect_err(|error|{
                eprintln!("The configuration format is valid, but the referenced credentials aren't valid: {error:?}");
            });
        }
        Command::Manage(command) => {
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
                ManagementCommands::Users(user_commands) => match user_commands {
                    UserCommands::Add { name } => _ = db::User::create(&mut conn, &name).await?,
                    UserCommands::Remove { name } => {
                        let users_deleted = db::User::delete(&mut conn, &name).await?;
                        println!("Deleted {} user(s) from the database", users_deleted);
                    }
                },
                ManagementCommands::Migrate {} => db::migrate(&db_pool).await?,
            }
            conn.commit().await?;
        }
    };

    Ok(())
}

/// Install and manage signal handlers for the process.
///
/// # SIGTERM and SIGINT
///
/// Sending SIGTERM or SIGINT to the process will cause it to stop accepting new
/// signing requests. Existing signing requests will be allowed to complete
/// before the process shuts down.
async fn signal_handler(halt_token: CancellationToken) -> Result<(), anyhow::Error> {
    let mut sigterm_stream = signal(SignalKind::terminate()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGTERM signal handler");
    })?;
    let mut sigint_stream = signal(SignalKind::interrupt()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGINT signal handler");
    })?;

    loop {
        tokio::select! {
            _ = sigterm_stream.recv() => {
                tracing::info!("SIGTERM received, beginning service shutdown");
                halt_token.cancel();
            }
            _ = sigint_stream.recv() => {
                tracing::info!("SIGINT received, beginning service shutdown");
                halt_token.cancel();
            }
        }
    }
}
