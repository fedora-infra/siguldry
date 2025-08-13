use std::{path::PathBuf, time::Duration};

use anyhow::Context;
use sequoia_openpgp::crypto::Password;
use siguldry::server::Config;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

// Location of the socket, relative to $RUNTIME_DIRECTORY
pub const SOCKET_PATH: &str = "pin-entry.socket";

pub async fn read(config: &mut Config) -> anyhow::Result<()> {
    let binding = config
        .pkcs11_bindings
        .iter_mut()
        .find(|b| b.private_key.is_some())
        .ok_or_else(|| {
            anyhow::anyhow!("Server configuration has no bindings with a 'private_key' set!")
        })?;

    let private_key = binding.private_key.as_ref().unwrap();
    if let Some(pin) = private_key
        .split(";")
        .find_map(|s| s.strip_prefix("pin-value="))
        .map(Password::from)
    {
        binding.pin = Some(pin);
        tracing::error!(
            "pkcs11 URI contains a PIN; this should not be used in production deployments"
        );
        return Ok(());
    }

    let runtime_directory = std::env::var("RUNTIME_DIRECTORY")
        .context("The RUNTIME_DIRECTORY must be set and be protected as systemd does")
        .map(PathBuf::from)?;
    let socket_path = runtime_directory.join(SOCKET_PATH);
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind to {}", &socket_path.display()))?;

    tracing::info!(
        ?socket_path,
        "Requesting PIN via Unix socket; provide a pin with 'siguldry-server enter-pin'"
    );
    let connection = loop {
        match tokio::time::timeout(Duration::from_secs(300), listener.accept()).await {
            Ok(Ok((connection, _addr))) => break connection,
            Ok(Err(error)) => tracing::warn!(?error, "Unable to read PIN, retrying..."),
            Err(_) => tracing::error!(
                ?socket_path,
                "The server cannot proceed without an unbinding PIN; \
                please use 'siguldry-server enter-pin' to provide one"
            ),
        }
    };
    let (mut read_half, mut write_half) = connection.into_split();

    write_half.write_all(private_key.as_bytes()).await?;
    drop(write_half);
    let mut pin = String::new();
    read_half.read_to_string(&mut pin).await?;
    binding.pin = Some(Password::from(pin));

    if let Err(error) = std::fs::remove_file(&socket_path) {
        tracing::warn!(?socket_path, ?error, "Failed to clean up socket");
    }
    tracing::info!("Successfully read PIN to unbind keys");

    Ok(())
}
