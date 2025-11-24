// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.
//
// Tests the integration with pesign-client.
//
// These tests require that the `pesign-client` binary be in your PATH.
// Additionally, since pesign-client doesn't offer a way to configure
// the socket it connects to, the user running the test must be able to
// read/write to `/run/pesign/socket`.

use std::{
    io::Write,
    net::TcpListener,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::{Mutex, Once},
    thread,
    time::Duration,
};

use anyhow::{anyhow, Result};
use assert_cmd::cargo;
use rustix::{
    fs::Mode,
    process::{kill_process, Pid},
};
use tempfile::NamedTempFile;

static UMASK: Once = Once::new();

// Since pesign-client can't have its socket path configured, we need to limit
// the tests to ensure one server is running at a time :(
static SOCKET_PERMIT: Mutex<()> = Mutex::new(());

fn run_command(
    mut client_command: Command,
    service_config: Option<PathBuf>,
) -> Result<(Output, Output)> {
    UMASK.call_once(|| {
        let mut umask = Mode::empty();
        umask.insert(Mode::RWXO);
        rustix::process::umask(umask);
    });
    let _socket_permit = SOCKET_PERMIT.lock().unwrap();

    let working_dir = "/run/pesign/";
    let socket_path = "/run/pesign/socket";
    if let Ok(_metadata) = std::fs::metadata(socket_path) {
        return Err(anyhow!(
            "{socket_path} exists; unable to start test instance"
        ));
    };
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../")
        .canonicalize()?;
    let creds_directory = repo_root.join("devel/creds/");

    let config_file = service_config.unwrap_or_else(|| {
        if std::env::var("GITHUB_ACTIONS").is_ok_and(|val| val.contains("true")) {
            repo_root.join("devel/github/config.toml")
        } else {
            repo_root.join("devel/local/config.toml")
        }
    });

    let mut server_command = Command::new(cargo::cargo_bin!("sigul-pesign-bridge"));
    server_command
        .env("RUNTIME_DIRECTORY", working_dir)
        .env("CREDENTIALS_DIRECTORY", creds_directory)
        .env("SIGUL_PESIGN_BRIDGE_LOG", "trace")
        .env("SIGUL_PESIGN_BRIDGE_CONFIG", config_file)
        .arg("listen")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());
    let mut service = server_command.spawn()?;
    let service_id = service.id().try_into()?;

    let mut tries = 0;
    while let Err(error) = std::fs::metadata(socket_path) {
        std::thread::sleep(Duration::from_millis(5));
        tries += 1;
        if tries > 100 {
            if let Ok(Some(status)) = service.try_wait() {
                let service_output = service.wait_with_output()?;
                println!(
                    "exited: {:?}\nservice_stderr: {}",
                    status,
                    String::from_utf8_lossy(&service_output.stderr)
                );
            }
            return Err(anyhow!("Failed to start service: {error:?}"));
        }
    }
    // Need to read stderr/out concurrently to avoid hanging
    let service = std::thread::spawn(|| service.wait_with_output());

    let client_output = client_command.output()?;
    println!(
        "client_stdout: {}",
        String::from_utf8_lossy(&client_output.stdout)
    );
    println!(
        "client_stderr: {}",
        String::from_utf8_lossy(&client_output.stderr)
    );

    kill_process(
        Pid::from_raw(service_id).unwrap(),
        rustix::process::Signal::TERM,
    )?;
    let service_output = service.join().unwrap()?;
    println!(
        "service_stderr: {}",
        String::from_utf8_lossy(&service_output.stderr)
    );

    Ok((client_output, service_output))
}

// Assert the bridge handles the upstream Sigul server being unresponsive
// and reports the failure to the client.
#[test]
fn signing_times_out() -> Result<()> {
    let output_dir = tempfile::tempdir()?;
    let out_file = output_dir.path().join("sample-uefi.signed.efi");
    let mut in_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    in_file.push("../target/x86_64-unknown-uefi/debug/sample-uefi.efi");

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let server_address = listener.local_addr()?;
    let _server_thread = thread::spawn(move || {
        let mut conns = vec![];
        for stream in listener.incoming() {
            conns.push(stream);
        }
    });

    let config_path = output_dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
                total_request_timeout_secs = 3
                sigul_request_timeout_secs = 1

                [sigul]
                bridge_hostname = "localhost"
                bridge_port = {}
                server_hostname = "localhost"
                sigul_user_name = "sigul-client"
                private_key = "sigul.client.private_key.pem"
                client_certificate = "sigul.client.certificate.pem"
                ca_certificate = "sigul.ca_certificate.pem"

                [[keys]]
                pesign_token_name = "OpenSC Card"
                pesign_certificate_name = "whatever pesign asked for"
                key_name = "Sigul HSM Key"
                certificate_name = "Secure Boot Code Signing Certificate"
                passphrase_path = "sigul.signing-key-passphrase"
            "#,
            server_address.port()
        ),
    )?;

    let mut client_command = Command::new("pesign-client");
    client_command
        .arg("--sign")
        .arg("--token=OpenSC Card")
        .arg("--certificate=whatever pesign asked for")
        .arg(format!("--infile={}", in_file.as_path().display()))
        .arg(format!("--outfile={}", &out_file.as_path().display()));
    let (client_output, service_output) = run_command(client_command, Some(config_path))?;

    assert!(!client_output.status.success());
    assert_eq!(
        "pesign-client: signing failed: \"\"\n",
        String::from_utf8_lossy(&client_output.stderr)
    );
    assert!(service_output.status.success());
    let service_logs = String::from_utf8_lossy(&service_output.stderr);
    assert!(service_logs.contains("Sigul signing request timed out; retrying..."));

    Ok(())
}

// Assert the bridge handles the abrupt disconnections from Sigul
#[test]
fn signing_hangs_up() -> Result<()> {
    let output_dir = tempfile::tempdir()?;
    let out_file = output_dir.path().join("sample-uefi.signed.efi");
    let mut in_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    in_file.push("../target/x86_64-unknown-uefi/debug/sample-uefi.efi");

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let server_address = listener.local_addr()?;
    let _server_thread = thread::spawn(move || {
        for stream in listener.incoming() {
            // Rudely hang up.
            drop(stream);
        }
    });

    let config_path = output_dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
                total_request_timeout_secs = 3
                sigul_request_timeout_secs = 1

                [sigul]
                bridge_hostname = "localhost"
                bridge_port = {}
                server_hostname = "localhost"
                sigul_user_name = "sigul-client"
                private_key = "sigul.client.private_key.pem"
                client_certificate = "sigul.client.certificate.pem"
                ca_certificate = "sigul.ca_certificate.pem"

                [[keys]]
                pesign_token_name = "OpenSC Card"
                pesign_certificate_name = "whatever pesign asked for"
                key_name = "Sigul HSM Key"
                certificate_name = "Secure Boot Code Signing Certificate"
                passphrase_path = "sigul.signing-key-passphrase"
            "#,
            server_address.port()
        ),
    )?;

    let mut client_command = Command::new("pesign-client");
    client_command
        .arg("--sign")
        .arg("--token=OpenSC Card")
        .arg("--certificate=whatever pesign asked for")
        .arg(format!("--infile={}", in_file.as_path().display()))
        .arg(format!("--outfile={}", &out_file.as_path().display()));
    let (client_output, service_output) = run_command(client_command, Some(config_path))?;

    assert!(!client_output.status.success());
    assert_eq!(
        "pesign-client: signing failed: \"\"\n",
        String::from_utf8_lossy(&client_output.stderr)
    );
    assert!(service_output.status.success());
    let service_logs = String::from_utf8_lossy(&service_output.stderr);
    assert!(service_logs.contains("signing failed; retrying sigul request in 2 seconds"));

    Ok(())
}

#[test]
fn sign_attached() -> Result<()> {
    let output_dir = tempfile::tempdir()?;
    let out_file = output_dir.path().join("sample-uefi.signed.efi");
    let mut in_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    in_file.push("../target/x86_64-unknown-uefi/debug/sample-uefi.efi");

    let mut client_command = Command::new("pesign-client");
    client_command
        .arg("--sign")
        .arg("--token=OpenSC Card")
        .arg("--certificate=whatever pesign asked for")
        .arg(format!("--infile={}", in_file.as_path().display()))
        .arg(format!("--outfile={}", &out_file.as_path().display()));
    let (client_output, service_output) = run_command(client_command, None)?;

    assert!(client_output.status.success());
    assert!(service_output.status.success());

    let input_signature_list = Command::new("sbverify")
        .arg("--list")
        .arg(in_file.as_path())
        .output()?;
    println!("{}", String::from_utf8_lossy(&input_signature_list.stderr));
    println!(
        "stdout: {}",
        String::from_utf8_lossy(&input_signature_list.stdout)
    );
    let output_signature_list = Command::new("sbverify")
        .arg("--list")
        .arg(&out_file)
        .output()?;
    println!("{}", String::from_utf8_lossy(&output_signature_list.stderr));
    println!(
        "stdout: {}",
        String::from_utf8_lossy(&output_signature_list.stdout)
    );

    let mut signing_cert = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    signing_cert.push("../devel/creds/secure-boot-code-signing-cert.pem");
    let output_signed = Command::new("sbverify")
        .arg("--cert")
        .arg(&signing_cert)
        .arg(&out_file)
        .output()?;
    assert!(output_signed.status.success());
    let input_signed = Command::new("sbverify")
        .arg("--cert")
        .arg(signing_cert)
        .arg(in_file)
        .output()?;
    assert!(!input_signed.status.success());

    Ok(())
}

// Test the daemon reponds gracefully to the unlock command, which is not supported.
#[test]
fn unlock() -> Result<()> {
    let mut pinfile = NamedTempFile::new()?;
    pinfile.write_all(b"secret_password\n")?;

    let mut client_command = Command::new("pesign-client");
    client_command
        .arg("--unlock")
        .arg(format!("--pinfile={}", pinfile.path().display()))
        .arg("--token=Test Cert DB");
    let (client_output, service_output) = run_command(client_command, None)?;

    assert!(!client_output.status.success());
    assert_eq!(
        "pesign-client: command \"unlock-token\" not known by server\n",
        String::from_utf8_lossy(&client_output.stderr)
    );
    assert!(service_output.status.success());
    let service_logs = String::from_utf8_lossy(&service_output.stderr);
    assert!(service_logs.contains(
        "Client queried for the server version of command UnlockToken, which is not supported"
    ));

    Ok(())
}

// Test the daemon reponds gracefully to the kill command, which is not supported.
#[test]
fn kill() -> Result<()> {
    let mut client_command = Command::new("pesign-client");
    client_command.arg("--kill");
    let (client_output, service_output) = run_command(client_command, None)?;

    assert!(!client_output.status.success());
    assert_eq!(
        "pesign-client: command \"kill-daemon\" not known by server\n",
        String::from_utf8_lossy(&client_output.stderr)
    );
    assert!(service_output.status.success());
    let service_logs = String::from_utf8_lossy(&service_output.stderr);
    assert!(service_logs
        .contains("Client queried for the server version of command Kill, which is not supported"));

    Ok(())
}
