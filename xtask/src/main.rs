// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::anyhow;
use clap::CommandFactory;
use openssl::{pkey::PKey, rsa::Rsa, symm::Cipher};
use siguldry::v1::client::{CertificateType, Client, KeyType, TlsConfig};

const TASKS: [&str; 3] = ["manual", "extract-keys", "generate-sigul-data"];

fn main() -> anyhow::Result<()> {
    match env::args()
        .nth(1)
        .ok_or(anyhow!("Must provide a task"))?
        .as_str()
    {
        "manual" => generate_manual(),
        "extract-keys" => extract_keys(),
        "generate-sigul-data" => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(generate_sigul_data()),
        _ => Err(anyhow!("Unknown task, use one of {:?}", TASKS)),
    }
}

fn generate_manual() -> anyhow::Result<()> {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("../");

    let outdir = root.join("sigul-pesign-bridge/docs/");
    let command = sigul_pesign_bridge::cli::Cli::command();
    let manual = clap_mangen::Man::new(command);
    manual.generate_to(outdir)?;

    Ok(())
}

fn extract_keys() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let outdir = root.join("../devel/creds");
    let image = env::args()
        .nth(2)
        .unwrap_or_else(|| "quay.io/jeremycline/sigul-pesign-bridge-ci:latest".to_string());
    println!("Extracting keys from {}", &image);

    let mut command = std::process::Command::new("podman");
    command.args(["create", "--name=sigul-ci-key-extract", &image]);
    if !command.output()?.status.success() {
        anyhow::bail!("Failed to create container (have you pulled it?)");
    }

    // Drop the existing credentials or the new ones end up in devel/creds/creds
    let _ = std::fs::remove_dir_all(&outdir);
    let mut command = std::process::Command::new("podman");
    command.args(["cp", "sigul-ci-key-extract:/srv/siguldry/creds"]);
    command.arg(outdir);
    let output = command.output()?;
    if !output.status.success() {
        anyhow::bail!(
            "Failed to extract keys: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let mut command = std::process::Command::new("podman");
    command.args(["rm", "sigul-ci-key-extract"]);
    if !command.output()?.status.success() {
        anyhow::bail!("Failed to remove container 'sigul-ci-key-extract'");
    }

    Ok(())
}

/// Generate a sigul database for migration testing.
async fn generate_sigul_data() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../");
    let compose_file = root.join("compose.yml");
    let creds_dir = root.join("devel/creds");
    let outdir = root.join("devel/sigul-data");
    let _ = std::fs::remove_dir_all(&outdir);
    std::fs::create_dir_all(&outdir)?;

    const ADMIN_PASSPHRASE: &str = "my-admin-password";
    const GPG_PASSPHRASE: &str = "gpg-key-passphrase";
    const ECC_PASSPHRASE: &str = "ecc-key-passphrase";
    const RSA_PASSPHRASE: &str = "rsa-key-passphrase";
    const CA_PASSPHRASE: &str = "ca-key-passphrase";
    const AUTOSIGNER_USERNAME: &str = "autosigner";
    const AUTOSIGNER_PASSPHRASE: &str = "autosigner-password";
    const AUTOSIGNER_RSA_PASSPHRASE: &str = "autosigner-rsa-passphrase";
    const SIGULDRY_USERNAME: &str = "siguldry-client";
    const SIGULDRY_PASSPHRASE: &str = "siguldry-client-password";
    const SIGULDRY_GPG_PASSPHRASE: &str = "siguldry-gpg-key-passphrase";

    println!("Starting sigul server and bridge with podman-compose...");
    let mut command = Command::new("podman-compose");
    command
        .current_dir(&root)
        .args(["-f", compose_file.to_str().unwrap(), "up", "-d"]);
    let output = command.output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to start containers: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let tls_config = TlsConfig::new(
        creds_dir.join("sigul.client.certificate.pem"),
        creds_dir.join("sigul.client.private_key.pem"),
        None,
        creds_dir.join("sigul.ca_certificate.pem"),
    )?;
    let client = Client::new(
        tls_config,
        "localhost".to_string(),
        44334,
        "localhost".to_string(),
        "sigul-client".to_string(),
    );

    // It can take a bit for the server to connect to the bridge depending on
    // the order they come up in.
    let mut retries = 10;
    loop {
        match client.users(ADMIN_PASSPHRASE.into()).await {
            Ok(users) => {
                println!("Connected to Sigul server. Users: {:?}", users);
                break;
            }
            Err(e) if retries > 0 => {
                println!("Waiting for server to be ready ({retries} retries left): {e}");
                retries -= 1;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => {
                cleanup_containers(&root, &compose_file)?;
                return Err(anyhow::anyhow!(
                    "Failed to connect to server after retries: {e}"
                ));
            }
        }
    }

    client
        .create_user(
            ADMIN_PASSPHRASE.into(),
            AUTOSIGNER_USERNAME.to_string(),
            false,
            Some(AUTOSIGNER_PASSPHRASE.into()),
        )
        .await?;
    // Siguldry tests use the "siguldry-client" user by default so this makes setup easier
    client
        .create_user(
            ADMIN_PASSPHRASE.into(),
            SIGULDRY_USERNAME.to_string(),
            false,
            Some(SIGULDRY_PASSPHRASE.into()),
        )
        .await?;

    println!("Creating GPG key 'test-sigul-gpg-key'...");
    client
        .new_key(
            ADMIN_PASSPHRASE.into(),
            GPG_PASSPHRASE.into(),
            "test-sigul-gpg-key".to_string(),
            KeyType::GnuPG {
                real_name: Some("Test GPG Key".to_string()),
                comment: Some("For testing import".to_string()),
                email: Some("test@example.com".to_string()),
                expire_date: None,
            },
            None,
        )
        .await?;

    println!("Creating ECC key 'test-sigul-ca-key'...");
    client
        .new_key(
            ADMIN_PASSPHRASE.into(),
            CA_PASSPHRASE.into(),
            "test-sigul-ca-key".to_string(),
            KeyType::Ecc,
            None,
        )
        .await?;
    println!("Creating CA certificate for 'test-sigul-ca-key'...");
    client
        .sign_certificate(
            "test-sigul-ca-key".to_string(),
            CA_PASSPHRASE.into(),
            None,
            "test-sigul-ca-key".to_string(),
            "root".to_string(),
            CertificateType::Ca,
            "Test Root CA".to_string(),
            10,
        )
        .await?;

    // We have to import RSA keys since sigul crashes if asked to generate them
    println!("Importing RSA key 'test-sigul-rsa-key'...");
    let rsa_key_pem = {
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        pkey.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), RSA_PASSPHRASE.as_bytes())?
    };
    client
        .import_key(
            ADMIN_PASSPHRASE.into(),
            RSA_PASSPHRASE.into(),
            RSA_PASSPHRASE.into(),
            "test-sigul-rsa-key".to_string(),
            &rsa_key_pem,
            KeyType::Rsa,
            None,
        )
        .await?;
    println!("Creating code signing certificate for test-sigul-rsa-key...");
    client
        .sign_certificate(
            "test-sigul-ca-key".to_string(),
            CA_PASSPHRASE.into(),
            Some("root".to_string()),
            "test-sigul-rsa-key".to_string(),
            "codesigning".to_string(),
            CertificateType::CodeSigning,
            "Test Code Signing".to_string(),
            5,
        )
        .await?;

    println!("Creating ECC key 'test-sigul-ecc-key'...");
    client
        .new_key(
            ADMIN_PASSPHRASE.into(),
            ECC_PASSPHRASE.into(),
            "test-sigul-ecc-key".to_string(),
            KeyType::Ecc,
            None,
        )
        .await?;

    println!(
        "Granting key access for test-sigul-rsa-key to {}...",
        AUTOSIGNER_USERNAME
    );
    client
        .grant_key_access(
            ADMIN_PASSPHRASE.into(),
            "test-sigul-rsa-key".to_string(),
            RSA_PASSPHRASE.into(),
            AUTOSIGNER_USERNAME.to_string(),
            AUTOSIGNER_RSA_PASSPHRASE.into(),
            None,
            None,
        )
        .await?;
    client
        .grant_key_access(
            ADMIN_PASSPHRASE.into(),
            "test-sigul-gpg-key".to_string(),
            GPG_PASSPHRASE.into(),
            SIGULDRY_USERNAME.to_string(),
            SIGULDRY_GPG_PASSPHRASE.into(),
            None,
            None,
        )
        .await?;

    println!("Sigul keys in server:");
    for key in client.keys(ADMIN_PASSPHRASE.into()).await? {
        println!("\t{key}");
    }
    println!("Users in server:");
    for user in client.users(ADMIN_PASSPHRASE.into()).await? {
        println!("\t{user}");
    }

    // Dump a file that can be piped to the import-sigul command to answer all the
    // prompts correctly.
    //
    // The expected prompts here are
    //   - import sigul-client
    //     - import its access to the GPG key?
    //     - import its access to the CA key?
    //     - import its access to the RSA key?
    //     - import its access to the ECC key?
    //   - import autosigner
    //     - import its access to the RSA key?
    //   - import siguldry-client
    //     - import its access to the GPG key?
    let import_dialog_answer = format!(
        "y\n\
         y\n\
         {GPG_PASSPHRASE}\n\
         y\n\
         {CA_PASSPHRASE}\n\
         y\n\
         {RSA_PASSPHRASE}\n\
         y\n\
         {ECC_PASSPHRASE}\n\
         y\n\
         y\n\
         {AUTOSIGNER_RSA_PASSPHRASE}\n\
         y\n\
         y\n\
         {SIGULDRY_GPG_PASSPHRASE}\n"
    );
    std::fs::write(outdir.join("import-dialog-answers"), import_dialog_answer)?;

    let mut command = Command::new("podman-compose");
    command
        .current_dir(&root)
        .args(["-f", compose_file.to_str().unwrap(), "ps"]);
    let ps_output = String::from_utf8(command.output()?.stdout).unwrap();
    let container_id = if let Some(container_id) = ps_output
        .lines()
        .find(|l| l.contains("sigul-server"))
        .and_then(|l| l.split_whitespace().next())
    {
        container_id
    } else {
        cleanup_containers(&root, &compose_file)?;
        return Err(anyhow::anyhow!("Could not find sigul-server container"));
    };

    println!("Copying sigul data from container {container_id}...");
    let sigul_data_dir = outdir.join("sigul");
    let mut command = Command::new("podman");
    command.args([
        "cp",
        &format!("{container_id}:/var/lib/sigul"),
        sigul_data_dir.to_str().unwrap(),
    ]);
    let output = command.output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to copy /var/lib/sigul: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let softhsm_dir = outdir.join("softhsm");
    let mut command = Command::new("podman");
    command.args([
        "cp",
        &format!("{container_id}:/var/lib/softhsm"),
        softhsm_dir.to_str().unwrap(),
    ]);
    let output = command.output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to copy /var/lib/softhsm: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    cleanup_containers(&root, &compose_file)?;
    println!("Done! Sigul data extracted to {}", outdir.display());

    Ok(())
}

fn cleanup_containers(root: &Path, compose_file: &Path) -> anyhow::Result<()> {
    println!("Stopping containers...");
    let mut command = Command::new("podman-compose");
    command
        .current_dir(root)
        .args(["-f", compose_file.to_str().unwrap(), "down"]);
    let output = command.output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to stop containers: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}
