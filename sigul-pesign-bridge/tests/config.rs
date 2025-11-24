// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::process::{Command, Stdio};

use anyhow::Result;
use assert_cmd::cargo;

#[test]
fn config_with_default_works() -> Result<()> {
    let mut creds_directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    creds_directory.push("../devel/creds/");
    let mut command = Command::new(cargo::cargo_bin!("sigul-pesign-bridge"));
    let output = command
        .env("CREDENTIALS_DIRECTORY", creds_directory)
        .arg("config")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()?;
    let logs = String::from_utf8_lossy(&output.stdout);
    println!("cli_stdout: {logs}");
    println!("cli_stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success());
    assert!(logs.contains("[sigul]"));
    assert!(logs.contains("[[keys]]"));

    Ok(())
}
