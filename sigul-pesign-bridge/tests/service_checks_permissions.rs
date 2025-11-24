// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::Result;
use assert_cmd::cargo;

#[test]
fn stops_world_readable() -> Result<()> {
    let socket_dir = tempfile::tempdir()?;
    let mut creds_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    creds_directory.push("../devel/creds/");

    rustix::process::umask(rustix::fs::Mode::empty());
    let mut command = Command::new(cargo::cargo_bin!("sigul-pesign-bridge"));
    let output = command
        .env("SIGUL_PESIGN_BRIDGE_LOG", "trace")
        .env("RUNTIME_DIRECTORY", socket_dir.path())
        .env("CREDENTIALS_DIRECTORY", creds_directory)
        .arg("listen")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()?;
    let logs = String::from_utf8_lossy(&output.stderr);
    println!("service_stderr: {logs}");
    assert!(!output.status.success());
    assert!(logs.contains("Other users have access to the socket, adjust the service umask!"));

    Ok(())
}
