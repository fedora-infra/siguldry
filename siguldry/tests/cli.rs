#![cfg(all(feature = "server", feature = "cli"))]

use siguldry::server::db;
use siguldry_test::{InstanceBuilder, keys};

#[tokio::test]
async fn pkcs11_list_no_tokens() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().build().await?;

    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("siguldry-server"))
        .arg("--config")
        .arg(instance.state_dir.path().join("server.toml"))
        .args(["manage", "pkcs11", "list"])
        .assert()
        .success()
        .stdout("No PKCS#11 tokens registered\n");

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
async fn pkcs11_unregister_requires_remove_key_accesses() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_hsm_rsa_key()
        .with_hsm_ec_key()
        .build()
        .await?;
    let pool = db::pool(instance.server_config.database().to_str().unwrap(), true).await?;
    let mut conn = pool.acquire().await?;
    let token = db::Pkcs11Token::list(&mut conn).await?.pop().unwrap();
    let token_keys = db::Key::get_token_keys(&mut conn, &token).await?;

    let result = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("siguldry-server"))
        .arg("--config")
        .arg(instance.state_dir.path().join("server.toml"))
        .args(["manage", "pkcs11", "unregister", &token.serial_number])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&result.get_output().stderr);
    assert!(
        stderr.contains(
            format!(
                "Error: Failed to unregister PKCS#11 token {}. \
            If users still have access to its keys, pass --remove-key-accesses \
            to remove their access records, or revoke access first.",
                token.serial_number,
            )
            .as_str()
        ),
        "{stderr:?}"
    );
    assert_eq!(db::Pkcs11Token::list(&mut conn).await?, vec![token.clone()]);
    assert_eq!(
        db::Key::get_token_keys(&mut conn, &token).await?,
        token_keys
    );

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
async fn pkcs11_unregister_removes_key_accesses() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_hsm_rsa_key()
        .with_hsm_ec_key()
        .build()
        .await?;
    let pool = db::pool(instance.server_config.database().to_str().unwrap(), true).await?;
    let mut conn = pool.acquire().await?;
    let token = db::Pkcs11Token::list(&mut conn).await?.pop().unwrap();
    let token_keys = db::Key::get_token_keys(&mut conn, &token).await?;
    assert_eq!(token_keys.len(), 2);

    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("siguldry-server"))
        .arg("--config")
        .arg(instance.state_dir.path().join("server.toml"))
        .args([
            "manage",
            "pkcs11",
            "unregister",
            &token.serial_number,
            "--remove-key-accesses",
        ])
        .assert()
        .success()
        .stdout(format!("Unregistered token {}\n", token.serial_number));

    assert!(db::Pkcs11Token::list(&mut conn).await?.is_empty());
    for key in token_keys {
        assert!(matches!(
            db::Key::get(&mut conn, &key.name).await,
            Err(sqlx::Error::RowNotFound)
        ));
    }

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
async fn pkcs11_unregister_empty_token() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().build().await?;
    let pool = db::pool(instance.server_config.database().to_str().unwrap(), false).await?;
    let mut conn = pool.acquire().await?;
    db::Pkcs11Token::create(
        &mut conn,
        "/unavailable/pkcs11.so".into(),
        "empty-token".to_string(),
        None,
        None,
        "abc123".to_string(),
        None,
    )
    .await?;

    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("siguldry-server"))
        .arg("--config")
        .arg(instance.state_dir.path().join("server.toml"))
        .args(["manage", "pkcs11", "unregister", "abc123"])
        .assert()
        .success()
        .stdout("Unregistered token abc123\n");

    assert!(db::Pkcs11Token::list(&mut conn).await?.is_empty());
    instance.halt().await?;
    Ok(())
}

#[tokio::test]
async fn pkcs11_unregister_nonexistent_token() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().build().await?;

    let result = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("siguldry-server"))
        .arg("--config")
        .arg(instance.state_dir.path().join("server.toml"))
        .args(["manage", "pkcs11", "unregister", "nonexistent"])
        .assert()
        .failure();
    assert!(
        String::from_utf8_lossy(&result.get_output().stderr)
            .contains("No registered PKCS#11 token has the specified serial number")
    );

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
async fn pkcs11_list_token() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new()
        .with_hsm_rsa_key()
        .with_hsm_ec_key()
        .build()
        .await?;
    let pool = db::pool(instance.server_config.database().to_str().unwrap(), true).await?;
    let mut conn = pool.acquire().await?;
    let tokens = db::Pkcs11Token::list(&mut conn).await?;
    assert_eq!(tokens.len(), 1);

    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("siguldry-server"))
        .arg("--config")
        .arg(instance.state_dir.path().join("server.toml"))
        .args(["manage", "pkcs11", "list"])
        .assert()
        .success()
        .stdout(format!(
            "Token: siguldry-test-token
  Serial number: {}
  Manufacturer: Kryoptic Project
  Model: v1
  Module: /usr/lib64/pkcs11/libkryoptic_pkcs11.so
  Concurrent requests: Unlimited
  Keys: 2
    \"{}\" (P256 key) (PKCS#11 ID: 2a)
    \"{}\" (rsa4k key) (PKCS#11 ID: 01)\n",
            tokens.first().unwrap().serial_number,
            keys::HSM_EC_KEY_NAME,
            keys::HSM_RSA_KEY_NAME,
        ));

    instance.halt().await?;
    Ok(())
}

#[tokio::test]
async fn pkcs11_list_empty_token() -> anyhow::Result<()> {
    let instance = InstanceBuilder::new().build().await?;
    let pool = db::pool(instance.server_config.database().to_str().unwrap(), false).await?;
    let mut conn = pool.acquire().await?;
    db::Pkcs11Token::create(
        &mut conn,
        "/some/pkcs11.so".into(),
        "token-with-no-keys".to_string(),
        None,
        None,
        "abc123".to_string(),
        None,
    )
    .await?;

    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("siguldry-server"))
        .arg("--config")
        .arg(instance.state_dir.path().join("server.toml"))
        .args(["manage", "pkcs11", "list"])
        .assert()
        .success()
        .stdout(concat!(
            "Token: token-with-no-keys\n",
            "  Serial number: abc123\n",
            "  Manufacturer: Unknown\n",
            "  Model: Unknown\n",
            "  Module: /some/pkcs11.so\n",
            "  Concurrent requests: Unlimited\n",
            "  Keys: 0\n",
        ));

    instance.halt().await?;
    Ok(())
}
