// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.
//
// Integration tests for the siguldry client.
//
// These tests are expected to work against sigul v1.3+.

use std::path::PathBuf;

use siguldry::error::{ClientError, Sigul};
use tokio::sync::RwLock;

/// Some tests fiddle with the `sigul-client` account
static SIGUL_CLIENT: std::sync::LazyLock<RwLock<()>> = std::sync::LazyLock::new(|| RwLock::new(()));

fn get_client() -> siguldry::client::Client {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../")
        .canonicalize()
        .unwrap();
    let creds_directory = repo_root.join("devel/creds/");
    let tls_config = siguldry::client::TlsConfig::new(
        creds_directory.join("sigul.client.certificate.pem"),
        creds_directory.join("sigul.client.private_key.pem"),
        None,
        creds_directory.join("sigul.ca_certificate.pem"),
    )
    .unwrap();
    let ci = std::env::var("GITHUB_ACTIONS").is_ok_and(|val| val.contains("true"));
    siguldry::client::Client::new(
        tls_config,
        if ci {
            "sigul-bridge".into()
        } else {
            "localhost".into()
        },
        44334,
        if ci {
            "sigul-server".into()
        } else {
            "localhost".into()
        },
        "sigul-client".into(),
    )
}

// Assert our user is in the list somewhere; since this runs at the same time
// as tests that create and remove users this is the best we can do.
#[tokio::test]
async fn list_users() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let expected_user = "sigul-client".to_string();
    let users = client.users("my-admin-password".into()).await?;

    assert!(users.contains(&expected_user));
    Ok(())
}

#[tokio::test]
async fn get_user() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let user = client
        .get_user("my-admin-password".into(), "sigul-client".to_string())
        .await?;

    assert!(user.admin());
    assert_eq!(user.name(), "sigul-client");
    Ok(())
}

#[tokio::test]
async fn get_user_does_not_exist() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let user = client
        .get_user("my-admin-password".into(), "not-sigul-client".to_string())
        .await;
    match user {
        Err(ClientError::Sigul(Sigul::UserNotFound)) => {}
        _ => panic!("Expected a Sigul error, got {:?}", user),
    }

    Ok(())
}

#[tokio::test]
async fn get_user_invalid_password() -> anyhow::Result<()> {
    let client = get_client();
    let user = client
        .get_user("not-my-admin-password".into(), "sigul-client".to_string())
        .await;
    if !matches!(user, Err(ClientError::Sigul(Sigul::AuthenticationFailed))) {
        panic!("Expected a Sigul error, got {:?}", user)
    }

    Ok(())
}

#[tokio::test]
async fn create_user_no_password() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let cleanup = client
        .delete_user("my-admin-password".into(), "no-password-user".to_string())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::UserNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }

    client
        .create_user(
            "my-admin-password".into(),
            "no-password-user".to_string(),
            false,
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), "no-password-user".to_string())
        .await?;

    assert_eq!(user.name(), "no-password-user");
    assert!(!user.admin());
    Ok(())
}

#[tokio::test]
async fn create_user_with_password() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let cleanup = client
        .delete_user("my-admin-password".into(), "with-password-user".to_string())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::UserNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }

    client
        .create_user(
            "my-admin-password".into(),
            "with-password-user".to_string(),
            true,
            Some("with-password".into()),
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), "with-password-user".to_string())
        .await?;

    assert_eq!(user.name(), "with-password-user");
    assert!(user.admin());
    Ok(())
}

#[tokio::test]
async fn modify_user_toggle_admin() -> anyhow::Result<()> {
    let test_user = "modify-admin-user";
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let cleanup = client
        .delete_user("my-admin-password".into(), test_user.to_string())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::UserNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }
    client
        .create_user(
            "my-admin-password".into(),
            test_user.to_string(),
            false,
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert!(!user.admin());

    // Promote the user to admin
    client
        .modify_user(
            "my-admin-password".into(),
            test_user.to_string(),
            None,
            Some(true),
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert!(user.admin());

    // Return the user to non-admin
    client
        .modify_user(
            "my-admin-password".into(),
            test_user.to_string(),
            None,
            Some(false),
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert!(!user.admin());
    Ok(())
}

#[tokio::test]
async fn modify_user_change_name() -> anyhow::Result<()> {
    let test_user = "modify-user-change-name";
    let test_user_new_name = "modified-name";

    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let cleanup = client
        .delete_user("my-admin-password".into(), test_user.to_string())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::UserNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }
    client
        .create_user(
            "my-admin-password".into(),
            test_user.to_string(),
            false,
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert_eq!(user.name(), test_user);

    // Change the user's name
    client
        .modify_user(
            "my-admin-password".into(),
            test_user.to_string(),
            Some(test_user_new_name.to_string()),
            None,
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user_new_name.to_string())
        .await?;
    assert_eq!(user.name(), test_user_new_name);
    assert!(!user.admin());

    // Return the user to the original name and promote it to admin
    client
        .modify_user(
            "my-admin-password".into(),
            test_user_new_name.to_string(),
            Some(test_user.to_string()),
            Some(true),
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert_eq!(user.name(), test_user);
    assert!(user.admin());

    Ok(())
}

#[tokio::test]
async fn modify_user_change_password() -> anyhow::Result<()> {
    let test_user = "sigul-client";

    let client = get_client();
    let _guard = SIGUL_CLIENT.write().await;
    _ = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;

    // Change the user's password and verify the old one doesn't work
    client
        .modify_user(
            "my-admin-password".into(),
            test_user.to_string(),
            None,
            None,
            Some("my-new-admin-password".into()),
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await;
    if !matches!(user, Err(ClientError::Sigul(Sigul::AuthenticationFailed))) {
        panic!("The user's old password still works!");
    }
    _ = client
        .get_user("my-new-admin-password".into(), test_user.to_string())
        .await?;

    // Set the password back to the original
    client
        .modify_user(
            "my-new-admin-password".into(),
            test_user.to_string(),
            None,
            Some(true),
            Some("my-admin-password".into()),
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert_eq!(user.name(), test_user);
    assert!(user.admin());

    Ok(())
}

/// Test that a key created with no owner is owned by the creating user.
#[tokio::test]
async fn key_user_info_self_owner() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let key_name = "gpg-key-self-owner".to_string();
    let cleanup = client
        .delete_key("my-admin-password".into(), key_name.clone())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::KeyNotFound))) {
        panic!(
            "unexpected Sigul error while cleaning up, got {:?}",
            cleanup
        )
    }

    let key = client
        .new_key(
            "my-admin-password".into(),
            "my-key-passphrase".into(),
            key_name.clone(),
            siguldry::client::KeyType::GnuPG,
            None,
            Some("my real name".to_string()),
            Some("This is a test GPG key".to_string()),
            Some("gpg@example.com".to_string()),
            None,
        )
        .await?;
    assert_eq!(key.key_name(), &key_name);
    key.as_string().expect("key should be valid UTF-8");

    let key = client
        .key_user_info(
            "my-admin-password".into(),
            "sigul-client".to_string(),
            key_name.clone(),
        )
        .await?;
    assert_eq!(key.key(), &key_name);
    assert_eq!(key.user(), "sigul-client");
    assert!(key.admin());

    Ok(())
}

/// Test that a key created with an explicit owner is owned by that user.
#[tokio::test]
async fn key_user_info_other_owner() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let key_name = "gpg-key-other-owner".to_string();
    let test_user = "new-key-admin".to_string();
    let cleanup_key = client
        .delete_key("my-admin-password".into(), key_name.clone())
        .await;
    if cleanup_key.is_err() && !matches!(cleanup_key, Err(ClientError::Sigul(Sigul::KeyNotFound))) {
        panic!(
            "unexpected Sigul error while cleaning up, got {:?}",
            cleanup_key
        )
    }
    let cleanup_user = client
        .delete_user("my-admin-password".into(), test_user.clone())
        .await;
    if cleanup_user.is_err()
        && !matches!(cleanup_user, Err(ClientError::Sigul(Sigul::UserNotFound)))
    {
        panic!("Expected a Sigul error, got {:?}", cleanup_user)
    }

    client
        .create_user(
            "my-admin-password".into(),
            test_user.to_string(),
            false,
            None,
        )
        .await?;
    let key = client
        .new_key(
            "my-admin-password".into(),
            "my-key-passphrase".into(),
            key_name.clone(),
            siguldry::client::KeyType::GnuPG,
            Some(test_user.clone()),
            Some("my real name".to_string()),
            Some("This is a test GPG key".to_string()),
            Some("gpg@example.com".to_string()),
            None,
        )
        .await?;
    assert_eq!(key.key_name(), &key_name);
    key.as_string().expect("key should be valid UTF-8");

    let key = client
        .key_user_info(
            "my-admin-password".into(),
            test_user.clone(),
            key_name.clone(),
        )
        .await?;
    assert_eq!(key.key(), &key_name);
    assert_eq!(key.user(), &test_user);
    assert!(key.admin());

    let result = client
        .key_user_info(
            "my-admin-password".into(),
            "sigul-client".to_string(),
            key_name.clone(),
        )
        .await;

    if !matches!(result, Err(ClientError::Sigul(Sigul::KeyUserNotFound))) {
        panic!("Expected a Sigul error, got {:?}", result);
    }

    Ok(())
}

/// Test key owners can be modified to not be admins.
#[tokio::test]
async fn modify_key_user_demote_promote() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let key_name = "gpg-key-other-not-owner".to_string();
    let test_user = "new-key-not-admin".to_string();
    let cleanup_key = client
        .delete_key("my-admin-password".into(), key_name.clone())
        .await;
    if cleanup_key.is_err() && !matches!(cleanup_key, Err(ClientError::Sigul(Sigul::KeyNotFound))) {
        panic!(
            "unexpected Sigul error while cleaning up, got {:?}",
            cleanup_key
        )
    }
    let cleanup_user = client
        .delete_user("my-admin-password".into(), test_user.clone())
        .await;
    if cleanup_user.is_err()
        && !matches!(cleanup_user, Err(ClientError::Sigul(Sigul::UserNotFound)))
    {
        panic!("Expected a Sigul error, got {:?}", cleanup_user)
    }

    client
        .create_user(
            "my-admin-password".into(),
            test_user.to_string(),
            false,
            None,
        )
        .await?;
    let key = client
        .new_key(
            "my-admin-password".into(),
            "my-key-passphrase".into(),
            key_name.clone(),
            siguldry::client::KeyType::GnuPG,
            Some(test_user.clone()),
            Some("my real name".to_string()),
            Some("This is a test GPG key".to_string()),
            Some("gpg@example.com".to_string()),
            None,
        )
        .await?;
    assert_eq!(key.key_name(), &key_name);
    key.as_string().expect("key should be valid UTF-8");

    let key = client
        .key_user_info(
            "my-admin-password".into(),
            test_user.clone(),
            key_name.clone(),
        )
        .await?;
    assert_eq!(key.key(), &key_name);
    assert_eq!(key.user(), &test_user);
    assert!(key.admin());

    // Demote the user.
    client
        .modify_key_user(
            "my-admin-password".into(),
            test_user.clone(),
            key_name.clone(),
            Some(false),
        )
        .await?;

    let key = client
        .key_user_info(
            "my-admin-password".into(),
            test_user.clone(),
            key_name.clone(),
        )
        .await?;
    assert_eq!(key.key(), &key_name);
    assert_eq!(key.user(), &test_user);
    assert!(!key.admin());

    // Promote
    client
        .modify_key_user(
            "my-admin-password".into(),
            test_user.clone(),
            key_name.clone(),
            Some(true),
        )
        .await?;
    let key = client
        .key_user_info(
            "my-admin-password".into(),
            test_user.clone(),
            key_name.clone(),
        )
        .await?;
    assert_eq!(key.key(), &key_name);
    assert_eq!(key.user(), &test_user);
    assert!(key.admin());

    Ok(())
}

/// Test listing keys and asserting the created key is in the list.
#[tokio::test]
async fn key_create_and_list() -> anyhow::Result<()> {
    let client = get_client();
    let key_name = "gpg-key-create-list".to_string();
    let _guard = SIGUL_CLIENT.read().await;
    let cleanup = client
        .delete_key("my-admin-password".into(), key_name.clone())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::KeyNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }

    let key = client
        .new_key(
            "my-admin-password".into(),
            "my-key-passphrase".into(),
            key_name.clone(),
            siguldry::client::KeyType::GnuPG,
            None,
            Some("my real name".to_string()),
            Some("This is a test GPG key".to_string()),
            Some("gpg@example.com".to_string()),
            None,
        )
        .await?;
    assert_eq!(key.key_name(), &key_name);

    let keys = client.keys("my-admin-password".into()).await?;
    assert!(keys.iter().any(|k| *k
        == format!(
            "{} ({})",
            &key_name,
            siguldry::client::KeyType::GnuPG.to_string()
        )));

    client
        .delete_key("my-admin-password".into(), key_name)
        .await?;

    Ok(())
}

/// Test creating and then deleting a GPG key.
#[tokio::test]
async fn key_gpg_create_and_delete() -> anyhow::Result<()> {
    let client = get_client();
    let key_name = "gpg-key-create-delete".to_string();
    let _guard = SIGUL_CLIENT.read().await;
    let key = client
        .new_key(
            "my-admin-password".into(),
            "my-key-passphrase".into(),
            key_name.clone(),
            siguldry::client::KeyType::GnuPG,
            None,
            Some("my real name".to_string()),
            Some("This is a test GPG key".to_string()),
            Some("gpg@example.com".to_string()),
            None,
        )
        .await?;
    assert_eq!(key.key_name(), &key_name);

    client
        .delete_key("my-admin-password".into(), key_name)
        .await?;

    Ok(())
}

/// Test creating and then deleting an RSA key.
#[tokio::test]
#[ignore = "RSA key creation does not work in Sigul"]
async fn key_rsa_create_and_delete() {
    let client = get_client();
    let key_name = "rsa-key-create-delete".to_string();
    let _guard = SIGUL_CLIENT.read().await;
    let key = client
        .new_key(
            "my-admin-password".into(),
            "my-key-passphrase".into(),
            key_name.clone(),
            siguldry::client::KeyType::Rsa,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(key.key_name(), &key_name);

    client
        .delete_key("my-admin-password".into(), key_name)
        .await
        .unwrap();
}

/// Test creating and then deleting an ECC key.
#[tokio::test]
async fn key_ecc_create_and_delete() -> anyhow::Result<()> {
    let client = get_client();
    let key_name = "ecc-key-create-delete".to_string();
    let _guard = SIGUL_CLIENT.read().await;
    let key = client
        .new_key(
            "my-admin-password".into(),
            "my-key-passphrase".into(),
            key_name.clone(),
            siguldry::client::KeyType::Ecc,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(key.key_name(), &key_name);

    client
        .delete_key("my-admin-password".into(), key_name)
        .await?;

    Ok(())
}

/// Assert the correct error is returned when trying to delete a key that doesn't exist.
#[tokio::test]
async fn key_delete_nonexistent() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let key_name = "gpg-key-delete-nonexistent".to_string();
    let result = client
        .delete_key("my-admin-password".into(), key_name)
        .await;
    if !matches!(result, Err(ClientError::Sigul(Sigul::KeyNotFound))) {
        panic!("Expected a Sigul error, got {:?}", result);
    }
    Ok(())
}

/// Create an RSA key and then import it to Sigul.
#[tokio::test]
pub async fn key_rsa_import() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let key_name = "rsa-key-import".to_string();
    let cleanup = client
        .delete_key("my-admin-password".into(), key_name.clone())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::KeyNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }

    let key = openssl::rsa::Rsa::generate(2048)?;
    let pem = key.private_key_to_pem_passphrase(
        openssl::symm::Cipher::aes_128_cbc(),
        "my-key-passphrase".as_bytes(),
    )?;

    client
        .import_key(
            "my-admin-password".into(),
            "my-key-passphrase".into(),
            "my-new-key-passphrase".into(),
            key_name.clone(),
            pem.as_slice(),
            siguldry::client::KeyType::Rsa,
            None,
        )
        .await?;
    let keys = client.keys("my-admin-password".into()).await?;
    assert!(keys.iter().any(|k| *k
        == format!(
            "{} ({})",
            &key_name,
            siguldry::client::KeyType::Rsa.to_string()
        )));

    client
        .delete_key("my-admin-password".into(), key_name)
        .await?;

    Ok(())
}
