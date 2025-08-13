-- Add migration script here
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS "key_types" (
    "type" TEXT NOT NULL PRIMARY KEY
);
-- 4096 bit RSA keys
INSERT INTO key_types(type) VALUES ("rsa4k");
-- Ed25519 ECC keys
INSERT INTO key_types(type) VALUES ("Ed25519");
-- NIST-P256 ECC keys
INSERT INTO key_types(type) VALUES ("P256");

CREATE TABLE IF NOT EXISTS "key_locations" (
    location TEXT NOT NULL PRIMARY KEY
);
-- GPG keys for use with Sequoia's softkey keystore; these are stored in the "gpg-keys" directory
-- of the Siguldry state directory. They are encrypted by a server-generated password.
INSERT INTO key_locations(location) VALUES ("sequoia-softkey");
-- Keys accessible via PKCS11; it's assumed p11-kit is being used to manage pkcs11 modules.
-- These keys are only for signatures created via OpenSSL
INSERT INTO key_locations(location) VALUES ("pkcs11");
-- Keys stored on the filesystem; these are stored in the "keys" directory of the Siguldry state
-- directory. They are encrypted by a server-generated password.
INSERT INTO key_locations(location) VALUES ("encrypted-file");

CREATE TABLE IF NOT EXISTS "keys" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL UNIQUE,
    "key_type" TEXT NOT NULL,
    "key_location" TEXT NOT NULL,
    -- This uniquely identifies a key and its value is dependant on `key_location`; it may
    -- be a PKCS11 URI or a GPG fingerprint, for example.
    "handle" TEXT NOT NULL UNIQUE,
    FOREIGN KEY(key_type) REFERENCES key_types(type) ON DELETE RESTRICT,
    FOREIGN KEY(key_location) REFERENCES key_locations(location) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS "users" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS "key_accesses" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "key_id" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,
    "encrypted_passphrase" BLOB NOT NULL,
    "key_admin" BOOLEAN NOT NULL,
    -- Foreign key constraints that require all key_accesses referencing a user or key
    -- to be explicitly removed before a key or user can be deleted.
    FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE RESTRICT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT,
    UNIQUE("key_id", "user_id")
);
CREATE INDEX index_key_accesses_user_key ON key_accesses(user_id, key_id);

-- Both these should be pointless as this is the initial migration.
PRAGMA integrity_check;
PRAGMA foreign_key_check;
