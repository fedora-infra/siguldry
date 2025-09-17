-- Add migration script here
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS "key_algorithms" (
    "type" TEXT NOT NULL PRIMARY KEY
);
-- 4096 bit RSA keys
INSERT INTO key_algorithms(type) VALUES ("rsa4k");
-- NIST-P256 ECC keys
INSERT INTO key_algorithms(type) VALUES ("P256");

CREATE TABLE IF NOT EXISTS "key_locations" (
    location TEXT NOT NULL PRIMARY KEY
);
-- GPG keys for use with Sequoia's softkey keystore; they are encrypted by a server-generated password.
INSERT INTO key_locations(location) VALUES ("sequoia-softkey");
-- Keys accessible via PKCS11; it's assumed p11-kit is being used to manage pkcs11 modules.
-- These keys are only for signatures created via OpenSSL
INSERT INTO key_locations(location) VALUES ("pkcs11");
-- Keys for use with OpenSSL; they are encrypted by a server-generated password.
INSERT INTO key_locations(location) VALUES ("encrypted");

CREATE TABLE IF NOT EXISTS "keys" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL UNIQUE,
    "key_algorithm" TEXT NOT NULL,
    "key_location" TEXT NOT NULL,
    -- This uniquely identifies a key. For example, the GPG key fingerprint, or the SHA256 sum of
    -- the public key.
    "handle" TEXT NOT NULL UNIQUE,
    -- The encrypted key material, or in the case of keys stored in hardware, information on how
    -- to access the key (e.g. a PKCS11 URI).
    --
    -- The scheme is dependent on the type of key, but it will be a text representation (ASCII-armored, PEM-encoded, etc)
    "key_material" TEXT NOT NULL,
    -- The public key in a text-friendly encoding (ASCII-armored, PEM-encoded, etc)
    "public_key" TEXT NOT NULL,
    FOREIGN KEY(key_algorithm) REFERENCES key_algorithms(type) ON DELETE RESTRICT,
    FOREIGN KEY(key_location) REFERENCES key_locations(location) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS "public_key_material_types" (
    "type" TEXT NOT NULL PRIMARY KEY
);
INSERT INTO public_key_material_types(type) VALUES ("x509");
INSERT INTO public_key_material_types(type) VALUES ("revocation");

-- This table contains data associated with a key pair that is meant to be distributed.
-- This includes the public key itself, X509 certificates for the key, and key revocations.
CREATE TABLE IF NOT EXISTS "public_key_material" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "key_id" INTEGER NOT NULL,
    "data_type" TEXT NOT NULL,
    "data" TEXT NOT NULL,
    FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE RESTRICT,
    FOREIGN KEY(data_type) REFERENCES public_key_material_types(type) ON DELETE RESTRICT
);
CREATE INDEX index_public_key_material_key_id_type on public_key_material(key_id, data_type);

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
