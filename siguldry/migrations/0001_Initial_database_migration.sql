-- Add migration script here
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS "key_algorithms" (
    "type" TEXT NOT NULL PRIMARY KEY
);
-- 2048 bit RSA keys
INSERT INTO key_algorithms(type) VALUES ("rsa2k");
-- 4096 bit RSA keys
INSERT INTO key_algorithms(type) VALUES ("rsa4k");
-- NIST-P256 ECC keys
INSERT INTO key_algorithms(type) VALUES ("P256");

CREATE TABLE IF NOT EXISTS "keys" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    -- If set, this references the id of another key which is the second part of a hybrid key pair.
    "hybrid_pair_id" INTEGER UNIQUE REFERENCES keys(id) ON DELETE SET NULL,
    "name" TEXT NOT NULL UNIQUE,
    "key_algorithm" TEXT NOT NULL,
    -- This uniquely identifies a key. For example, the GPG key fingerprint, or the SHA256 sum of
    -- the public key.
    "handle" TEXT NOT NULL UNIQUE,
    -- The encrypted key material if this is not a PKCS#11-backed key. For PKCS#11-backed keys, this
    -- is the hex-encoded ID attribute of the key within the associated token. That is, it is a human-
    -- readable version of the blob stored in the `pkcs11_key_id` field.
    --
    -- The format used is PEM-encoded PKCS#8 EncryptedPrivateKeyInfo structures. The key is encrypted
    -- with AES-256-CBC using a 128 byte server-generated secret. This secret is then encrypted per-user
    -- in the key_accesses table.
    "key_material" TEXT NOT NULL,
    -- The PEM-encoded public key.
    "public_key" TEXT NOT NULL,
    "pkcs11_token_id" INTEGER,
    -- The Id attribute of the key within the token
    "pkcs11_key_id" BLOB,
    CHECK ( (pkcs11_token_id IS NULL) = (pkcs11_key_id IS NULL) ),
    CHECK (hybrid_pair_id != id),
    FOREIGN KEY(key_algorithm) REFERENCES key_algorithms(type) ON DELETE RESTRICT,
    -- If a token is removed, delete all associated keys.
    FOREIGN KEY(pkcs11_token_id) REFERENCES pkcs11_tokens(id) ON DELETE CASCADE
);

-- Setting the hybrid_pair_id on either key updates the target; keys that are already in a pair cause
-- an error.
CREATE TRIGGER IF NOT EXISTS keys_hybrid_pair_id_set
AFTER UPDATE OF hybrid_pair_id ON keys
WHEN NEW.hybrid_pair_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'Target key already has a hybrid pair id set')
    WHERE EXISTS (
        SELECT 1 FROM keys
        WHERE id = NEW.hybrid_pair_id
          AND hybrid_pair_id IS NOT NULL
          AND hybrid_pair_id != NEW.id
    );
    UPDATE keys SET hybrid_pair_id = NEW.id
    WHERE id = NEW.hybrid_pair_id AND (hybrid_pair_id IS NULL OR hybrid_pair_id = NEW.id);
END;

-- Unset the hybrid_pair_id if either key unsets it
CREATE TRIGGER IF NOT EXISTS keys_hybrid_pair_id_unset
AFTER UPDATE OF hybrid_pair_id ON keys
WHEN NEW.hybrid_pair_id IS NULL AND OLD.hybrid_pair_id IS NOT NULL
BEGIN
    UPDATE keys SET hybrid_pair_id = NULL
    WHERE id = OLD.hybrid_pair_id AND hybrid_pair_id = OLD.id;
END;

-- Tokens registered with Siguldry will have their keys imported.
--
-- The token's user PIN is used in place of a server-generated encryption secret; tokens can have
-- multiple keys, but only a single user PIN, so technically any user with access to the PIN can
-- get to any key. It's up to Siguldry to enforce users only access the keys they've been allowed
-- to use, since the Siguldry client never gets the actual user PIN.
CREATE TABLE IF NOT EXISTS "pkcs11_tokens" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "module_path" TEXT NOT NULL,
    -- The PKCS#11 label; while not required by the spec, we'll expect the token to have it.
    "label" TEXT NOT NULL UNIQUE,
    "manufacturer_id" TEXT,
    "model" TEXT,
    "serial_number" TEXT NOT NULL UNIQUE,
    -- The number of concurrent signing requests; this translates to the number of open
    -- sessions and signing operations. Some tokens have limits. The default, 0, means no
    -- limit.
    "concurrent_requests" INTEGER DEFAULT 0 NOT NULL
);

CREATE TABLE IF NOT EXISTS "public_key_material_types" (
    "type" TEXT NOT NULL PRIMARY KEY
);
INSERT INTO public_key_material_types(type) VALUES ("x509");
INSERT INTO public_key_material_types(type) VALUES ("openpgp");

-- This table contains data associated with a key pair that is meant to be distributed.
-- This includes the public key itself, X509 certificates for the key, and key revocations.
CREATE TABLE IF NOT EXISTS "public_key_material" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "key_id" INTEGER NOT NULL,
    -- A friendly identifier for the material; must be unique to the associated key.
    "name" TEXT NOT NULL,
    "data_type" TEXT NOT NULL,
    "data" TEXT NOT NULL,
    UNIQUE("key_id", "name"),
    -- If the parent key is deleted, remove all the associated public key material
    FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE CASCADE,
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
