-- This migration adds entries to the key_algorithms table for the PQC module lattice key types
-- as well as the EdDSA keys used in composite key schemes for OpenPGP in RFC 9980.
PRAGMA foreign_keys = ON;

INSERT INTO key_algorithms(type) VALUES ('ed25519');
INSERT INTO key_algorithms(type) VALUES ('ed448');
INSERT INTO key_algorithms(type) VALUES ('mldsa65');
INSERT INTO key_algorithms(type) VALUES ('mldsa87');

PRAGMA integrity_check;
PRAGMA foreign_key_check;
