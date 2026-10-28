# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [4.0.0] - 2026-10-29

### Changed


### Fixed

- According to Section 4.6.3 of PKCS#11 3.2, certificate serial numbers in the CKA_SERIAL_NUMBER
  attribute must be DER-encoded. Prior to this release, that attribute held the raw serial number
  bytes.


## [3.0.0] - 2026-10-20

### Changed

- Tokens now have a non-zero serial number assigned to them. The serial number
  derived from the public key of the key pair being exposed. This is a breaking
  change only if the PKCS11 URI you use included the serial number (#277)


## [2.2.0] - 2026-09-23

### Added

- The module now supports the CKM_ML_DSA mechanism and exposes ML-DSA-65 and ML-DSA-87 keys for
  signing. The only supported mechanism is the pure ML-DSA signature; none of the pre-hash
  mechanisms are supported at this time (#269)

- The module now supports the CKM_EDDSA mechanism and exposes Ed25519 and Ed448 keys for signing.
  At this time, the module only accepts inputs that are 32 or 64 bytes in length, which is not
  compliant with the specification but does support signing with OpenPGP or anything else that
  computes the signature on a raw digest (#269)


## [2.1.0] - 2026-05-15

### Added

- The module now accepts an environment variable, LIBSIGULDRY_PKCS11_KEYS, to control what
  keys are exposed as tokens (#201)

### Changed

- The default log level for the module is now WARN, rather than INFO (#201)

- The log level for function instrumentation on most PKCS11 functions has been dropped to
  DEBUG as it was overly verbose for info-level logs (#201)

## [2.0.0] - 2026-03-27

### Changed

- The module requires version 0.6 or greater of the siguldry client proxy as
  the IPC format has changed (#166)

### Fixed

- Fix an assumption that C's char type is signed (#161)


## [1.0.0] - 2026-03-12

### Added

- Everything (initial release).
