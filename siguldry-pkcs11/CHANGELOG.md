# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
