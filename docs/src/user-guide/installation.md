# Installation

## Distribution repositories

Siguldry is packaged for Fedora and EPEL 10 as `siguldry`:

```bash
$ sudo dnf install siguldry
```

This package includes the server, bridge, and client.

The PKCS #11 module is also available in Fedora and EPEL 10 as `siguldry-pkcs11` and should be installed
on clients that plan to perform signing:

```bash
$ sudo dnf install siguldry-pkcs11
```


## Crates.io

Siguldry is also available on crate.io. The Minimum Supported Rust Version (MSRV) will always be
less than or equal to the version available in the latest point release of Red Hat Enterprise Linux.
For example, with RHEL 10.1 being available, the MSRV is 1.88. It can be installed with cargo:

```bash
cargo install siguldry
```

You will need several header packages installed when using this method:

- `cargo`
- `clang` for libsqlite3-sys
- `openssl` headers (provided by `openssl-devel` in Fedora and `libssl-dev` in Debian)
- `sqlite` headers (provided by `sqlite-devel` in Fedora and `libsqlite3-dev` in Debian)

Be aware, however, that the provided systemd units expect some binaries to be installed into
`/usr/libexec/`.

The PKCS #11 module is not available to install from crates.io since it only provides a dynamic
library and cargo  will not install crates without a binary.
