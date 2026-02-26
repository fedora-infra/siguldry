# Siguldry

Services to manage signing keys and tools to use them.

Heavily inspired by [Sigul](https://pagure.io/sigul), Siguldry provides a service to help isolate
signing keys. The server connects to an authenticated proxy, the bridge, and communicates with
clients through that bridge. Keys are generated on the server, are encrypted, and there is no
interface to extract the keys by the clients. Keys can also be provided by hardware security modules
that provide a PKCS#11 interface.

The primary interface for clients is offered by the `libsiguldry_pkcs11.so` PKCS #11 module.
With this, any tool that can use PKCS #11 can use keys stored in the Siguldry server. This includes,
but is not limited to, `openssl` via [pkcs11-provider](github.com/latchset/pkcs11-provider/),
[Sequoia PGP](https://sequoia-pgp.org/) via its cryptoki keystore backend, `sbsign`, `pesign`,
`systemd-measure`, etc. The module is designed so that it's usable from network-isolated build
environments if you can expose a Unix socket in the build environment.

Although this is primarily developed with Fedora in mind, there is nothing Fedora-specific in the
server, bridge, or client. Some tools included in this repository are RPM-specific, but it is not a
requirement.


## Getting Started

Siguldry should be available in Fedora and EPEL repositories. There are three major components and,
in a production scenario, these components run on dedicated hosts.

Refer to the `ADMIN.md` document for detailed instructions on installation, configuration, and
management of the server, bridge, and client.

## Building

To build all the components, you need the following system dependencies:

- `cargo`
- `capnproto` for sequoia-keystore
- `clang` for libsqlite3-sys
- `openssl` headers (provided by `openssl-devel` in Fedora and `libssl-dev` in Debian)
- `sqlite` headers (provided by `sqlite-devel` in Fedora and `libsqlite3-dev` in Debian)

Note that the system-provided version of Cargo on Debian may be too old; in that case you will need
to use rustup. Refer to `CONTRIBUTING.md` for more details and test dependencies.
