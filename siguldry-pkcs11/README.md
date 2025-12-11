# siguldry-pkcs11

A [PKCS #11](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html) module that
supports signing operations using a Siguldry server.

This PKCS #11 module does _not_ implement the complete specification. Instead, it only support
signing, and only using mechanisms supported by the Siguldry server. It is possible to use any key
pair in Siguldry for signing, included OpenPGP keys. This module also supports using Sequoia's
cryptoki backend to produce OpenPGP signatures with any OpenPGP keys in the Siguldry server.

The module was written using version 3.2 of the specification, but provides interfaces for 3.0 and
2.40 for older tooling. It does not explicitly test those older interfaces, however.

## Configuration

The module communicates with the Siguldry server using a Unix socket provided by `siguldry-client
proxy`.  This socket needs to be configured before using this module.

To do so, start the systemd socket `siguldry-client-proxy.socket`. Refer to the documentation for
`siguldry-client proxy` for more details.

The module reads two environment variables:

- `LIBSIGULDRY_PKCS11_PROXY_PATH` - if set, it should contain the absolute path to the Unix socket
  provided by `siguldry-client proxy`. The default is `/run/siguldry-client-proxy/siguldry-client-proxy.socket`, which matches the systemd unit.
- `LIBSIGULDRY_PKCS11_LOG` - if set, it is used to configure the logging filter via [envfilter
  directives](https://docs.rs/tracing-subscriber/0.3.22/tracing_subscriber/filter/struct.EnvFilter.html#directives)
