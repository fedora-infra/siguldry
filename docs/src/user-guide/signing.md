# Signing

Once the server, bridge, and client(s) are configured, we can now sign things.

Signing should be done with the Siguldry PKCS #11 module. While it can be used manually, Fedora
automates signing content using its AMQP message broker that its build services connect to.

## siguldry-pkcs11

First, here's some examples of how various content can be signed using the
[siguldry-pkcs11](https://crates.io/crates/siguldry-pkcs11) library. This is a [PKCS
#11](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html) module, which is an API many popular libraries and tools understand.


### Configuration

As a PKCS #11 module is a dynamic library loaded by other programs, the primary way to provide configuration is by environment variable.

{{#include ../../../siguldry-pkcs11/README.md:22:31}}

{{#include ../../../siguldry-pkcs11/README.md:41:}}


## siguldry-fedora-autopen

Rather than manually signing every piece of content, you can automate the process.

{{#include ../../../siguldry-fedora-autopen/README.md:5}}
