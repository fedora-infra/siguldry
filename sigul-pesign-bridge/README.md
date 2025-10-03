[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/sigul-pesign-bridge.svg
[crates-url]: https://crates.io/crates/sigul-pesign-bridge
[docs-badge]: https://docs.rs/sigul-pesign-bridge/badge.svg
[docs-url]: https://docs.rs/sigul-pesign-bridge
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: LICENSE
[actions-badge]: https://github.com/fedora-infra/siguldry/workflows/CI/badge.svg
[actions-url]:https://github.com/fedora-infra/siguldry/actions?query=workflow%3ACI

# sigul-pesign-bridge

Drop-in replacement for pesign's daemon that bridges pesign-client requests to a Sigul server.

The service provides a Unix socket at, by default, `/run/pesign/socket`. `pesign-client` can be used to connect to this socket and request signatures for PE applications. Unlike `pesign`, this implementation forwards the request to a [sigul](https://pagure.io/sigul) signing server.

## Configuration

`sigul-pesign-bridge` configuration is provided via a TOML file. The current configuration (or the default, if none is provided) can be seen with:
```bash
sigul-pesign-bridge config
```

The configuration format with in-line documentation:

```toml
# An example configuration file for sigul-pesign-bridge.
#
# In order to use the service you will need to alter this as it requires
# the signing key names you're using, at a minimum. The service does not
# support configuration overrides so you must have a valid value for all
# non-optional configuration keys. All keys are required unless explicitly
# noted as optional.

# The total length of time (in seconds) to wait for a signing request to complete.
#
# The service will retry requests to the Sigul server until it succeeds or
# this timeout is reached, at which point it will signal to the pesign-client
# that the request failed. This must be a non-zero value.
total_request_timeout_secs = 600

# The timeout (in seconds) to wait for a response from the Sigul server.
#
# Requests that time out are retried until `total_request_timeout_secs` is reached.
# As such, this value should be several times smaller than `total_request_timeout_secs`.
sigul_request_timeout_secs = 60

# Configuration to connect to the Sigul server.
[sigul]
# The hostname of the Sigul bridge; this is used to verify the bridge's
# TLS certificate.
bridge_hostname = "sigul-bridge.example.com"

# The port to connect to the Sigul bridge; the typical port is 44334.
bridge_port = 44334

# The hostname of the Sigul server; this is used to verify the server's
# TLS certificate.
server_hostname = "sigul-server.example.com"

# The username to use when authenticating with the Sigul bridge.
sigul_user_name = "sigul-client"

# The systemd credentials ID of the PEM-encoded private key file.
#
# This private key is the key that matches the `client_certificate` and is used to authenticate
# with the Sigul bridge. It is expected to be provided by systemd's "ImportCredential" or
# "LoadCredentialEncrypted" option.
#
# # Example
#
# To prepare the encrypted configuration:
#
# ```bash
# systemd-creds encrypt /secure/ramfs/private-key.pem /etc/credstore.encrypted/sigul.client.private_key
# ```
#
# This will produce an encrypted blob which will be decrypted by systemd at runtime.
private_key = "sigul.client.private_key.pem"

# The path to client certificate that matches the `private_key`.
client_certificate = "sigul.client.certificate.pem"

# The path to the certificate authority to use when verifying the Sigul bridge and Sigul
# server certificates.
ca_certificate = "sigul.ca_certificate.pem"


# A list of signing keys available for use.
#
# The pesign-client requests a signing key and certificate using the `--token`
# and `--certificate` arguments respectively. If the pesign-client specifies
# a pair that isn't present in this configuration file, the request is rejected.
[[keys]]
# The name of the key in Sigul.
key_name = "signing-key"

# The name of the certificate in Sigul.
certificate_name = "codesigning"

# The path to a file containing the Sigul passphrase to access the key.
#
# It is expected to be the ID used in the systemd encrypted credential.
passphrase_path = "sigul.signing-key.passphrase"

# The certificate to validate the PE signature with; this field is optional.
#
# If set, the service will validate the PE has been signed with the given certificate
# before returning the signed file to the client. This validation is done with the
# "sbverify" application, which must be installed to use this option.
certificate_file = "/path/to/signing/certificate.pem"


# Additional signing keys can be specified.
[[keys]]
key_name = "other-signing-key"
certificate_name = "other-codesigning"
passphrase_path = "sigul.other-signing-key.passphrase"
```

## Running

This document assumes the service is running under systemd using a unit file based off the one provided
at `sigul-pesign-bridge/sigul-pesign-bridge.service`. Some set up is required as the expectation is all
secrets are handled by systemd.

### Secrets

To start with, a few secrets need to be prepared. Refer to [systemd's
credentials documentation](https://systemd.io/CREDENTIALS/) for details.

For each signing key in Sigul, we should configure the passphrase needed to unlock it (the key access
password for the user):

```bash
# This will prompt you for both passwords.
systemd-ask-password | systemd-creds encrypt - /etc/credstore.encrypted/sigul.signing-key.passphrase
systemd-ask-password | systemd-creds encrypt - /etc/credstore.encrypted/sigul.other-signing-key.passphrase
```

The service expects passwords to be on a single line, terminated by a newline.
Anything after the newline is ignored.

In addition to the key access password, you should encrypt the private key used for client
authentication:

```bash
systemd-creds encrypt /secure/ramfs/private-key.pem /etc/credstore.encrypted/sigul.client.private_key
```

While not technically secrets, you can also store the client certificate and CA certificate as systemd
credentials, either encrypted in `/etc/credstore.encrypted/` or in `/etc/credstore/` as plaintext. They
should have names that start with `sigul.` as the systemd unit will automatically load any credential
starting with that prefix.

Now that the secrets are prepared, place your TOML configuration at
`/etc/sigul-pesign-bridge/config.toml`, which is the default set in the systemd
unit file.

Finally, start the service:

```bash
sudo systemctl enable --now sigul-pesign-bridge.service
```

## Signing

With the service running, you can now use it to sign PE files:

```bash
pesign-client --sign \
    --token="signing-key" \
    --certificate="codesigning" \
    --infile=unsigned-application.efi \
    --outfile=signed-application.efi
```

The default setup requires that the user executing pesign-client be in the
`pesign` group.
