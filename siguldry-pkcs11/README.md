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

## Example Uses

The module, being a rather incomplete implementation of the specification, may not work with all
applications that use PKCS#11. However, it does aim to support common tools that only use the
signing interfaces. The examples below all assume there's an instance of `siguldry-client proxy`
listening at the default location used by the systemd unit
(`/run/siguldry-client-proxy/siguldry-client-proxy.socket`). If this is not the case for you, ensure
the `LIBSIGULDRY_PKCS11_PROXY_PATH` environment variable points to the correct location.

### OpenSSL CLI

You can use the module with the OpenSSL CLI. For example:

```bash
$ PKCS11_PROVIDER_MODULE=path/to/libsiguldry_pkcs11.so openssl \
    pkeyutl -sign -rawin \
    -provider pkcs11 -inkey 'pkcs11:token=siguldry-key-name' \
    -in a_file -out a_file.sig
    -digest sha256
```

### GPG

It's possible to use gpg2 with the module via
[gnupg-pkcs11-scd](https://github.com/alonbl/gnupg-pkcs11-scd).

After installing `gnupg-pkcs11-scd`, add some configuration:
```bash
# Configure gpg-agent to use gnupg-pkcs11-scd
$ cat <<EOF >> "$GNUPGHOME/gpg-agent.conf"
scdaemon-program /usr/bin/gnupg-pkcs11-scd
EOF

# Configure gnupg-pkcs11-scd to use the Siguldry PKCS#11 module
$ cat <<EOF >> "$GNUPGHOME/gnupg-pkcs11-scd.conf"
providers siguldry 
provider-siguldry-library /path/to/libsiguldry_pkcs11.so
EOF
```

Once the agent is configured, fetch the OpenPGP certificate from the Siguldry key using
`siguldry-client key` (todo implement this command) and import the public key:

```bash
$ gpg --batch --import cert.asc
$ gpg --card-status
```

Finally, sign something:

```bash
$ gpg --batch --detach-sign --output a_file.sig a_file
$ gpg --verify a_file.sig a_file
```

### Sequoia

Siguldry exposes its keys in the format used by Sequoia's cryptoki backend. If using the default
values for `sq`, Sequoia expects the configuration in
`$HOME/.config/sequoia/keystore/cryptoki/config.toml`, but if you specified a custom `SEQUOIA_HOME` the
file should be placed at `$SEQUOIA_HOME/config/keystore/cryptoki/config.toml`:

```bash
$ cat <<EOF >> "$HOME/.config/sequoia/keystore/cryptoki/config.toml"
[[modules]]
path = "/path/to/libsiguldry_pkcs11.so"
EOF
```

Once the agent is configured, fetch the OpenPGP certificate from the Siguldry key using
`siguldry-client key` (todo implement this command) and import the public key and mark it trusted:

```bash
$ sq cert import cert.asc
$ sq pki link add --cert=<fingerprint> --all
```

Finally, sign something:

```bash
$ sq sign --signer=<fingerprint> --signature-file=a_file.sig a_file
$ sq verify --signature-file=a_file.sig a_file
```

### rpmsign

You can sign RPMs using `rpmsign` via either Sequoia or GPG as described above. It can be used for
both the OpenPGP signature and IMA file signatures. Assuming you have configured Sequoia as
described above:

```bash
# The SubjectKeyID is from the X509 certificate associated with the signing key; you can provide
# any positive integer to test this out.
$ rpmsign --addsign --rpmv6 --signfiles \
    --define='_openpgp_sign sq' \
    --define='_openpgp_sign_id 44431F5254FE5E31ADCC6EEE2F9ED88F2EEDB782' \
    --define='_file_signing_key_id <SubjectKeyId>' \
    --fskpath "pkcs11:token=ima-signing-key" \
    cloud-init-25.2-10.fc43.noarch.rpm
```

If you only want an OpenPGP signature, omit the `--signfiles`, `--fskpath`, and
`_file_signing_key_id` definition.

### systemd-measure

You can sign the current set of PCR values with:

```bash
$ /usr/lib/systemd/systemd-measure --private-key="pkcs11:token=pcr-signing-key" \
    --private-key-source="provider:pkcs11" \
    --certificate=./pcr-signing-cert.pem \
    sign --current --bank=sha256 
```
