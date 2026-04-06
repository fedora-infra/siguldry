# Configuration

The server, bridge, and client configurations are written in TOML. By default, the configurations
are loaded relative the the `CONFIGURATION_DIRECTORY` environment variable and named `server.toml`,
`bridge.toml`, and `client.toml` respectively. Systemd sets the `CONFIGURATION_DIRECTORY` variable
automatically in the provided systemd unit files, and if run as a system service the default
directory is `/etc/siguldry/`.

> [!NOTE]
> For production deployments, it is expected that the server, bridge, and any clients are
> separate hosts.

## systemd-creds

None of the configuration files contain any secrets directly. All secrets are provided via file
paths and these files should be encrypted with
[systemd-creds](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html).

`systemd-creds` allows you to encrypt secrets using a root-owned host key, a TPM2 device, or both.
It also includes the ability to seal the secret to a set of PCR values in various ways. How you
choose to set it up is left as an exercise to the reader.

Once you've decided on the configuration, you can encrypt any necessary secrets. For example,
here's how to generate a new key pair with OpenSSL, along with a certificate signing request for
an associated X.509 certificate:

```bash
openssl req -new -nodes -sha256 \
    -subj "/CN=siguldry-server.example.com" \
    -keyout - \
    -newkey rsa:4096 \
    -out example.csr | \
    sudo systemd-creds encrypt - \
    /etc/credstore.encrypted/siguldry.server.private_key.pem
```

This generates the private key and pipes it directly to `systemd-creds` to be encrypted. The systemd
units are configured to load and decrypt any credentials that begin with `siguldry.`

Within the configuration files, secret files should be referred to by the path relative to
`/etc/credstore.encrypted/` or `/etc/credstore/`. For the above example, you would set something
like the following when referencing a secret:

```toml
private_key = "siguldry.server.private_key.pem"
```

## X.509 Certificates

The server, bridge, and client all make use of X.509 certificates for mutual authentication when
connecting over TLS.

- Both server and client connect to the bridge. Both server and client check to ensure the
  certificate presented by the bridge includes a `subjectAltName` entry that matches the DNS name.

- Both server and client present client certificates to the bridge for mutual TLS authenticate. These
  certificates *MUST* include the `clientAuth` extended key usage. The bridge only checks that the
  certificate presented is signed by the expected Certificate Authority.

- The client connects to the server through the bridge and checks to ensure the certificate
  presented by the server matches the name in the client configuration file. The client presents its
  client certificate to the server. The server uses the Common Name field of the client's certificate
  as the username. User setup will be covered in the administration section, but be aware that the
  name used when creating the user must match the value of the Common Name.

You will need to generate a set of keys and TLS certificates for the server, bridge, and one or more
clients.

As an example, the following bash script creates a valid set of key pairs and X.509 certificates for
a server, bridge, and single client.

> [!CAUTION]
> This script does _**not**_ encrypt any of the secret keys and
> should not be used for production credentials

```bash
{{#include ../../../devel/siguldry_auth_keys.sh}}
```

Use the above script as an inspiration and encrypt all the private keys with `systemd-creds`. With
your credentials in hand, you can now configure the services.

## Server Configuration

An example [server configuration](https://docs.rs/siguldry/latest/siguldry/server/struct.Config.html#fields):

```toml
{{#include ../../../siguldry/server.toml.example}}
```

By default, this is loaded from `/etc/siguldry/server.toml`.

### Hardware Signing Key

In the event you plan to use signing keys stored in hardware security modules, you need to configure
the `siguldry-signer@.service` unit to have access to it. Add a systemd override file with the
appropriate
[DeviceAllow](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#DeviceAllow=)
directives.


## Bridge Configuration

An example [bridge configuration](https://docs.rs/siguldry/latest/siguldry/bridge/struct.Config.html#fields):

```toml
{{#include ../../../siguldry/bridge.toml.example}}
```

By default, this is loaded from `/etc/siguldry/bridge.toml`.


## Client Configuration

An example [client configuration](https://docs.rs/siguldry/latest/siguldry/client/struct.Config.html#fields):

```toml
{{#include ../../../siguldry/client.toml.example}}
```

By default, this is loaded from `/etc/siguldry/client.toml`.
