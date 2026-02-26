# Administrator's Guide

The server side of Siguldry is made up of two components. The server itself, and a proxy called the
bridge. The server communicates with the bridge using mutual TLS (mTLS). The client communicates
with the bridge, also via mTLS, and once both client and server have connected to the bridge, the
client starts a TLS connection to the server using the connection to the bridge.

Siguldry is expected to be run under systemd and relies heavily on its security features. The
systemd units provided expect at least systemd 258 and will need adjustment on older systems when
used with TPM-bound credentials.


## Prereqs

In production, Siguldry should be run on three separate hosts.

Ideally, the server should be configured to drop all incoming traffic (except that related to its
established connections to the bridge) and should be managed out of band (e.g. through a management
console, in person, etc).

The bridge should be configured to accept connections on the two ports it listens on. The server
port should only accept connections from the server, and ideally the client port should also be
restricted to a set of known clients.

Clients have no special requirements, but are expected to be running in a trusted environment.

In a test environment, all three services can run on the same host, or the server and bridge can be
on the same host.


## Certificates

If you already have a way to issue TLS certificates, it is recommended that you use that flow.

For reference, the following is how to generate a complete set of certificates.  Note that for
production environments, care should be taken to encrypt and protect the private keys generated.
Later, when setting up the service, we will make use of [systemd
credentials](https://systemd.io/CREDENTIALS/) so one approach is generate the key on the host and
pipe it directly to `systemd-creds`.

In all examples, adjust the common name to match your environment.

### Certificate Authority

First, create a certificate authority which is used to sign all our certificates:
```bash
openssl req -x509 -new -nodes -sha256 \
    -days 3650 \
    -extensions v3_ca \
    -subj "/CN=Siguldry CA" \
    -newkey rsa:4096 \
    -keyout siguldry.ca.private_key.pem \
    -out siguldry.ca_certificate.pem
```

Once you've finished signing everything you should store the private key in a safe
place or just delete it.


### Server

The server uses its certificate both as a client connecting to the bridge, and
as a server the client connects to via the bridge. The certificate for the
server must have the `clientAuth` _and_ `serverAuth` extended key usage
extensions.

Since the client only communicates through the bridge, and because the server
initiates the connection to the bridge, the server's name does not need to
resolve, but it does need to match what the client has been configured to
accept.

```bash
SERVER_CN="server.example.com"

openssl req -new -nodes -sha256 \
    -addext "subjectAltName = DNS:$SERVER_CN" \
    -addext "extendedKeyUsage = clientAuth,serverAuth" \
    -subj "/CN=$SERVER_CN" \
    -newkey rsa:2048 \
    -keyout siguldry.server.private_key.pem \
    -out server-cert.csr
openssl x509 -req -in server-cert.csr \
    -CAkey siguldry.ca.private_key.pem \
    -CA siguldry.ca_certificate.pem \
    -copy_extensions copyall \
    -days 3650 \
    -sha256 \
    -out siguldry.server.certificate.pem
```

### Bridge

The bridge accepts connections from the server and the client. It needs the
`serverAuth` extended key usage extension, and its name must resolve for both
the client and server.

```bash
BRIDGE_CN="bridge.example.com"

openssl req -new -nodes -sha256 \
    -addext "subjectAltName = DNS:$BRIDGE_CN" \
    -addext "extendedKeyUsage = serverAuth" \
    -subj "/CN=$BRIDGE_CN" \
    -newkey rsa:2048 \
    -keyout siguldry.bridge.private_key.pem \
    -out bridge-cert.csr
openssl x509 -req -in bridge-cert.csr \
    -CAkey siguldry.ca.private_key.pem \
    -CA siguldry.ca_certificate.pem \
    -copy_extensions copyall \
    -days 3650 \
    -sha256 \
    -out siguldry.bridge.certificate.pem
```

### Clients

Each client needs a certificate to authenticate with. The common name of the certificate must match
the username that we create on the Siguldry server later.

```bash
CLIENT_CN = "demo-client"

# Create and sign a client certificate
openssl req -new -nodes -sha256 \
    -addext "extendedKeyUsage = clientAuth" \
    -subj "/CN=$CLIENT_CN" \
    -newkey rsa:2048 \
    -keyout siguldry.client.private_key.pem \
    -out client-cert.csr
openssl x509 -req -in client-cert.csr \
    -CAkey siguldry.ca.private_key.pem \
    -CA siguldry.ca_certificate.pem \
    -copy_extensions copyall \
    -days 3650 \
    -sha256 \
    -out siguldry.client.certificate.pem
```

Finally, you can clean up the certificate signing requests and check that things are signed properly:

```bash
rm {client,bridge,server}-cert.csr

openssl verify -CAfile ./siguldry.ca_certificate.pem siguldry.server.certificate.pem
openssl verify -CAfile ./siguldry.ca_certificate.pem siguldry.bridge.certificate.pem
openssl verify -CAfile ./siguldry.ca_certificate.pem siguldry.client.certificate.pem

```

## Server Configuration

With the certificates in hand, we can configure the server. First, encrypt the server's
private key using systemd-creds and add the certificate to the credential store:

```bash
systemd-creds encrypt siguldry.server.private_key.pem /etc/credstore.encrypted/siguldry.server.private_key.pem
cp siguldry.server.certificate.pem /etc/credstore/
cp siguldry.ca_certificate.pem /etc/credstore/
```

The systemd unit will load any credentials prefixed with `siguldry.`.

Next, write a [server configuration](https://docs.rs/siguldry/latest/siguldry/server/struct.Config.html#fields) to `/etc/siguldry/server.toml`:

```toml
state_directory = "/var/lib/siguldry/"
signer_socket_path = "/run/siguldry-signer/signer.socket"
bridge_hostname = "bridge.example.com"
bridge_port = 44333
connection_pool_size = 32
user_password_length = 32

# These should match the filenames in /etc/credstore.encrypted/ and /etc/credstore/
[credentials]
private_key = "siguldry.server.private_key.pem"
certificate = "siguldry.server.certificate.pem"
ca_certificate = "siguldry.ca_certificate.pem"

[certificate_subject]
country = "US"
state_or_province = "Massachusetts"
locality = "Cambridge"
organization = "Your Organization"
organizational_unit = "Department within your Organization"

# If you'd like keys to be bound to hardware tokens, provide one or more certificates.
# At least one entry should have a private_key entry with a pkcs11 URI. If not, provide
# no [[pkcs11_bindings]] entries.
[[pkcs11_bindings]]
certificate = "/etc/siguldry/binding_cert1.pem"
private_key = "pkcs11:serial=abc123;id=%01;type=private"

[[pkcs11_bindings]]
certificate = "/etc/siguldry/binding_cert2.pem"

# This concludes the configuration.
```

Start the service:

```bash
systemctl enable --now siguldry-server.service
```


## Bridge Configuration

Similar to the server, we will encrypt its private key and place its certificate and the CA in the
credential store:

```bash
systemd-creds encrypt siguldry.bridge.private_key.pem /etc/credstore.encrypted/siguldry.bridge.private_key.pem
cp siguldry.bridge.certificate.pem /etc/credstore/
cp siguldry.ca_certificate.pem /etc/credstore/
```

Next, write a [bridge configuration](https://docs.rs/siguldry/latest/siguldry/bridge/struct.Config.html#fields) to `/etc/siguldry/bridge.toml`:

```toml
server_listening_address = "[::]:44333"
client_listening_address = "[::]:44334"

[credentials]
private_key = "sigul.bridge.private_key.pem"
certificate = "sigul.bridge.certificate.pem"
ca_certificate = "sigul.ca_certificate.pem"
```

And start the service:

```bash
systemctl enable --now siguldry-bridge.service
```


## Client Configuration

A client command-line interface is available to query available keys, test out authentication, and to run
a service that offers a Unix socket with the PKCS #11 module uses to communicate with the service through.

Encrypt the client's private key and add its certificate to the credential store:

```bash
systemd-creds encrypt siguldry.client.private_key.pem /etc/credstore.encrypted/siguldry.client.private_key.pem
cp siguldry.client.certificate.pem /etc/credstore/
cp siguldry.ca_certificate.pem /etc/credstore/
```

Add a client configuration:

```toml
server_hostname = "server.example.com"
bridge_hostname = "bridge.example.com"
bridge_port = 44334

# Keys can be automatically unlocked by configuring them here.
# This is really only recommended when using the PKCS #11 module with
# the protected authentication path feature (e.g. clients don't need a PIN).
keys = []

[request_timeout]
secs = 30
nanos = 0

[credentials]
private_key = "siguldry.client.private_key.pem"
certificate = "siguldry.client.certificate.pem"
ca_certificate = "siguldry.ca_certificate.pem"
```
