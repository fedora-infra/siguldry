# Design

This is a high-level description of the design of Siguldry.

Siguldry leans heavily on systemd sandboxing and encryption features. In particular, every service
is expected to use [systemd credentials](https://systemd.io/CREDENTIALS/) for private keys used for
TLS authentication and for key passwords used by clients. It also makes heavy use of systemd
sandboxing features.

## Server

The server component of Siguldry does its best to isolate the keys, whether they are hardware-backed
or stored in the database, and only allow authenticated users to sign content. It does not make
decisions about what should and should not be signed. It is also designed to not allow the keys to
be extracted by users of the service.

It's important to note that while the server fills a similar role to a hardware security module,
there's not necessarily any hardware preventing a malicious administrator from exfiltrating the
database containing signing keys. While the keys are encrypted with per-user credentials, the users
that are administrating the server may also have access to credentials for a key.

Each client unlocks keys separately, and this is enforced using a systemd-managed process for each
client connection.

### Key Storage

Signing keys are stored either in an SQLite database, or are provided by PKCS#11 tokens that have
been registered with the service.

#### Database Keys

Private keys in the database are stored as PEM-encoded PKCS#8 EncryptedPrivateKeyInfo structures
using AES-256-CBC.  The passphrase used to encrypt the key is 128 bytes of cryptographically strong
pseudo-random bytes generated on the server from OpenSSL's RAND_bytes interface. These bytes are
then base64-encoded and the result is used as a passphrase. This passphrase never leaves the server.

The passphrase is encrypted for each user that is granted access to the signing key using their
personal access key. Since the signing service is expected to be used by service accounts, there is
no key derivation function applied to these personal access keys. Fedora uses 64 byte random
strings.

Optionally, the server can be configured with "bindings", which are used to encrypt the key
passphrase. With this scheme, the passphrase is encrypted using a list of X509 certificates provided
in the server configuration. These certificates should correspond to private keys stored in a
hardware token accessible via PKCS#11. For each certificate in the list, the passphrase is encrypted
to a [CMS](https://www.rfc-editor.org/rfc/rfc5652) structure using AES-256-GCM. The list of
encrypted passphrases is then serialized to JSON and the result is encrypted with the user's
personal access key as described above.

#### PKCS#11 Keys

For keys stored in a token accessible via PKCS#11, the administrator provides the user PIN to access
to token. This PIN is then encrypted using the same process used by key passphrases described in the
Database Keys section above.

Tokens may store multiple key pairs, and there's only one PIN protecting them. Siguldry clients
never have access to the PIN itself and need to be granted access so the PIN is encrypted by their
personal access key, but technically if there were a bug in the server, clients _could_ be able to
sign content with other key pairs in the token.

### Client Access

The main server process, run by the siguldry-server.service systemd unit, connects using mutually
TLS to the bridge service. The bridge service is discussed in depth later, but is essentially a
proxy with strong authentication requirements.

Other than this outgoing TCP connection to the bridge, the server expects to be isolated from other
hosts. While allowing other network access to the server should be safe (e.g. the server does not
listen on any network interfaces), care should be taken since that makes it easier for unauthorized
users to access the keys stored in the database.

The server only accepts client connections using its outgoing connection to the bridge. It does this
by treating the bridge connection as an incoming connection after the handshake is complete. This
nested TLS session also uses mutual TLS to authenticate the client. The client is identified by the
Common Name field in its client certificate. The value of that field must match a user in the
database or the connection is dropped.

### Signing

This main service is configured in the systemd unit to have read-only access to the data directory
containing the database as it needs to look up user and key information, but for keys stored in
hardware tokens, the main service should _not_ be granted access to those devices.

There is a second systemd service and an associated systemd socket, `siguldry-signer@.service` and
`siguldry-signer.socket` respectively. systemd starts a new `siguldry-signer@.service` instance for
each connection opened with the Unix socket it is configured to listen on. By default, this socket
is `/run/siguldry-signer/signer.socket`. The main service process opens a connection to this Unix
socket for each client connection.

This helper service is the only place signing keys are accessed. As such, this service may need to
be adjusted by users to grant it access to hardware tokens. However, beyond that, the service is
intended to be as locked down as possible: the entire filesystem is mounted read-only, it has no
network access, and it should opt into as many of the sandboxing capabilities systemd provides as
possible.

## Bridge

The bridge component of Siguldry is designed to allow access to the server, but only if the client
can successfully authenticate using mTLS. Beyond this, the bridge ferries bytes between the client
and server. The client establishes a nested TLS session with the server so the bytes cannot be
inspected or tampered with by the bridge. 

## Client

The client is expected to run in a trusted environment, and the program invoking the client is
expected to be responsible for policy decisions about what will and won't be signed.

The primary interface for signing is provided by the `libsiguldry_pkcs11.so` PKCS#11 module combined
with a systemd service that proxies requests from a Unix socket to the server. This client proxy can
be configured to unlock one or more signing keys, in which case users of the PKCS#11 only need to be
able to access the Unix socket. If the client proxy isn't configured to unlock keys, the user is
responsible for unlocking the key using the personal access key as the user PIN.


## Differences with Sigul

This section is intended for users who are familiar with the Sigul design and want to know what's
different.

The primary reason for these changes are because the way Fedora Infrastructure deploys Sigul is very
different from how Sigul was originally expected to be used. If we assume the client is trusted, as
Sigul could not, a number of complicated aspects of the protocol go away.

### The Client

Originally, Sigul was designed for the client to be used by individual Fedora contributors. Thus,
great care was taken in the Sigul bridge and server to validate client input.

Siguldry, on the other hand, assumes the client is run in a trusted environment. It expects the
users of the client to handle validating the input should be signed. For example, in Fedora it is
expected that signing is triggered via AMQP messages. The consumer of those messages must validate
the content before requesting a signature from the Siguldry client.

### The Bridge

One major difference with Sigul is that all client-server communication happens in the nested TLS
session, and as such, it is no longer possible to mix traffic to the inner and outer TLS sessions:
after the protocol header is sent to the bridge, all traffic must be sent via the inner session.

The primary reason in Sigul to allow the bridge to inspect traffic between the client and server was
to perform validation of that content.  As noted in the client section, the client was not entirely
trusted, so the bridge was responsible for checking if, for example, the RPM built in Koji.

Since Siguldry assumes the client is trusted, there's no reason for the bridge to inspect traffic.
Removing this makes handling the traffic easier for clients and servers, too, since they no longer
need to track inner vs outer TLS session traffic.

### The Server

In Sigul, the server was aware of the type of content it was signing. It ran `rpmsign` to handle
RPMs, for example. This meant that content needed to be sent to the server, and that the tooling
available on the server had a significant impact on what content was supported. Old versions of RPM
on the signing server meant Fedora couldn't take advantage of some new features.

In Siguldry, the server signs digests. It does not need to be made aware of new types of content,
and the versions of the tools available in the operating system the server runs don't impact the
types of content it can sign.

The signatures algorithms it is capable of still depend on what version of OpenSSL the server has.

The database schema is very similar, and it is possible to migrate Sigul data to Siguldry. The key
storage scheme is nearly identical.
