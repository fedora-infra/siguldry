# Administrator's Guide

The server side of Siguldry is made up of two components. The server itself, and a proxy called the
bridge. The server communicates with the bridge using mutual TLS (mTLS). The client communicates
with the bridge, also via mTLS, and once both client and server have connected to the bridge, the
client starts a TLS connection to the server using the connection to the bridge.


## Prerequisites

In production, Siguldry should be run on at least three separate hosts.

Ideally, the server should be configured to drop all incoming network traffic (except that related
to its established connections to the bridge) and should be managed out of band (e.g. through a
management console, in person, etc).

The bridge should be configured to accept connections on the two ports it listens on. The server
port should only accept connections from the server, and ideally the client port should also be
restricted to a set of known clients.

Clients have no special requirements, but are expected to be running in a trusted environment.

In a test environment, all three services can run on the same host, or the server and bridge can be
on the same host.

## Logging

All services configure logging via environment variables. The default is to log Siguldry events at
`INFO` level and 3rd party library events at `WARN` level. Logging can be configured using [tracing
directives](https://docs.rs/tracing-subscriber/0.3.23/tracing_subscriber/filter/struct.EnvFilter.html#directives) to enable or disable particular logging statements.

To adjust the log level, use a systemd override file to set the appropriate environment variable for
the service. The systemd unit contains a comment with examples and the expected environment variable.

## Bridge

Assuming you've prepared the configuration and it is located in `/etc/siguldry/bridge.toml`, all you
need to do is start the service:

```bash
systemctl enable --now siguldry-bridge.service
```

The bridge does not store any state.

## Server

The server is composed of several systemd services, a command-line utility called `siguldry-server`,
and some persistent state. The server stores its state, by default, in `/var/lib/siguldry/`. At this
time, it consists of a single SQLite database.

> [!NOTE]
> To back up the server, save the contents of the state directory, and ensure you have backups to any
> PKCS#11 binding keys you may have configured. Backing up PKCS#11 devices is outside the scope of
> this guide.

### Database

The SQLite database stores users, signing keys, OpenPGP and X.509 certificates for those signing
keys, and per-user key access passwords. For signing keys stored in an HSM, it stores a record of
how to access the HSM, rather than the signing keys themselves.

> [!CAUTION]
> Always back up your database before applying a migration.

To create the database, or to apply new database migrations, run:

```bash
systemd-run --pty --wait --collect \
  --working-directory=/var/lib/siguldry \
  --setenv=SIGULDRY_SERVER_CONFIG=/etc/siguldry/server.toml \
  --property=UMask=017 \
  --uid=siguldry \
  --gid=siguldry \
  siguldry-server manage migrate
```

### Importing Sigul Data

If you have an existing Sigul server that you wish to migrate to Siguldry, this
can be done via the `siguldry-server manage import-sigul` command. Before you begin, you
will need:

- The data directory for Sigul; this includes an SQLite database, as well as a number of directories
  for GPG keys, X.509 certificates, and PEM-encoded key pairs.
- The PKCS#11 device used for binding, if bindings were used with the Sigul server
- Some or all of the user passwords for the keys you wish to import.

You will be prompted for each user and key you wish to import.

### Users

Users can be managed with `siguldry-server manage users` subcommands. You will need to
create at least one user before creating any keys. 

For example, to create a user:

```bash
systemd-run --pty --wait --collect \
  --working-directory=/var/lib/siguldry \
  --setenv=SIGULDRY_SERVER_CONFIG=/etc/siguldry/server.toml \
  --uid=siguldry \
  --gid=siguldry \
  siguldry-server manage users create jcline
```

> [!NOTE]
> The username used here must match the Common Name field of the client certificates you
> create to authenticate.

Users can also have their access to signing keys granted or revoked with the `grant-key-access` and
`revoke-key-access` commands respectively.

### Keys

Keys can be managed with `siguldry-server manage key` subcommands.

For example, to create a key:

```bash
systemd-run --pty --wait --collect \
  --working-directory=/var/lib/siguldry \
  --setenv=SIGULDRY_SERVER_CONFIG=/etc/siguldry/server.toml \
  --uid=siguldry \
  --gid=siguldry \
  siguldry-server manage key create jcline test-key
```

You will be prompted to provide the user's access password. This password is used to encrypt the
key, so it should be a long, random value that you store safely in a credential manager.

Review the help text for `key create` as there are a number of optional values to control the key
type.

> [!NOTE]
> Keys are created with both X.509 certificates and OpenPGP certificates

### Services

The server's primary systemd service is `siguldry-server.service`. There are two associated systemd
units to be aware of. `siguldry-signer.socket` is a systemd managed Unix socket configured to start
an instance of `siguldry-signer@.service` for each new connection to the socket. The main
`siguldry-server.service` unit sets `BindsTo=siguldry-signer.socket`, so there is no need to enable
the socket unit. The `siguldry-signer@.service` instance is the unit where signatures are performed.
Logs for a signing operation can be associated across the units via the `session_id` and `request_id`
fields.

To start with, enable the primary service:

```bash
systemctl enable --now siguldry-server.service
```

Next, if using PKCS#11 bindings, enter the PIN to unlock the binding device:

```bash
systemd-run --pty --wait --collect \
  --working-directory=/var/lib/siguldry \
  --setenv=SIGULDRY_SERVER_CONFIG=/etc/siguldry/server.toml \
  --uid=siguldry \
  --gid=siguldry \
  siguldry-server enter-pin
```

The server will now connect to the bridge.

## Client

The client is primarily used via the `libsiguldry_pkcs11.so` PKCS#11 module. In order to isolate the
credentials from the PKCS#11 module, the `siguldry-client-proxy.socket` systemd socket is provided.
This spawns a `siguldry-client-proxy@.service` instance.

### Socket Limits

Systemd enforces limits on the number of concurrent units created by sockets. The [systemd default
is 64](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html#MaxConnections=)
and the default set by the unit shipped by siguldry is `256`. You will want to adjust this limit if
you want more (or fewer) concurrent signing operations.

There are related system limits you must also adjust. The most important one is on the
systemd-provided `systemd-creds.socket`, which provides a varlink interface to decrypt secrets.
Upstream uses the default `MaxConnections=` setting, and sets the related
[MaxConnectionsPerSource=](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html#MaxConnectionsPerSource=)
to 16. Each unit spawned by `siguldry-client-proxy.socket` will, assuming you use systemd-creds, use
a connection to decrypt the client's private key and any key passphrases. Removing the
`MaxConnectionsPerSource=` setting and bumping `MaxConnections=` equal to or slightly more than the
value set by `siguldry-client-proxy.socket` is recommended.


## siguldry-fedora-autopen

Start and enable the `siguldry-fedora-autopen.service` unit. 

> [!NOTE]
> This unit has a dependency on the `siguldry-client-proxy.socket` unit.

The configuration file for this service includes a number of limits and tunables you should consider carefully in combination with the socket limits you'ved configured for `siguldry-client-proxy.socket` and `systemd-creds.socket`. The `siguldry.concurrency` option controls how many connections to `siguldry-client-proxy.socket` the service will make.

### AMQP

In addition to configuring how to connect to the AMQP broker, the `amqp` configuration section includes two tunables: `prefetch_count` and `redelivery_delay`.

#### Prefect Count

The `prefect_count` setting controls [how many unacknowledged messages](https://www.rabbitmq.com/docs/confirms#channel-qos-prefetch) the broker will deliver. Messages are processed concurrently, and each message will result in at least one signing request, but typically will involve multiple requests. For example, a Koji build will contain multiple RPMs which must each be signed. Other, content-specific limits apply, but this is the top-level concurrency tunable.

#### Redelivery Delay

If a message is not processed successfully, it will be requeued and redelivered by the broker. Sometimes this is because there's a client bug, or the message is otherwise referencing "bad" data. At the moment, the AMQP client does not dead-letter messages, so it will spin forever on a bad message until an admin examines it.

The `redelivery_delay` is an artifical delay applied to a message that is flagged as being previously delivered to ensure we don't spin too fast.

### RPM

Each RPM is signed by running an `rpmsign` subprocess. When IMA is enabled, this will start a new `siguldry-client-proxy.socket` connection so `siguldry.concurrency` roughly controls how many RPMs will be signed at the same time.

However, because `rpmsign` requires the entire RPM file, another limit is available. The `rpm.storage_limit_mb` will limit, in Mebibytes, the amount of space used to download RPMs. The appropriate value for this is, unfortunately, somewhat tricky to calculate. RPMs are downloaded to `/tmp`, and `rpmsign` _may_ make a copy of the RPM while signing, so you should ensure that `tmp.mount` is configured such that it's at least twice as large as `storage_limit_mb`, and `storage_limit_mb` must also be larger than the largest RPM you wish to sign.

Storage is granted in the order it is requested, so if your limit is set to `1000`, `500` is currently in use, and an RPM arrives that needs `950`, no additional RPMs will be granted space until sufficient room is available for the RPM that needs `950`.

### Metrics

The service provides optional Prometheus-compatible metrics. Setting the `metrics.http_listener` configuration option will enable these metrics. Be aware that if you use a port other than `9000`, you must adjust the [SocketBindAllow=](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#SocketBindAllow=bind-rule) setting on the `siguldry-fedora-autopen.service`.
