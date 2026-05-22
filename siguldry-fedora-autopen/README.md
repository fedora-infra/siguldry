# siguldry-fedora-autopen

Automatically sign content based on AMQP messages published in Fedora's infrastructure.

`siguldry-fedora-autopen` is a service that connects to an AMQP broker and consumes messages as published by [fedora-messaging](https://fedora-messaging.readthedocs.io/en/stable/index.html). It supports automatically signing RPMs built in Koji when tagging events occur, OSTree repositories, and CoreOS artifacts. It uses the `siguldry-pkcs11` module to perform signing.

## Configuration

The `siguldry-fedora-autopen.service` requires that the `siguldry-client-proxy.socket` systemd socket is active and accessible to the service. Its default configuration file location when running as a system service is `/etc/siguldry/fedora-autopen.toml`. Its configuration is similar, but not identical, to the [robosignatory](https://pagure.io/robosignatory/) service it replaces.

Refer to the included `config.toml.example` file for a detailed explanation of configuration options.
