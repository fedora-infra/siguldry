# Introduction

Siguldry is a set of services to isolate and manage signing keys.

It consists of a server, which generates and protects the signing keys, a
client, and a "bridge" which both the server and client connect to in order to
communicate. A [PKCS #11](https://en.wikipedia.org/wiki/PKCS_11)module ,which
is the primary way signing is performed, is also provided.

Siguldry was heavily inspired by [Sigul](https://pagure.io/sigul) and shares
many of its design choices.
