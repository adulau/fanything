# QUIC Fingerprint Reference

Client example:

```text
quic|client|v=1|tls_v=771|c=4865-4866-4867|e=65037-57-45-0-27-16-51-10-17613-43-13|g=4588-29-23-24|p=|sv=772|alpn=h3|sig=1027-2052-1025-1283-2053-1281-2054-1537-513
```

Client fields:

* `quic`: Fingerprinted transport protocol.
* `client`: Observed role. This means the fingerprint was extracted from the
  client-side TLS ClientHello carried inside QUIC Initial packets.
* `v`: QUIC version from the QUIC Initial packet.
* `tls_v`: Legacy TLS version field from the TLS ClientHello. For TLS 1.3 this
  is a compatibility field, not the final negotiated TLS version.
* `c`: Ordered list of cipher suites advertised by the client.
* `e`: Ordered list of TLS extension types present in the ClientHello. GREASE
  values are removed before canonicalization.
* `g`: Ordered list of supported cryptographic groups, such as ECDHE curves or
  key exchange groups.
* `p`: EC point formats advertised by the client. This is often empty for
  modern TLS 1.3 clients.
* `sv`: TLS versions advertised through the `supported_versions` extension.
  This is the authoritative TLS version capability signal for TLS 1.3 clients.
* `alpn`: Application protocols advertised through ALPN.
* `sig`: Ordered list of supported signature algorithms.

Server example:

```text
quic|server|v=1|tls_v=771|c=4865|e=51-43|sv=772
```

Server fields:

* `quic`: Fingerprinted transport protocol.
* `server`: Observed role. This means the fingerprint was extracted from the
  server-side TLS ServerHello carried inside QUIC Initial packets.
* `v`: QUIC version from the QUIC Initial packet.
* `tls_v`: Legacy TLS version field from the TLS ServerHello. For TLS 1.3 this
  is a compatibility field, not the final negotiated TLS version.
* `c`: Cipher suite selected by the server.
* `e`: Ordered list of TLS extension types present in the ServerHello. GREASE
  values are removed before canonicalization.
* `sv`: TLS version selected through the `supported_versions` extension. This is
  the authoritative TLS version selection signal for TLS 1.3 servers.
