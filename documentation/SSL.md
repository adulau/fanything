# SSL

FAN/1 treats SSLv3 and SSLv2 as legacy active TLS-family measurements. Modern
passive ClientHello parsing uses the TLS feature strings when SSL/TLS records
are available.

## SSLv3 Feature Shape

SSLv3 active probing emits the normal TLS server shape:

```text
tls|server|v=<legacy_version>|c=<selected_cipher>|e=<extensions>|sv=
```

SSLv3 has no TLS extensions in normal use, so `e=` is usually empty and `sv=`
is empty.

| Field | Length | Meaning |
| --- | --- | --- |
| `tls` | fixed literal | TLS-family namespace used by the script. |
| `server` | fixed literal | Server selection role. |
| `v` | variable numeric text | Legacy protocol version from ServerHello. |
| `c` | variable numeric text | Cipher suite selected by server. |
| `e` | variable list | Server extension types if any are present; usually empty for SSLv3. |
| `sv` | empty | No `supported_versions` selection in SSLv3. |

## SSLv2 Feature Shape

SSLv2 active probing has a special fallback shape:

```text
tls|server|v=2|c=<server_cipher_specs>|e=|sv=
```

| Field | Length | Meaning |
| --- | --- | --- |
| `tls` | fixed literal | TLS-family namespace used by the script. |
| `server` | fixed literal | Server response role. |
| `v` | fixed numeric text | `2`, meaning SSLv2 response path. |
| `c` | variable list | SSLv2 cipher specs advertised by server. Decimal values joined with `-`; order from server response preserved. |
| `e` | empty | SSLv2 has no TLS extension list. |
| `sv` | empty | SSLv2 has no TLS `supported_versions` extension. |

## Active Request Defaults

`fanything-tls.nse` includes SSL probes after TLS probes by default:

```text
TLSv1.3, TLSv1.2, TLSv1.1, TLSv1.0, SSLv3, SSLv2
```

Default scan stops at the first full server fingerprint. SSL probes run only
when higher TLS versions fail, unless forced with `fanything-tls.tls-version`.

| Probe | Default request behavior |
| --- | --- |
| `SSLv3` | Uses legacy cipher order derived from Firefox 33-era NSS enabled ciphers. |
| `SSLv2` | Uses Nmap SSLv2 library cipher names for old-server measurement only. |
| Timeout | `5000` ms |
| Output role | `server` |
| Output mode | `active` |

## Active Request Order

SSL probes inherit the deterministic active scanner order. They are reached only
after higher TLS probes fail unless forced with `fanything-tls.tls-version`.

### SSLv3 ClientHello Cipher Order

```text
1. TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA 49162
2. TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA 49161
3. TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA   49171
4. TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA   49172
5. TLS_ECDHE_ECDSA_WITH_RC4_128_SHA     49159
6. TLS_ECDHE_RSA_WITH_RC4_128_SHA       49169
7. TLS_DHE_RSA_WITH_AES_128_CBC_SHA     51
8. TLS_DHE_DSS_WITH_AES_128_CBC_SHA     50
9. TLS_DHE_RSA_WITH_AES_256_CBC_SHA     57
10. TLS_RSA_WITH_AES_128_CBC_SHA        47
11. TLS_RSA_WITH_AES_256_CBC_SHA        53
12. TLS_RSA_WITH_3DES_EDE_CBC_SHA       10
13. TLS_RSA_WITH_RC4_128_SHA            5
14. TLS_RSA_WITH_RC4_128_MD5            4
```

For SSLv3, the scanner still builds the shared legacy extension table in code,
but SSLv3 servers generally do not return TLS extensions. The emitted `e=` and
`sv=` fields are usually empty.

Force SSL probes:

```text
fanything-tls.tls-version=SSLv3
fanything-tls.tls-version=SSLv2
```

SSLv2 request cipher order:

```text
SSL2_RC4_128_WITH_MD5
SSL2_RC4_128_EXPORT40_WITH_MD5
SSL2_RC2_128_CBC_WITH_MD5
SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
SSL2_IDEA_128_CBC_WITH_MD5
SSL2_DES_64_CBC_WITH_MD5
SSL2_DES_192_EDE3_CBC_WITH_MD5
```
