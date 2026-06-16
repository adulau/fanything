# Active scan

`fanything-tls.nse` is the active collector. It creates its own network
interaction with the target and emits canonical features without a mode
component. The `active` mode is carried in the FAN/1 fingerprint prefix and in
output metadata:

```text
fingerprint: fan1:tls:server:active:<base64url-features>:sha256:<digest>
features: tls|server|v=<legacy_version>|c=<selected_cipher>|e=<extensions>|sv=<selected_supported_version>
```

The active TLS scanner exposes protocol-version probes:

* `TLSv1.3`: TLS 1.3 probe.
* `TLSv1.2`: TLS 1.2 probe.
* `TLSv1.1`: TLS 1.1 probe.
* `TLSv1.0`: TLS 1.0 probe.
* `SSLv3`: SSLv3 probe.
* `SSLv2`: SSLv2 probe.

Force one protocol version:

```bash
nmap -Pn -p443 --script ./fanything-tls.nse \
  --script-args fanything-tls.tls-version=TLSv1.3 <target>
```

Without `fanything-tls.tls-version`, the scanner tries protocol versions from
TLS 1.3 down to SSLv2 and stops at the first full server fingerprint. This
means default output is the highest successful protocol in that order, not a
full compatibility matrix.

## Source References

The script names cipher tables by protocol version. Firefox/NSS references are
used only to choose and document cipher-suite order:

* TLS 1.3 and TLS 1.2 use Firefox ESR 140 source as the modern NSS reference:
  * `security.tls.version.min = 3` means minimum TLS 1.2.
  * `security.tls.version.max = 4` means maximum TLS 1.3.
  * `security.tls.version.enable-deprecated = false`.
  * Enabled `security.ssl3.*` prefs define which TLS 1.2 and below suites are
    enabled.
  * NSS `SSL_ImplementedCiphers[]` defines the cipher-suite ordering.
* TLS 1.1, TLS 1.0, and SSLv3 use Firefox 33-era source as the historical NSS
  reference.

References:

* Firefox ESR 140 prefs:
  https://raw.githubusercontent.com/mozilla-firefox/firefox/esr140/modules/libpref/init/StaticPrefList.yaml
* NSS cipher-suite order:
  https://raw.githubusercontent.com/mozilla-firefox/firefox/esr140/security/nss/lib/ssl/sslenum.c
* Firefox 34 release notes, SSLv3 disabled:
  https://www.mozilla.org/en-US/firefox/34.0/releasenotes/
* Mozilla Security Blog, POODLE and SSLv3 shutdown plan:
  https://blog.mozilla.org/security/2014/10/14/the-poodle-attack-and-the-end-of-ssl-3-0/
* Firefox 78 release notes, TLS 1.0 and TLS 1.1 disabled:
  https://www.mozilla.org/en-US/firefox/78.0/releasenotes/
* Firefox 33 PSM cipher prefs and TLS version defaults:
  https://hg.mozilla.org/releases/mozilla-release/raw-file/FIREFOX_33_0_RELEASE/security/manager/ssl/src/nsNSSComponent.cpp
* Firefox 33 NSS cipher-suite order:
  https://hg.mozilla.org/releases/mozilla-release/raw-file/FIREFOX_33_0_RELEASE/security/nss/lib/ssl/sslenum.c

This is not a Firefox ClientHello emulator. The script uses protocol-version
tables and active scanner behavior; Firefox/NSS source is only the cipher-order
reference.

## TLS 1.3

Firefox ESR 140 allows TLS 1.3 and NSS orders the TLS 1.3 suites as follows.
Nmap's TLS library uses `TLS_AKE_*` names for TLS 1.3 suites.

| Order | IANA cipher suite | Nmap name | Value |
| --- | --- | --- | --- |
| 1 | `TLS_AES_128_GCM_SHA256` | `TLS_AKE_WITH_AES_128_GCM_SHA256` | `4865` (`0x1301`) |
| 2 | `TLS_CHACHA20_POLY1305_SHA256` | `TLS_AKE_WITH_CHACHA20_POLY1305_SHA256` | `4867` (`0x1303`) |
| 3 | `TLS_AES_256_GCM_SHA384` | `TLS_AKE_WITH_AES_256_GCM_SHA384` | `4866` (`0x1302`) |

The scanner also includes the TLS 1.2 suite list in the
TLS 1.3 ClientHello for compatibility, matching normal TLS negotiation behavior.
The `supported_versions` extension advertises only TLS 1.3 and TLS 1.2.

Expected active feature shape when the server selects TLS 1.3:

```text
tls|server|v=771|c=<selected_tls13_cipher>|e=<server_extensions>|sv=772
```

`v=771` is the TLS 1.2 legacy version in TLS 1.3 ServerHello. `sv=772`
identifies the selected supported version, TLS 1.3.

## TLS 1.2

The TLS 1.2 probe uses the enabled Firefox ESR 140/NSS suite order below.

| Order | Cipher suite | Value |
| --- | --- | --- |
| 1 | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `49195` (`0xc02b`) |
| 2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `49199` (`0xc02f`) |
| 3 | `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` | `52393` (`0xcca9`) |
| 4 | `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` | `52392` (`0xcca8`) |
| 5 | `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | `49196` (`0xc02c`) |
| 6 | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | `49200` (`0xc030`) |
| 7 | `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` | `49162` (`0xc00a`) |
| 8 | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `49161` (`0xc009`) |
| 9 | `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` | `49171` (`0xc013`) |
| 10 | `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` | `49172` (`0xc014`) |
| 11 | `TLS_RSA_WITH_AES_128_GCM_SHA256` | `156` (`0x009c`) |
| 12 | `TLS_RSA_WITH_AES_256_GCM_SHA384` | `157` (`0x009d`) |
| 13 | `TLS_RSA_WITH_AES_128_CBC_SHA` | `47` (`0x002f`) |
| 14 | `TLS_RSA_WITH_AES_256_CBC_SHA` | `53` (`0x0035`) |

Expected active feature shape when the server selects TLS 1.2:

```text
tls|server|v=771|c=<selected_tls12_cipher>|e=<server_extensions>|sv=
```

`sv` is empty for normal TLS 1.2 ServerHello because the TLS 1.3
`supported_versions` extension is not used to select TLS 1.2 in that response.

## TLS 1.1, TLS 1.0, SSLv3, SSLv2

Modern Firefox ESR 140 does not actively probe these protocols in normal
configuration, but `fanything-tls.nse` can probe them explicitly as active scanner
behavior:

| Protocol | Active scanner behavior | Firefox ESR 140 reference |
| --- | --- | --- |
| TLS 1.1 | probed by `fanything-tls.tls-version=TLSv1.1`, or by default only if TLS 1.3 and TLS 1.2 fail | below `security.tls.version.min = 3` |
| TLS 1.0 | probed by `fanything-tls.tls-version=TLSv1.0`, or by default only if higher versions fail | below `security.tls.version.min = 3` |
| SSLv3 | probed by `fanything-tls.tls-version=SSLv3`, or by default only if higher versions fail | obsolete |
| SSLv2 | probed by `fanything-tls.tls-version=SSLv2`, or by default only if higher versions fail | obsolete, no modern Firefox TLS policy |

Default active scan stops at the first full success:

```bash
nmap -Pn -p443 --script ./fanything-tls.nse <target>
```

Legacy probes should be interpreted as active scanner behavior, not Firefox ESR
140 behavior.

## Historical SSL Sources

For SSL-calibrated cipher ordering, the source reference must go back in
Firefox/NSS history. Firefox ESR 140 is the wrong reference for SSLv3 because it
has minimum TLS 1.2 and no SSL behavior.

Source-reference split:

| Protocol table | Protocol target | Browser/NSS anchor | Status |
| --- | --- | --- | --- |
| `TLS13_CIPHERS` | TLS 1.3 | Firefox ESR 140 | implemented |
| `TLS12_CIPHERS` | TLS 1.2 | Firefox ESR 140 | implemented |
| `LEGACY_CIPHERS` | TLS 1.1, TLS 1.0, SSLv3 | Firefox 33 era, before Firefox 34 disabled SSLv3 after POODLE | implemented |
| `SSLV2_CIPHERS` | SSLv2 | Nmap SSLv2 library, no Firefox calibration | implemented as scanner measurement |

This matters for cipher suites:

* TLS 1.3 and TLS 1.2 can use the Firefox ESR 140/NSS `SSL_ImplementedCiphers[]`
  order documented above.
* TLS 1.1 and TLS 1.0 should use a pre-Firefox-78 NSS source if browser
  fidelity is required. Firefox 78 release notes document that TLS 1.0 and
  TLS 1.1 were disabled in that release.
* SSLv3 should use a pre-Firefox-34 source. Firefox 34 release notes document
  `Disabled SSLv3`, and Mozilla's POODLE post explains the shutdown plan.
* SSLv2 should not be inferred from modern Firefox. It needs a separate old NSS
  source audit before claiming a Firefox-equivalent cipher order. OpenSSL 3.x
  also lacks practical `s_server` SSLv2 coverage, so local validation needs an
  older SSL stack or a purpose-built SSLv2 test server.

## Firefox 33-Era Legacy Source

The legacy cipher table exists because SSLv3 calibration needs older browser
behavior. Firefox 33 source uses `security.tls.version.min = 0` and
`security.tls.version.max = 3`, meaning SSLv3 through TLS 1.2. It also uses
`sCipherPrefs` defaults for enabled suites. The scanner orders those enabled
suites using Firefox 33 NSS `SSL_ImplementedCiphers[]`.

TLS 1.2 uses this enabled Firefox 33-era order:

| Order | Cipher suite | Value |
| --- | --- | --- |
| 1 | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `49195` (`0xc02b`) |
| 2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `49199` (`0xc02f`) |
| 3 | `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` | `49162` (`0xc00a`) |
| 4 | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `49161` (`0xc009`) |
| 5 | `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` | `49171` (`0xc013`) |
| 6 | `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` | `49172` (`0xc014`) |
| 7 | `TLS_ECDHE_ECDSA_WITH_RC4_128_SHA` | `49159` (`0xc007`) |
| 8 | `TLS_ECDHE_RSA_WITH_RC4_128_SHA` | `49169` (`0xc011`) |
| 9 | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | `51` (`0x0033`) |
| 10 | `TLS_DHE_DSS_WITH_AES_128_CBC_SHA` | `50` (`0x0032`) |
| 11 | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA` | `57` (`0x0039`) |
| 12 | `TLS_RSA_WITH_AES_128_CBC_SHA` | `47` (`0x002f`) |
| 13 | `TLS_RSA_WITH_AES_256_CBC_SHA` | `53` (`0x0035`) |
| 14 | `TLS_RSA_WITH_3DES_EDE_CBC_SHA` | `10` (`0x000a`) |
| 15 | `TLS_RSA_WITH_RC4_128_SHA` | `5` (`0x0005`) |
| 16 | `TLS_RSA_WITH_RC4_128_MD5` | `4` (`0x0004`) |

TLS 1.1, TLS 1.0, and SSLv3 use the same Firefox 33-era enabled order without
TLS 1.2-only GCM suites:

| Order | Cipher suite | Value |
| --- | --- | --- |
| 1 | `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` | `49162` (`0xc00a`) |
| 2 | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `49161` (`0xc009`) |
| 3 | `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` | `49171` (`0xc013`) |
| 4 | `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` | `49172` (`0xc014`) |
| 5 | `TLS_ECDHE_ECDSA_WITH_RC4_128_SHA` | `49159` (`0xc007`) |
| 6 | `TLS_ECDHE_RSA_WITH_RC4_128_SHA` | `49169` (`0xc011`) |
| 7 | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | `51` (`0x0033`) |
| 8 | `TLS_DHE_DSS_WITH_AES_128_CBC_SHA` | `50` (`0x0032`) |
| 9 | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA` | `57` (`0x0039`) |
| 10 | `TLS_RSA_WITH_AES_128_CBC_SHA` | `47` (`0x002f`) |
| 11 | `TLS_RSA_WITH_AES_256_CBC_SHA` | `53` (`0x0035`) |
| 12 | `TLS_RSA_WITH_3DES_EDE_CBC_SHA` | `10` (`0x000a`) |
| 13 | `TLS_RSA_WITH_RC4_128_SHA` | `5` (`0x0005`) |
| 14 | `TLS_RSA_WITH_RC4_128_MD5` | `4` (`0x0004`) |

`SSLV2_CIPHERS` does not claim Firefox equivalence. Firefox 33 NSS still lists
SSLv2 cipher IDs, but the Firefox 33 version defaults start at SSLv3, not
SSLv2.

## Test harness

Run active scan tests against local OpenSSL servers:

```bash
test/nse-openssl.sh
```

The harness validates TLS 1.3, TLS 1.2, TLS 1.1, and TLS 1.0 against local
OpenSSL servers. It also starts a multi-version TLS 1.0-to-1.2 server and checks
that default scan output contains exactly one TLS server fingerprint. SSLv3 and
SSLv2 are skipped when the local OpenSSL build no longer provides those server
modes.
