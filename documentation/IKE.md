# IKE

FAN/1 IKE fingerprints currently target IKEv2 packets. Passive extraction can
emit initiator and responder observations. Active scanning emits responder
behavior from an `IKE_SA_INIT` probe.

```text
ike|<role>|v=<major.minor>|ex=<exchange_type>|flags=<flags>|np=<first_payload>|p=<payload_types>|sa=<accepted_or_offered_sa>|ke=<dh_group>|n=<notify_types>
```

## Fields

| Field | Length | Meaning |
| --- | --- | --- |
| `ike` | fixed literal | Protocol namespace. |
| `<role>` | fixed vocabulary | `initiator` or `responder` in passive mode; `responder` in active mode. |
| `v` | variable numeric text | IKE version as `major.minor`, for example `2.0`. |
| `ex` | variable numeric text | IKE exchange type from header. `34` is `IKE_SA_INIT`; `35` is `IKE_AUTH`. |
| `flags` | variable numeric text | IKE flags byte from header. `8` means initiator flag; `32` means response flag. |
| `np` | variable numeric text | First payload type from IKE header. |
| `p` | variable list | Payload type sequence from clear payload chain. Decimal values joined with `-`; wire order preserved. |
| `sa` | variable structured list | Security Association proposals. Empty when SA payload is absent or encrypted. |
| `ke` | variable numeric text | Diffie-Hellman group from KE payload. Empty when KE payload is absent or encrypted. |
| `n` | variable list | Notify message types from Notify payloads. Decimal values joined with `-`; wire order preserved. |

Empty fields are represented as empty strings.

## Payload Values

Common payload type numbers in current parser output:

| Value | Payload |
| --- | --- |
| `33` | Security Association (`SA`) |
| `34` | Key Exchange (`KE`) |
| `40` | Nonce |
| `41` | Notify |
| `43` | Vendor ID |
| `46` | Encrypted and Authenticated |

When payload `46` appears, following IKE payloads are encrypted. `fanfp.py`
does not decrypt them, so `sa=`, `ke=`, and `n=` are usually empty for those
packets.

## Notify Values

`n=` contains IKEv2 Notify Message Types extracted from Notify payloads
(`payload type 41`). Values are decimal and preserve wire order.

Reference registry:
[IANA IKEv2 Notify Message Error and Status Types](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml).

Common values seen while probing IKEv2:

| Value | Notify type | Meaning |
| --- | --- | --- |
| `7` | `INVALID_SYNTAX` | Responder considers the packet malformed or syntactically invalid. |
| `9` | `INVALID_MESSAGE_ID` | Message ID is invalid for current IKE SA state. |
| `11` | `INVALID_SPI` | Referenced SPI is unknown or invalid for the peer. Common when a packet refers to a non-existing SA. |
| `14` | `NO_PROPOSAL_CHOSEN` | Responder understood the request but rejected the proposed SA transforms. |
| `17` | `INVALID_KE_PAYLOAD` | KE group is not acceptable; responder may include preferred group. |
| `24` | `AUTHENTICATION_FAILED` | Authentication failed, usually later than `IKE_SA_INIT`. |
| `34` | `SINGLE_PAIR_REQUIRED` | Responder requires traffic selectors to contain one address pair. |
| `35` | `NO_ADDITIONAL_SAS` | Responder will not accept additional child SAs. |
| `36` | `INTERNAL_ADDRESS_FAILURE` | Internal address assignment failed. |
| `37` | `FAILED_CP_REQUIRED` | Configuration payload required or failed. |
| `38` | `TS_UNACCEPTABLE` | Traffic selectors are unacceptable. |
| `39` | `INVALID_SELECTORS` | Packet selectors do not match negotiated selectors. |
| `16388` | `NAT_DETECTION_SOURCE_IP` | NAT detection hash for source address/port. |
| `16389` | `NAT_DETECTION_DESTINATION_IP` | NAT detection hash for destination address/port. |
| `16392` | `HTTP_CERT_LOOKUP_SUPPORTED` | Peer supports HTTP-based certificate lookup. |
| `16404` | `MULTIPLE_AUTH_SUPPORTED` | Peer supports multiple authentication rounds. |
| `16418` | `CHILDLESS_IKEV2_SUPPORTED` | Peer supports IKE SA setup without immediately creating a Child SA. |
| `16430` | `IKEV2_FRAGMENTATION_SUPPORTED` | Peer advertises IKEv2 fragmentation support. |

Observed valid responder status combinations:

| `n=` | Meaning |
| --- | --- |
| empty | No Notify payloads in clear responder chain. This is normal when response contains `SA-KE-Nonce` only. |
| `16388-16389` | NAT detection source and destination hashes. Common normal `IKE_SA_INIT` response. |
| `16404` | Multiple authentication supported. |
| `16418-16404` | Childless IKEv2 and multiple authentication supported. |
| `16392` | HTTP certificate lookup supported. |
| `16388-16389-16430` | NAT detection plus fragmentation support. |

Examples:

```text
ike|responder|v=2.0|ex=34|flags=32|np=41|p=41|sa=|ke=|n=14
ike|responder|v=2.0|ex=34|flags=32|np=41|p=41|sa=|ke=|n=7
```

These are responder-only Notify packets. `n=14` means the target is alive but
did not accept the proposed crypto suite. `n=7` means the target rejected the
packet syntax.

## SA Encoding

`sa=` is encoded as proposals separated by `;`.

```text
<protocol_id>:<transform_type>=<transform_id>[.<key_length>],...
```

Example:

```text
sa=1:1=20.256,2=5,4=19
```

Meaning:

| Part | Meaning |
| --- | --- |
| `1:` | IKE protocol ID. |
| `1=20.256` | Transform type `1` encryption algorithm, transform ID `20`, key length `256`. |
| `2=5` | Transform type `2` pseudorandom function, transform ID `5`. |
| `4=19` | Transform type `4` Diffie-Hellman group, transform ID `19`. |

The active NSE probe uses same SA transform encoding as `fanfp.py`.

## Passive Extraction

`fanfp.py` scans UDP datagrams where either source or destination port is `500`
or `4500`. For UDP/4500, it removes the four-byte NAT-T non-ESP marker
`00000000` before parsing.

Role is derived from IKE flags:

| Flag bit | Role |
| --- | --- |
| response bit `0x20` set | `responder` |
| response bit not set | `initiator` |

Example from `pcap/ikev2_s2s_ipsec_vpn_aes_gcm.pcapng`:

```text
ike|initiator|v=2.0|ex=34|flags=8|np=33|p=33-34-40-43-43-41-41-41-43|sa=1:1=20.256,2=5,4=19|ke=19|n=16388-16389-16430
ike|responder|v=2.0|ex=34|flags=32|np=33|p=33-34-40-43-43-41-41-41-43|sa=1:1=20.256,2=5,4=19|ke=19|n=16388-16389-16430
```

## Active Request Defaults

`fanything-ike.nse` sends one IKEv2 `IKE_SA_INIT` request and fingerprints the
responder packet.

| Default | Value |
| --- | --- |
| Transport | UDP |
| Ports/services | UDP/500 `isakmp`, UDP/4500 `ipsec-nat-t`, unless `fanything-ike.force` is set |
| Timeout | `5000` ms |
| Exchange type | `34` (`IKE_SA_INIT`) |
| Request flags | `8` (`initiator`) |
| Request first payload | `33` (`SA`) |
| NAT-T marker | Four zero bytes when target port is `4500`; absent on port `500` |
| Output role | `responder` |
| Output mode | `active` |

Arguments:

```text
fanything-ike.timeout=<milliseconds>
fanything-ike.force=true
```

## Active Request Order

The active request payload order is strict and intentionally minimal. The goal
is to get a valid `IKE_SA_INIT` responder selection rather than a standalone
Notify error.

`fanything-ike.nse` sends exactly one `IKE_SA_INIT` request per target port. It
does not try proposal 1, then retry proposal 2, then retry proposal 3. All
proposals are inside the same SA payload. The responder selects one acceptable
proposal, usually the first one it accepts according to its policy, and returns
that selected SA in the response.

Scan outcome:

| Response | Script behavior |
| --- | --- |
| Valid `SA-KE-Nonce` response | Emit one active responder fingerprint and stop for that port. |
| Valid response with extra status Notify or Vendor ID payloads | Emit one active responder fingerprint and stop for that port. |
| Notify-only `INVALID_SYNTAX` (`n=7`) | Treat as invalid probe response; no fingerprint. |
| Notify-only `NO_PROPOSAL_CHOSEN` (`n=14`) | Treat as incompatible proposal response; no fingerprint. |
| No response or malformed response | No fingerprint. |

```text
1. SA      payload type 33
2. KE      payload type 34
3. Nonce   payload type 40
```

The SA proposals are deterministic:

```text
proposal 1:
1. transform type 1, transform ID 12, key length 256
2. transform type 2, transform ID 5
3. transform type 3, transform ID 12
4. transform type 4, transform ID 14

proposal 2:
1. transform type 1, transform ID 12, key length 128
2. transform type 2, transform ID 2
3. transform type 3, transform ID 2
4. transform type 4, transform ID 14

proposal 3:
1. transform type 1, transform ID 20, key length 256
2. transform type 2, transform ID 5
3. transform type 4, transform ID 14
```

Possible selected SA strings include:

```text
sa=1:1=12.256,2=5,3=12,4=14
sa=1:1=12.128,2=2,3=2,4=14
sa=1:1=20.256,2=5,4=14
```

The KE payload uses group `14` and a deterministic-length public value made of
255 zero bytes followed by byte `04`. The Nonce payload is 32 random bytes.

Canonical active initiator probe shape:

```text
ike|initiator|v=2.0|ex=34|flags=8|np=33|p=33-34-40|sa=<multi-proposal-sa>|ke=14|n=
```
