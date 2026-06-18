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

The active request payload order is strict and mirrors the passive
`IKE_SA_INIT` fixture shape used as probe reference:

```text
1. SA      payload type 33
2. KE      payload type 34
3. Nonce   payload type 40
4. VID     payload type 43
5. VID     payload type 43
6. Notify  payload type 41, notify type 16388
7. Notify  payload type 41, notify type 16389
8. Notify  payload type 41, notify type 16430
9. VID     payload type 43
```

The SA proposal is deterministic:

```text
proposal number: 1
protocol ID: 1
SPI size: 0
transform count: 3

1. transform type 1, transform ID 20, key length 256
2. transform type 2, transform ID 5
3. transform type 4, transform ID 19
```

Canonical active probe SA string:

```text
sa=1:1=20.256,2=5,4=19
```

The KE payload uses group `19` and a deterministic-length public value made of
255 zero bytes followed by byte `04`. The Nonce payload is 32 random bytes.
Vendor ID payload content is fixed probe text; fingerprinting records only the
payload type sequence, not Vendor ID bytes.

Canonical active initiator probe shape:

```text
ike|initiator|v=2.0|ex=34|flags=8|np=33|p=33-34-40-43-43-41-41-41-43|sa=1:1=20.256,2=5,4=19|ke=19|n=16388-16389-16430
```
