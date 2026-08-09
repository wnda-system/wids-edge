# Can params.md's 351 training columns be added to the capture app?

Short answer: no field can be added as-is — `params.md` describes 351 **one-hot-encoded
training columns**, not raw packet fields, and a live capture can only ever produce the
underlying raw field (this was already called out in `wifi_capture_poc_spec.md`'s schema
note). What I did instead: went through all 352 columns actually listed in `params.md`
(one more than the doc's own "351" header — a minor miscount in the source file, not
something worth chasing further) and, for every one, extracted or approximated the
**raw underlying field** directly in `capture.py` wherever that's genuinely possible from
a live packet.

`capture.py` and `app.py` are updated and tested (synthetic packets in a sandbox, plus a
full simulate-mode capture run end-to-end). The new columns show up in `simulate` mode
right now; the rest need your monitor-mode adapter to actually see traffic.

## The four outcomes

| Outcome | Count | What it means |
|---|---:|---|
| **Added & working** | 30 | New raw field extracted in `capture.py`, verified against synthetic packets |
| **Blocked on this device** | 55 | Code path exists (mostly already did, pre-dating this change), but needs a monitor-mode-capable adapter — you said you don't have one |
| **Not implemented (feasible, not attempted)** | 88 | Real Wireshark fields, but each needs meaningfully more work than this pass covered — see reasons below |
| **Not obtainable from a live capture at all** | 179 | These are one-hot buckets (e.g. `wlan.ssid_ASUS`, `tcp.flags.ack_0-1-0`) — reproducing the *exact* column needs the fitted training-time encoder, not a live packet |

Of those 179 one-hot columns, **128 do have a usable raw equivalent** now captured
(e.g. `dhcp.option.router_192.168.2.1` → we now capture raw `dhcp.option.router`;
`tls.handshake.version_0x00000303` → raw `tls.handshake.version`). The remaining 51 have
no raw equivalent at all, mostly because they're SSH negotiation fields (35 of them —
see below).

## Added this pass (raw fields, new in `capture.py`)

- **DNS**: `dns.count.auth_rr`, `dns.count.add_rr`, `dns.flags.authoritative`, `dns.flags.checkdisable`, `dns.flags.opcode`, plus a bonus `dns.count.labels`
- **HTTP**: `http.content_length`, `http.connection`, `http.request.version`, `http.response.version`
- **ARP**: `arp.hw.size`, `arp.proto.size`
- **DHCP**: `dhcp.id`, `dhcp.cookie`, `dhcp.option.router`, `dhcp.option.dhcp_server_id`, `dhcp.option.broadcast_address` (parsed from BOOTP/DHCP options)
- **SMB2**: `smb2.protocol_id`, `smb2.header_len`, `smb2.cmd`, `smb2.pid` — parsed by hand from the cleartext 64-byte SMB2 header (no dissector library needed, the header format is fixed and public)
- **NBSS** (legacy NetBIOS, port 139): `nbss.length`, `nbss.type`
- **TLS**: `tls.handshake.version` — read straight out of the cleartext ClientHello/ServerHello record header, before encryption starts
- **TCP**: `tcp.analysis.retransmission` — heuristic (exact duplicate segment: same 5-tuple + seq + payload length seen twice), not Wireshark's full stream-state analysis
- **Frame**: `frame.time_relative`, `frame.time_delta_displayed`
- **Presence flags**: `ldap.present`, `nbns.present`, `ssdp.present`, `llc.present` (added for `ldap_ldap`, `nbns_nbns`, `ssdp_ssdp`, `llc_llc`)
- **Engineered**: `has_app_features`, `has_mac_features` (computed from whether any field in that OSI-layer group was actually captured on the row)

## Blocked on this device (55 columns) — needs monitor mode

All 42 `wlan.*` and 11 `radiotap.*` columns, plus `eapol.keydes.replay_counter` and
`n_unique_dest_mac_per_sec`. These aren't a code problem — the code to read them already
existed before this change (`wlan.fc.type`, `wlan.ssid`, `wlan_radio.signal_dbm`, etc. were
already in `capture.py`). A managed-mode WiFi interface's driver strips 802.11 headers and
radio metadata before handing packets to any userspace socket; only a monitor-mode adapter
exposes them. Since you don't have monitor-mode hardware on this device, these columns will
capture as `-1` regardless — `simulate` mode is the only way to see what they'd look like.

## Not implemented — feasible, just out of scope for this pass (88 columns)

- **SSH (51 columns, all of them)**: SSH's key-exchange negotiation packet is cleartext and
  technically parseable (cookie, algorithm lists, protocol banner), but scapy has no SSH
  dissector — it would need a hand-written binary parser. Real effort; I left it at
  presence-only (`ssh.present`, already existed).
- **SMB v1 (all 12 columns)**: deprecated protocol, disabled by default on Windows since
  ~2017 — didn't build a dissector for it, presence-only.
- **HTTP timing/correlation (5 columns)**: `http.request_in`, `http.response_in`, etc. need
  matching each request to its response across a stream — session-level state beyond this
  pass.
- **DNS correlation (4 columns)**: `dns.retransmit_request/response`, `dns.time` need
  transaction-ID based matching across the whole capture.
- **TLS records/extensions (5 columns)**: alerts, session tickets, compressed-cert extension
  — rare, need a real TLS record parser beyond the single ClientHello check implemented.
- **TCP expert-info (4 columns)**: `tcp.analysis`/`tcp.analysis.flags` aren't real scalar
  values in Wireshark either (they're tree nodes); `reused_ports` needs full stream
  teardown tracking; `checksum.status` needs NIC offload awareness.
- **ICMPv6 (2), DHCP niche options (3), SMB2 body fields (2)**: obscure/command-specific
  sub-fields, low value for the effort.

Full reasoning for every individual column is in `params_coverage.csv` (352 rows: group,
field, status, reason — including which one-hot columns have a raw equivalent now captured).

## The 179 one-hot columns, in one sentence

`params.md` is explicit about this already: those are the *encoded* training columns, and
turning a raw capture into that exact 351-column format needs the fitted encoder/vocabulary
from training (not present in `params.md`) — that's a separate, later step once that encoder
file is available, not something a live capture can produce on its own.
