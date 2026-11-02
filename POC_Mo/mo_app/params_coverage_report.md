# Can params.md's 351 training columns be added to the capture app?

> **Update (6th pass)**: added an **opt-in** LLC/SNAP dispatch path — a
> colleague's review flagged that unencrypted 802.11 Data frames' LLC/SNAP
> payload wasn't being walked into to reach IP/ARP/EAPOL. `capture.py`
> itself is unchanged in row/column count (no new fields — this affects
> whether *existing* app-layer fields get populated, not which columns
> exist); the app now has a toggle between "Original" and "LLC/SNAP
> dispatch (experimental)" extraction. See "Sixth pass" near the end —
> including why I couldn't reproduce the underlying gap synthetically, so
> this needs validating against a real capture.

> **Update (5th pass)**: added `http.response.code.desc`, and — while
> looking into `ssdp.description` — found and fixed a real gap: SSDP
> (M-SEARCH/NOTIFY/response) traffic was never populating `http.request.
> method`/`http.response.code` at all, because scapy's HTTP layer only
> dissects TCP, not SSDP's UDP/1900. See "Fifth pass additions" near the
> end. `capture.py` is now at **155** raw columns (112 → 134 → 141 → 154 →
> 155).

> **Update (4th pass)**: added `wlan.tag`, `wlan.rsn.capabilities.mfpc`,
> `dhcp.description`, `dns.description`, `mdns.description`,
> `smb.flags.response`, `smb.flags2.sec_sig`, `smb.flags2.nt_error`,
> `smb.access.generic_read/write/execute`, `icmpv6.mldr.nb_mcast_records`,
> `tcp.checksum.status` — see "Fourth pass additions" near the end.
> `capture.py` is now at **154** raw columns (112 → 134 → 141 → 154). Also
> clarifies that the `arp`/`nbns`/`ldap`/`llc`/`ssdp` "raw summary string"
> columns asked about were already fully covered before this pass — see
> that section for why.

> **Update (3rd pass)**: added `wlan.fc.ds`, `radiotap.present.tsft`,
> `radiotap.timestamp.ts`, `wlan_radio.timestamp`, `wlan_radio.start_tsf`,
> `wlan_radio.duration`, `wlan_radio.end_tsf` — see "Third pass additions"
> further down. `capture.py` was at 141 raw columns after this (112 → 134
> → 141 → 154).

> **Update (2nd pass)**: pushed further into the "not implemented" list —
> see "Second pass additions" further down. Also found and fixed two more
> real, pre-existing bugs while testing (see that section) — one of them
> (`FCfield` bit extraction) meant `wlan.fc.retry`/`wlan.fc.protected` had
> likely never actually worked on a real capture, ever.


Short answer, unchanged from the last pass: no field can be added **as-is** — `params.md`
describes 351 one-hot-encoded training columns, not raw packet fields, and a live capture
can only ever produce the underlying raw field. Turning raw values into that exact
351-column format still needs the fitted training-time encoder/vocabulary — that's a later
step, not something a live capture can do on its own (see `wifi_capture_poc_spec.md`'s
schema note).

What changed **this pass**: your monitor-mode adapter (`wlx1cbfce71ebe7`) is now up and in
real monitor mode, and I closed most of the remaining "not implemented" gap from the
previous pass — SSH in particular, which was the single biggest chunk (51 of the 351
columns). `capture.py` went from **74 → 112 raw output columns**.

## What's new in `capture.py` this pass

- **SSH (21 new columns)** — hand-written parser (scapy has no SSH dissector) covering the
  cleartext version banner, and — from the Binary Packet Protocol framing — SSH_MSG_KEXINIT,
  SSH_MSG_KEX_DH_GEX_REQUEST, and SSH_MSG_KEXDH_REPLY/KEX_ECDH_REPLY: `ssh.protocol`,
  `ssh.direction`, `ssh.message_code`, `ssh.packet_length`, `ssh.padding_length`,
  `ssh.padding_string`, `ssh.cookie`, all 8 `*_algorithms_*_length` fields,
  `ssh.dh_gex.min/max/nbits`, `ssh.host_key.length/type_length`, `ssh.mpint_length`. Unit-
  tested against synthetic KEXINIT/version-banner/KEXDH-reply packets, byte-for-byte correct.
  Single TCP segment only — no stream reassembly, same limitation as the SMB2/TLS/NBSS
  parsers below.
- **EAPOL — bug fix + 1 new column**: `eapol.keydes.key_len` was silently broken since it
  was first added (scapy's `EAPOL` class has no `key_length` attribute, so the old
  `getattr`-based extraction always returned `-1`). Replaced with a hand-parse of the
  EAPOL-Key body at the correct byte offsets; also added `eapol.keydes.replay_counter`.
  (Caught the wrong-offset version of this fix too, mid-pass, via a synthetic-packet test —
  see below.)
- **HTTP correlation (3 new columns)**: `http.request_in`, `http.response_in`, `http.time`,
  via a per-TCP-stream FIFO tracked in `session_state` across the capture.
  `http.next_request_in`/`http.next_response_in` (pipelining-collision fields) are **not**
  implemented — low-confidence semantics for the effort.
- **DNS correlation (4 new columns)**: `dns.retransmit_request`, `dns.retransmit_response`,
  `dns.time` (transaction-ID keyed), plus `dns.resp.len` (missed in the previous pass).
- **SMB2 body fields (4 new columns)**: `smb2.buffer_code` (every command), plus
  `smb2.data_offset`/`smb2.write_length` (WRITE request) and `smb2.session_flags`
  (SESSION_SETUP response), all hand-parsed at fixed offsets past the 64-byte header.
  `smb2.auth_frame` still not implemented — needs session-wide MessageId correlation.
- **DHCP**: `dhcp.hw.addr_padding` (the zero-padding after the actual MAC in BOOTP's
  fixed 16-byte `chaddr` field).
- **TLS (3 new columns)**: `tls.alert_message.level`/`.desc` (Alert record, cleartext),
  `tls.handshake.session_ticket_length` (walks a ClientHello's extension list for ext type
  35). `tls.connection_id` and `tls.compress_certificate...length` still not implemented —
  rarer extensions/messages, real effort for 2 columns.
- **`n_unique_dest_mac_per_sec`**: the one remaining engineered feature, added as a
  whole-capture post-processing pass (`add_derived_columns()`) — buckets rows by
  `floor(frame.time_epoch)`, counts distinct `wlan.da` per bucket, assigns back to every row
  in that bucket. Needs monitor mode, same as the `wlan.*`/`radiotap.*` block.

All of the above is exercised in `simulate` mode too (`generate_mock_row` now covers ssh/
eapol/dhcp-padding/tls-alert/session-ticket kinds, and fakes the HTTP/DNS correlation the
same way the real path does) — verified with a live simulate-mode capture run.

## Hardware status change

`iw dev` confirms `wlx1cbfce71ebe7` is up in real monitor mode right now. The 53
`wlan.*`/`radiotap.*` columns that were "blocked on this device" in the last report needed
no new code — that extraction already existed — they were blocked purely because there was
no monitor-mode adapter available. That's no longer true.

**I couldn't verify this with an actual live capture myself this session** — opening the
raw socket needs root/`CAP_NET_RAW`, and this environment's `sudo` requires an interactive
password I don't have (the `wifi-capture-sudoers` NOPASSWD rule also isn't installed, and
its path is stale — it points at `/home/molecule/mo_app`, not this repo's actual
`.../mo_app` location). Everything else in this report was verified with synthetic-packet
unit tests and full simulate-mode runs; the monitor-mode fields specifically are unverified
against real traffic. Easiest way to confirm: run

```bash
sudo venv/bin/python3 app.py
```

then trigger a real (non-simulate) capture against `wlx1cbfce71ebe7` from the UI, or ask me
to review the resulting CSV afterward.

## Updated outcome counts (raw fields, out of the ~352 fields params.md's 351 columns
## are built from)

| Outcome | Count | Change from last pass |
|---|---:|---|
| Raw field extracted in `capture.py` | 67 | +37 (30 before) |
| Working now that hardware is available (code pre-existed) | 55 | unchanged code, now unblocked |
| Not implemented (feasible, real effort) | ~15 | -73 (was 88) |
| Not obtainable from a live capture at all (pure one-hot buckets) | 179 | unchanged — structural, needs the training-time encoder |

Still not implemented after the previous pass, with reasons:
- **SMB v1 — 7 of 12 columns** (`smb.flags.notify`, `smb.flags.response`, `smb.flags2.nt_error`,
  `smb.flags2.sec_sig`, `smb.access.generic_execute/read/write`): the other 5 got added this
  pass (see below) since they're literal fixed-offset integer reads. These 7 are bit-flag or
  ACE sub-fields I don't have high confidence reproducing correctly for a deprecated protocol
  (disabled by default on Windows since ~2017) — wrong data is worse than `-1`.
- **`http.next_request_in`/`next_response_in` (2)**: pipelining-collision fields — low
  value, low-confidence semantics for a WiFi-client capture (pipelining is rare).
- **`smb2.auth_frame` (1)**: needs full session-wide MessageId correlation across many
  frames, not a fixed-offset parse.
- **`tls.connection_id`, `tls.compress_certificate...length` (2)**: rarer TLS 1.3
  extension/message, need a fuller extension walk / a second handshake-message type.
- **TCP expert-info (4)**: `tcp.analysis`/`tcp.analysis.flags` aren't real scalar values in
  Wireshark either (tree nodes); `reused_ports` needs full stream teardown tracking;
  `checksum.status` needs NIC-offload awareness and its enum semantics carry real risk of
  being subtly wrong.
- **ICMPv6 (2), DHCP niche options (2 of 3 — `duid_ll_hw_type` is actually a DHCPv6 field,
  `vendor.bsdp.message_type` is an Apple-specific vendor sub-option)**: obscure, low value.
- **`wlan.fcs.bad_checksum`**: would need CRC32 verification of the 802.11 frame against a
  trailing captured FCS, plus knowing whether the driver even appends the real FCS bytes —
  same "subtly-wrong enum" risk class as `tcp.checksum.status`, skipped for the same reason.
- **`wlan.tag`, `wlan.country_info.fnm`**: `wlan.tag` is inherently multi-valued (a frame
  can carry many information elements, this column implies just one); `country_info.fnm`'s
  exact Wireshark semantics weren't clear enough to implement with confidence rather than
  guess.
- **`wlan.rsn.capabilities.mfpc`, `wlan_radio.duration`/`.end_tsf`/`.start_tsf`,
  `radiotap.timestamp.ts`, `radiotap.vendor_oui`**: RSN capabilities needs walking a
  variable-length cipher/AKM-suite list before reaching the fixed 2-byte capabilities field;
  the `wlan_radio` TSF/duration fields and RadioTap's newer Timestamp field are
  derived/compound values scapy doesn't expose cleanly. Real effort for low-traffic fields.
- **mDNS query vs. response** (2 of 3 `mdns_*` buckets): `mdns.present` is still pure
  port-based (5353); doesn't parse the payload to distinguish query from response the way
  the DNS correlation code does for regular DNS.

## Second pass additions (this update)

Went back through the "not implemented" list above and added everything with high enough
confidence to ship: `capture.py` went **112 → 134** raw columns.

- **`ip.version` bug fix**: only ever checked the IPv4 `IP` layer — any IPv6 traffic in a
  real capture silently got `-1` instead of `6`. `params.md`'s `ip.version_6` bucket implies
  IPv6 was present in training, so this was a real gap. One-line fix: also check `IPv6`.
- **`wlan.fc.frag/.order/.moredata/.pwrmgt`** (4 new) — same `FCfield` bitmask pattern as
  the pre-existing `retry`/`protected` extraction.
- **Bug fix, found via testing**: that `FCfield` extraction was gated on
  `isinstance(fc, int)`, but after a *real* wire dissection scapy represents `FCfield` as a
  `FlagValue` object, not a plain `int` — so that check has been `False` for every real
  captured packet, meaning **`wlan.fc.retry`/`wlan.fc.protected` likely never actually
  populated on a live capture**, only in code I could construct directly in a test. Fixed by
  converting with `int()` instead of an `isinstance` guard, and verified with a synthetic
  packet built the same way a real driver would produce one (construct → serialize to bytes
  → re-dissect, not just constructed-and-read-directly).
- **`wlan.fixed.timestamp`, `.beacon`, `.capabilities.ess`, `.capabilities.ibss`** (4 new) —
  from `Dot11Beacon`/`Dot11ProbeResp`.
- **`wlan.fixed.reason_code`** (1 new) — from `Dot11Deauth`/`Dot11Disas`.
- **`radiotap.length`, `.mactime`, `.channel.flags.cck`, `.channel.flags.ofdm`** (4 new) —
  direct RadioTap fields/flags.
- **`wlan_radio.frequency`, `.data_rate`** (2 new) — Wireshark's names for values RadioTap
  already exposes under different names (`ChannelFrequency`, `Rate` — confirmed `Rate` is
  already Mbps-scaled by scapy, not raw 500 kbps units, so no conversion needed); duplicated
  under both names rather than re-derived.
- **`wlan_radio.channel`** (1 new) — standard frequency→channel mapping (2.4/5/6 GHz bands),
  `MISSING` outside known ranges rather than guessing.
- **SMB v1 — 5 columns**: `smb.mid`, `smb.tid`, `smb.pid.high`, `smb.nt_status`,
  `smb.server_component` — literal fixed-offset reads from the 32-byte MS-CIFS header, no
  bit-flag interpretation needed (unlike the 7 still skipped above).
- **`arp.description`** (1 new) — supports the 5 `arp_Address Resolution Protocol (...)`
  one-hot buckets I'd previously written off as needing stored IP addresses. They don't: the
  request/reply/probe/announcement/gratuitous distinction is computed by comparing sender vs.
  target protocol address *in memory, during extraction*, and only the resulting label is
  ever written to the row — the IPs themselves never become a column, so this doesn't
  actually conflict with the project's identifier-exclusion rule the way I first assumed.

All verified with synthetic-packet unit tests built the realistic way (serialize → re-dissect
from wire bytes, not construct-and-read), plus a full simulate-mode integration run.
`generate_mock_row` now covers deauth and smb1 "kinds" too.

Full per-column reasoning from the first pass is still broadly accurate for what remains; a
`params_coverage.csv` still hasn't been generated (referenced by an earlier version of this
report but never actually committed — happy to generate it now if useful).

## Third pass additions

The remaining `wlan_radio.*`/`radiotap.*` fields from the "still not implemented" list,
requested directly: `wlan.fc.ds`, `radiotap.timestamp.ts`, `wlan_radio.duration`,
`wlan_radio.start_tsf`/`.end_tsf`/`.timestamp`, `radiotap.present.tsft`. `capture.py`:
134 → **141** columns.

- **`wlan.fc.ds`** — Wireshark packs `to_DS`/`from_DS` (`FCfield` bits 0x01/0x02, already
  adjacent) into one 2-bit value. Same pattern as the other `FCfield` bits, `fc & 0x03`.
- **`radiotap.present.tsft`** — direct read of the TSFT bit out of RadioTap's `present`
  bitmask (scapy exposes it as `present.TSFT`, boolean-like).
- **`radiotap.timestamp.ts`** — scapy actually has two *separate* radiotap fields here:
  the legacy `mac_timestamp` (TSFT, already captured as `radiotap.mactime`) and a newer,
  distinct "Timestamp" field with its own presence bit (`present.timestamp`), which scapy
  exposes as a plain field once you know to look. Verified with a synthetic packet that both
  populate independently and don't get confused with each other. In practice: your adapter's
  driver only ever emits the legacy TSFT one (see the real-capture check below) — this field
  is there for drivers that emit the newer one instead.
- **`wlan_radio.timestamp`, `wlan_radio.start_tsf`** — both are Wireshark's names for the
  same TSFT reading `radiotap.mactime` already captures; duplicated under these names rather
  than re-derived, same pattern as `wlan_radio.frequency`/`.data_rate`.
- **`wlan_radio.duration`, `wlan_radio.end_tsf`** — the one genuinely hard field in this
  batch. Wireshark computes this as the PPDU's actual airtime, and the formula is
  PHY-mode-dependent (DSSS/CCK, OFDM, HT, VHT, HE all differ). Implemented the published
  IEEE 802.11 TXTIME formula for the two **legacy** PHY modes only:
  - DSSS/CCK (1/2/5.5/11 Mbps): 192 µs preamble+PLCP-header (96 µs if short preamble —
    not applicable at 1 Mbps) + `ceil(bits / rate)` for the payload.
  - OFDM (6–54 Mbps): 16 µs training + 4 µs SIGNAL symbol + `4 µs × ceil((16 + 8×len + 6) /
    (rate×4))` for the data symbols.

  Deliberately returns `MISSING` for HT/VHT/HE (802.11n/ac/ax MCS rates) or any
  unrecognized rate rather than guessing — those use different, spatial-stream- and
  guard-interval-dependent formulas this pass didn't implement. `end_tsf = start_tsf +
  duration`, so it inherits the same legacy-only scope.

  No `tshark`/Wireshark is installed in this environment, so this couldn't be
  cross-validated against real ground truth. Instead, verified the *arithmetic* is right:
  hand-computed reference values for a few rate/length combinations (e.g. 1500 bytes @ 54
  Mbps OFDM → 244 µs; 1500 bytes @ 11 Mbps DSSS long-preamble → 1283 µs) and asserted the
  code matches. The formula itself is the standard published TXTIME calculation, not
  something I derived — but "formula is textbook-correct" and "matches Wireshark's exact
  dissector output" aren't the same claim; treat this one field as a well-reasoned
  approximation, not a verified match, until it's checked against real Wireshark output.

  One more approximation stacked on top: the formula needs the actual over-the-air frame
  length, which isn't quite `frame.len` (that includes the RadioTap prefix). Used
  `len(bytes(pkt[Dot11])) + 4`, assuming a standard 4-byte FCS trailer that scapy doesn't
  actually capture but which the real frame carries in the air.

**Checked against the real capture from earlier in this conversation**: your adapter's
driver only emits the legacy TSFT field (never the newer `timestamp` one), and every rate
seen (1.0, 6.0, 12.0 Mbps) falls in the legacy DSSS/OFDM set this formula covers — so on
your actual hardware, none of these new fields would come back `MISSING` due to PHY-mode
gaps. `wlan.fc.ds` would show `0` on essentially every frame in that capture, since it was
almost entirely beacons/management frames (which don't set to_DS/from_DS) — that's expected,
not a sign something's broken.

## Fourth pass additions

`wlan.tag`, `wlan.rsn.capabilities.mfpc`, the `dhcp`/`dns`/`mdns` description strings, 3 SMBv1
Flags/Flags2 bits + the 3 GENERIC_* ACCESS_MASK bits, `icmpv6.mldr.nb_mcast_records`, and
`tcp.checksum.status`, all requested directly. `capture.py`: 141 → **154** columns.

**First, a clarification on the `arp`/`dhcp`/`dns`/`mdns`/`nbns`/`ldap`/`llc`/`ssdp` "raw
summary string" ask**: these map to columns like `dns_Domain Name System (query)` and
`arp_Address Resolution Protocol (request)` in params.md — Wireshark's human-readable
protocol/message description, one-hot-bucketed per distinct string observed in training. Of
the 8 protocols asked about:
- **`arp`**: already fully covered — `arp.description` (added two passes ago) *is* this raw
  field, computing exactly "request"/"reply"/"ARP Probe"/"ARP Announcement"/"reply/gratuitous
  ARP".
- **`nbns`, `ldap`, `llc`, `ssdp`**: nothing to add. params.md itself says these collapsed to
  a *single* one-hot column each in training (`nbns_nbns`, `ldap_ldap`, etc.) — meaning every
  observed frame of that protocol got the exact same one description string. A presence flag
  (`nbns.present`, etc., already captured) is a complete raw equivalent of a column with only
  one possible value; there's no finer-grained raw field to extract.
- **`dhcp`, `dns`, `mdns`**: these genuinely needed new code — added this pass, see below.

- **`wlan.tag`**: a frame can carry many information elements (SSID, rates, RSN, vendor tags,
  ...), each with its own tag number, so this can't be a single scalar the way most fields
  here are. Went with every tag ID seen in the frame, comma-joined in order (e.g.
  `"0,1,48,221"`) — the same convention tshark itself uses when a repeating field is exported
  to one CSV column. Verified against a synthetic beacon carrying 3 elements.
- **`wlan.rsn.capabilities.mfpc`**: bit 0x0080 of the RSN element's (tag 48) Capabilities
  field — reached by walking past its two variable-length suite lists first (pairwise cipher
  suites, then AKM suites, both counted by a 2-byte count field immediately before them).
  Verified against synthetic RSN elements with both 1 and multiple suites per list.
- **`dhcp.description`**: formatted as `"Dynamic Host Configuration Protocol (<Type>)"` from
  the DHCP message-type option, using scapy's own `DHCPTypes` name table. Capitalization
  convention (`ACK`/`NAK` uppercase, everything else Title Case) was reverse-engineered from
  the two examples actually visible in params.md's own column names (`(ACK)`, `(Request)`) —
  confident about those two, reasonably confident about the rest by the same pattern.
- **`dns.description` / `mdns.description`**: `"Domain Name System (query/response)"`,
  trivially derived from `dns.flags.response` (already captured) — mDNS is the identical wire
  format, just gated on UDP port 5353 instead of 53 rather than needing separate parsing.
- **`smb.flags.response`** (Flags bit 0x80, MS-CIFS 2.2.3.1 `SMB_FLAGS_REPLY`),
  **`smb.flags2.sec_sig`** (Flags2 bit 0x0004, `SMB_FLAGS2_SECURITY_SIGNATURE`),
  **`smb.flags2.nt_error`** (Flags2 bit 0x4000, `SMB_FLAGS2_NT_STATUS`) — all three are
  well-documented, unambiguous bits I'm confident about (unlike `smb.flags.notify`, still not
  implemented — I couldn't find its bit position with the same confidence and won't guess).
- **`smb.access.generic_read/write/execute`**: `GENERIC_READ`/`WRITE`/`EXECUTE` (bits
  0x80000000/0x40000000/0x20000000 of a Windows `ACCESS_MASK`, MS-DTYP 2.4.3 — very standard,
  same layout everywhere from NTFS ACLs to SMB) out of the `DesiredAccess` field in an
  `NT_CREATE_ANDX` (command 0xA2) *request* body specifically — the one SMB1 command where
  this field appears at all. Added a safety check this class of field didn't have before:
  `NT_CREATE_ANDX`'s WordCount is always 24 by spec, so a mismatch means "not actually this
  command's body shape" and the code backs off rather than trusting a wrong offset.
- **`icmpv6.mldr.nb_mcast_records`**: turned out easier than expected — scapy has a real
  dissector for MLDv2 Report (`ICMPv6MLReport2`) with this field modeled directly
  (`records_number`), no hand-parsing needed. Verified with a synthetic report carrying 3
  multicast address records.
- **`tcp.checksum.status`**: the one I'd previously skipped over enum-semantics risk. Instead
  of guessing Wireshark's internal numeric Good/Bad/Unverified encoding, this actually
  recomputes the checksum (delete it from a copy, rebuild so scapy fills in a fresh one,
  re-parse to read it back out) and compares — outputting a plain `"Good"`/`"Bad"` string.
  Verified both directions: a correctly-checksummed packet reads `"Good"`, and a packet with
  the checksum bit-flipped reads `"Bad"`. Re-examined the NIC-checksum-offload concern that
  drove the earlier skip: it mostly doesn't apply here, since this is a monitor-mode capture
  of *other* stations' complete over-the-air frames, not the local machine's own outgoing
  traffic pre-hardware-checksum — what's captured is what was genuinely transmitted.

All verified with synthetic-packet unit tests (including a construction mistake I caught in
my *own test* rather than the code — an early RSN test packet omitted the required
`Dot11Beacon` fixed-parameters layer between `Dot11` and the element chain, which silently
misaligned everything scapy dissected after it; fixed the test, not `capture.py`) plus a full
simulate-mode integration run. `generate_mock_row` now covers `mdns`/`icmpv6mldr` kinds too.

## Fifth pass additions

`http.response.code.desc` and `ssdp.description`, asked about directly. `capture.py`:
154 → **155** columns.

- **`http.response.code.desc`**: turned out trivial — scapy's `HTTPResponse` layer already
  models this as `Reason_Phrase`, a field I'd simply never read. One-line addition.
- **`ssdp.description`**: same answer as `nbns`/`ldap`/`llc` from the fourth pass — params.md
  itself says `ssdp_ssdp` collapsed to one value in training, so `ssdp.present` (already
  captured) is a complete raw equivalent. Nothing new to add for this exact field.

  Digging into *why* pointed at something worth fixing anyway, though. params.md's `http`
  field group has one-hot buckets for `M-SEARCH`, `NOTIFY`, `SUBSCRIBE`, `UNSUBSCRIBE` (plus
  odd combo values like `GET-M-SEARCH`) — those are SSDP/UPnP methods, not real HTTP, which
  only makes sense if whatever generated the training data used a heuristic HTTP dissector
  that also fires on SSDP's HTTP-like text syntax over UDP port 1900 (Wireshark's own HTTP
  dissector does exactly this). `capture.py`'s HTTP extraction, though, only ever checked
  `pkt.haslayer(HTTPRequest)` — and scapy's `HTTPRequest`/`HTTPResponse` classes are bound to
  TCP only. Confirmed with a synthetic packet: an M-SEARCH message wrapped in UDP dissects as
  opaque `Raw`, never `HTTPRequest`. **This meant every one of those SSDP method buckets, and
  `http.response.code`/`.code.desc` for SSDP responses, had zero raw data captured, ever** —
  not something either of the previous "not implemented" lists had flagged, since the gap is
  in *how* `http.request.method` gets populated, not a missing column.

  Fixed by hand-parsing the first line of any UDP/1900 payload (same pattern as the other
  hand-rolled parsers in this file): `"M-SEARCH * HTTP/1.1"` → `http.request.method` =
  `"M-SEARCH"`, `http.request.version` = `"HTTP/1.1"`; `"HTTP/1.1 200 OK"` → `http.response.
  code` = `"200"`, `.code.desc` = `"OK"`, `.version` = `"HTTP/1.1"`. Deliberately writes into
  the *same* `http.*` columns real TCP HTTP traffic uses, matching how the training schema
  itself names these fields — there's no separate `ssdp.request.method` field in params.md.
  Verified against synthetic M-SEARCH, NOTIFY, and response messages.

## Sixth pass: LLC/SNAP dispatch (opt-in, not the default)

A colleague's code review flagged this: `llc.present` correctly detects unencrypted 802.11
Data frames (66/67 in their latest capture file), but the code never walked into the LLC/SNAP
header's Type field to hand the payload off to IP/ARP/EAPOL parsing. Their fix was already
fully specified — read the MAC header length, the 8-byte LLC/SNAP header, and dispatch by
EtherType. Implemented close to verbatim, generalized a bit (see below), as **`capture.py`'s
`extract_fields(..., llc_snap_dispatch=False)`** — off by default, since I couldn't verify it
against the real capture that motivated it. The app now has a "Field extraction" dropdown
(Original / LLC/SNAP dispatch) so both can be run against the same traffic and compared.

**What it does**: for an unencrypted (`wlan.fc.protected != 1`) 802.11 Data frame where scapy's
own dissection hasn't already found IP/ARP/EAPOL, reads the MAC header length off the frame's
own type/subtype/to-DS/from-DS/QoS bits (24 bytes plain, 26 QoS, 30 four-address/WDS, 32
QoS+WDS — bails rather than guess if an HT Control field might also be present), checks the
next 8 bytes are standard SNAP (`DSAP=SSAP=0xAA, Control=0x03, OUI=00:00:00` — a non-standard
OUI is left alone rather than assumed to mean the same thing IP-over-Ethernet's 0x0800 does),
and re-dissects everything after that into a fresh `IP`/`ARP`/`EAPOL` packet by EtherType
(also added `IPv6`/`0x86DD`, not in the original spec, for consistency with the IPv6 support
added earlier this session). Every "app-layer" extraction block downstream (TCP through TLS)
then runs against whichever packet succeeded — same code, decoded payload — with the
wlan.\*/radiotap.\* extraction entirely unaffected either way.

**Honesty about what I could and couldn't verify**: the byte-offset arithmetic and EtherType
dispatch are unit-tested and correct — built a synthetic LLC/SNAP/IP/TCP frame, deliberately
forced it into the same "scapy didn't auto-dissect" shape (a `Raw` payload after `Dot11`
instead of a properly-typed `LLC`/`SNAP`/`IP` chain), and confirmed `llc_snap_dispatch=True`
correctly recovers `ip.version`/`tcp.flags.syn`/etc. while `llc_snap_dispatch=False` (default)
leaves them exactly as before — a real regression check, not just a new-code check. Also
confirmed no interference when scapy's own dissection *does* already succeed, and that an
encrypted frame's payload is correctly left alone regardless of what it happens to look like.

**What I could *not* do**: reproduce a case where scapy's own automatic dissection actually
*fails* to walk LLC→SNAP→IP for a standard, well-formed frame. Every construction I tried —
plain Data (subtype 0), QoS Data (subtype 8, via the `Dot11QoS` field scapy inserts
automatically), even a non-zero vendor OUI — dissected correctly once round-tripped through
real wire bytes (`Dot11(bytes(pkt))`), which is exactly how a live capture's packets are
built. That means either (a) whatever caused the gap in the real capture is something more
specific to those particular frames that I can't see without the actual pcap (a non-standard
OUI, an FCS-trailer quirk, or — matching an observation from earlier in this session — the
specific 66/67 frames genuinely carrying no further payload at all, e.g. null/keep-alive
frames, in which case there's nothing to dispatch to regardless), or (b) this is a valid
defensive backstop for a gap that doesn't reproduce syntheically. Either way: **run both
options against the same real capture and compare the two CSVs** — that's the fastest way to
find out which explanation is right, and exactly why this landed as a toggle instead of
replacing the default behavior outright.

**Not attempted — decryption**: intentionally left alone this pass, per your own message —
you don't yet have answers to the two questions that determine the actual scope of work (the
key-acquisition mechanism, and whether this tool wraps tshark/pyshark vs. reads raw
radiotap/802.11 bytes directly), and guessing at that again after the WPA2-Enterprise mixup
isn't worth repeating. Once those are answered, happy to help implement whichever path they
point to — pointing `pyshark`/`tshark` at a keys file is a config change; hand-rolling WPA2
CCMP (AES-CCM keyed off derived PTKs) is a real implementation project.
