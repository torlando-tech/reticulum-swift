# reticulum-swift port deviations

All logic in this swift port mirrors `../Reticulum/RNS/` (python reference).
Any deviation from the python reference must be documented here with the
file:line, the python reference site, and the reason.

## Active deviations

### Tunnel-synthesize handler dispatched synchronously on the transport actor

**Sites:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` —
`handleRegularData(_:from:)` (the `tunnelSynthesizeDestination` intercept) and
`Sources/ReticulumSwift/Transport/ReticulumTransport+Tunnels.swift`
(`tunnelSynthesizeHandler`, `handleTunnel`).

**Python reference:** `RNS/Transport.py:247-250` (the `tunnel_synthesize`
destination is registered with `set_packet_callback(tunnel_synthesize_handler)`),
`:2306-2327` (`tunnel_synthesize_handler`), `:2336-2345` (`handle_tunnel`).

**Reason:** Category (a) — concurrency model. RNS is single-threaded: `inbound`
delivers a PLAIN packet to the destination's packet callback and the callback
(`tunnel_synthesize_handler` → `handle_tunnel`) runs to completion *inside*
`inbound`, so `Transport.tunnels` is populated by the time `inbound` returns.
reticulum-swift's `DestinationCallbackManager` callback is a synchronous
`(Data, Packet) -> Void` closure that cannot mutate the `ReticulumTransport`
actor's state without hopping to it via a detached `Task`, which would race a
`read_tunnels` that immediately follows `inbound()`. To preserve RNS's
run-to-completion semantics the swift port intercepts the tunnel-synthesize
control-destination packet directly in `handleRegularData` (already on the
transport actor) and calls the handler synchronously, instead of routing it
through the async callback path. The validate/establish logic, the 176-byte
exact-length gate, the `full_hash(public_key||interface_hash)` tunnel-id
derivation, and the receiving-interface binding are byte-for-byte the reference;
only the dispatch mechanism differs. No wire bytes change.

### Transport announce-retransmit phase anchor (`announces_last_checked`)

**Sites:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` —
`startRetransmissionLoop()` (`announcesLastChecked` back-dated anchor) and
`processAnnounceRetransmissions(force:)` (the `ANNOUNCES_CHECK_INTERVAL` gate).

**Python reference:** `RNS/Transport.py:181` (`announces_last_checked = 0.0`),
`:574`/`:636` (the announce-retransmit branch runs at most once per
`announces_check_interval = 1.0`s and unconditionally re-stamps
`announces_last_checked` after each sweep), `:500-503` (`jobloop`).

**Reason:** Category (a) — runtime model. RNS's `Transport` is a process-wide
singleton, so `announces_last_checked` is global and persists for the whole
process; the once-per-second announce sweep is therefore phased arbitrarily
relative to any individual heard announce, and the reference's own behavioral
`test_announce_rebroadcast_wire_format` (which sleeps exactly 1.0s then drains)
is correspondingly phase-fragile — it fails the reference in isolation and in a
full `tests/behavioral/` run, passing only when prior tests happen to align the
global phase. reticulum-swift instead constructs a FRESH `ReticulumTransport`
per conformance behavioral handle, so the phase would re-anchor every test and
deterministically race the sweep against the test's drain. The gate value
(1.0s) and steady-state cadence match RNS exactly; the only deviation is that
the per-transport anchor is back-dated so the FIRST sweep lands ~0.75s after
start — inside a forwarded announce's `[0, PATHFINDER_RW=0.5]`s due window plus
margin, before a 1.0s rebroadcast drain, and after the sub-0.5s drain windows of
the last-hop / forwarding tests. This makes the swift behavior deterministic
where RNS is luck-of-phase; it changes no wire bytes and no steady-state timing.

### ConformanceBridge `crypto_provider_op` — single crypto provider

**Sites:** `Sources/ConformanceBridge/Ext+Crypto.swift` — `handleCryptoExtCommand`,
`crypto_provider_op` case.

**Python reference:** `reticulum-conformance/reference/bridge_server.py`
`cmd_crypto_provider_op` — drives a primitive through a *named* RNS crypto backend
(`PROVIDER_INTERNAL` pure-Python vs `PROVIDER_PYCA` OpenSSL), which RNS selects at
import time, to assert the two backends are byte-identical on the wire.

**Reason:** Category (a) — language/runtime. reticulum-swift has a *single* crypto
provider (CryptoKit + CryptoSwift); there is no second backend to switch to. The
bridge command accepts and validates the `provider` arg (`internal`/`pyca`) for
API parity but maps both onto the same implementation. The conformance test only
asserts the two providers produce identical output against fixed NIST/RFC vectors,
which a single shared implementation satisfies trivially. No protocol bytes differ.

### ConformanceBridge `config_parse_interface` — focused `_synthesize_interface` port

**Sites:** `Sources/ReticulumSwift/Interfaces/InterfaceConfigSynthesizer.swift`
(`ConfigParser`, `InterfaceConfigSynthesizer`); driven by
`Sources/ConformanceBridge/Ext+Interface.swift` — `config_parse_interface` case.

**Python reference:** `RNS/Reticulum.py:685-1034` (`Reticulum._synthesize_interface`)
plus `RNS.vendor.configobj.ConfigObj`, exercised by
`reticulum-conformance/reference/bridge_server.py` `cmd_config_parse_interface`
over the no-op `ConfigParseProbeInterface` (`DEFAULT_IFAC_SIZE = 16`,
`AUTOCONFIGURE_MTU = False`, seed `bitrate = 62500`).

**Reason:** Category (a) — scope. reticulum-swift has no ConfigObj INI parser and
no full `_synthesize_interface` (its `InterfaceConfig` is a Codable struct, not an
INI pipeline). The port reproduces the config-derived RULES under conformance
*exactly* against the reference site — interface_mode alias selection + precedence
(incl. the upstream `c["mode"]` KeyError quirk at Reticulum.py:701), the
discoverable->gateway/AP forcing, the bitrate/announce_cap/ifac_size bound checks,
the discovery announce-interval floor/default, the ic_* ingress-control knobs, and
IFAC networkname/passphrase credential resolution. It deliberately does NOT model
the full interface-class dispatch (Reticulum.py:928-996) or
`Transport.add_interface`/`final_init`; instead it hardcodes the probe interface's
class constants (`DEFAULT_IFAC_SIZE == 16`, seed bitrate 62500, no
AUTOCONFIGURE_MTU re-size), which is the exact interface the reference command
synthesizes onto — so the read-back attributes match RNS byte-for-byte for the
keys under test. No protocol bytes differ; values outside the probe's constants
(other interface types) are out of scope for this command.

### `ReticulumTransport.onInterfacePeerSpawned` / `onInterfaceConnected` (new feature)

**Sites:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` —
`onInterfacePeerSpawned`, `onInterfaceConnected`, and their setters
`setOnInterfacePeerSpawned` / `setOnInterfaceConnected`.

**Python reference:** No equivalent. Python `RNS.Transport` has no app-layer
hook for "an interface was added" or "an interface reached connected." The
upstream pattern is for app code to inspect `RNS.Transport.interfaces`
directly or to register destinations and let the transport layer handle
discovery. Swift needs these hooks because the iOS app (Columba) has
lifecycle-driven UI state and per-interface announce policy that depends
on knowing precisely *when* an interface flips, distinguished by the
*kind* of trigger (peer-spawn on AutoInterface/BLE/MPC vs. state-change
on TCP/RNode/static).

**Reason:** Category (b) — new feature for the swift app surface. The
older single `onInterfaceAdded` callback (now wired as a deprecated shim)
fired from both kinds of trigger indistinguishably; the iOS app needs to
gate them independently behind separate user-facing settings
(`auto_announce_on_peer_spawned` vs `auto_announce_on_tcp_reconnect`).

### `ReticulumTransport.getInterfaceSnapshots` — status introspection (new feature)

**Sites:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` —
`getInterfaceSnapshots()` returning `[InterfaceSnapshot]`; forwards
`lastErrorDescription` from `TCPInterface` and (added) `RNodeInterface`.

**Python reference:** No equivalent. Python `RNS.Transport` has no
status-snapshot API and no per-interface `lastErrorDescription`; app code
inspects `RNS.Transport.interfaces` and the interface objects directly.

**Reason:** Category (b) — new feature for the swift app surface. The iOS app
(Columba) reads interface status across the app↔NetworkExtension process
boundary (IPC) to drive the Settings connection badges, and needs an actionable
failure reason per interface. `lastErrorDescription` forwarding was already
wired for `TCPInterface`; extended to `RNodeInterface` so a Model-B RNode
surfaces reasons like "Invalid configuration — TX power may exceed device
limits" instead of a bare offline flag.

### `TCPInterface.beginTunnelMode(send:)` / `endTunnelMode()` — VPN-extension hook (new feature)

**Sites:** `Sources/ReticulumSwift/Interfaces/TCPInterface.swift` —
`beginTunnelMode`, `endTunnelMode`, and the matching pair on
`Sources/ReticulumSwift/Interfaces/Auto/AutoInterface.swift`.

**Python reference:** No equivalent. Python's
`RNS.Interfaces.TCPInterface` owns its socket directly with no notion of
an outbound-write hook. The swift port needs this hook because iOS app
extensions (`NEPacketTunnelProvider`) run in a separate process and own
the authoritative network socket while the main app is suspended /
backgrounded. When the extension is active, the main-process
TCPInterface must tear down its own NWConnection and route outbound
bytes through the extension's IPC instead. Python doesn't have an
analogous process-split constraint — its Transport runs in one process
and that process keeps running.

**Reason:** Category (b) — new feature for the iOS port to support
background-mode delivery via Network Extension. No python-side analog
is meaningful.

**Sub-deviation (`endTunnelMode()` idempotency, fix/end-tunnel-mode-idempotent
2026-05-11):** `endTunnelMode()` now early-returns when `outboundHook ==
nil` instead of unconditionally tearing down and re-creating the
transport. The previous unconditional path was destructive when called
on an interface that was never in tunnel mode (e.g. the iOS VPN status
machinery emits a `.invalid` notification on every cold start regardless
of whether the user has enabled the tunnel; the downstream caller —
Columba-iOS `AppServices.applyTunnelModeToInterfaces` — would observe
this `.invalid` and fire `endTunnelMode()` on every TCPInterface,
killing every live NWConnection seconds after the Step 7 loop brought
them up). The downstream `isTunnelModeActive` workaround in Columba-iOS
exists specifically because this method wasn't idempotent; pinning the
contract here is the correct fix and lets the workaround be deleted on
the next Columba-iOS deps bump.

### Resource corrupt-assembly handling — `.failed` mapping + deferred bz2-overflow teardown (fix/resource-completion-cleanup 2026-06-02)

**Sites:** `Sources/ReticulumSwift/Link/Link.swift` — `handleResourceData`
assembly catch + `close()` resource teardown; `Sources/ReticulumSwift/Resource/Resource.swift`
— `cleanup()`.

**Python reference:** `RNS/Resource.py` `assemble()` (`:672-749`) + `cancel()`
(`:1071-1104`); `RNS/Link.py` `link_closed()` (`:724-726`).

**Behavior (faithful):** an inbound assembly that hits a hash-mismatch (`:715`),
decrypt error, or any exception (`:721`) leaves the resource non-COMPLETE and falls
through to `link.resource_concluded(self)` (`:723`) — the swift port drops it from
`inboundResources` and fires `resourceConcluded` (which the LXMF handler ignores for a
non-`.complete` resource, matching `LXMRouter.py:1878`). No packet is sent and the link
is NOT torn down. `Link.close()` cancels in-flight resources (mirrors `link_closed`
`:724-726`) without emitting `RESOURCE_ICL`, because the link is no longer ACTIVE
(`Resource.py:1088-1092` gates the cancel packet on `link.status == ACTIVE`). The prior
swift `catch` only logged, leaking the resource in `.assembling` with the callback never
fired — that leak is what this fixes.

**Two structural notes (not behavioral divergences from the common corrupt path):**
1. `ResourceState` has no `CORRUPT` case (pre-existing); the corrupt-assembly path maps
   to the terminal `.failed`. Observably identical: non-COMPLETE ⇒ not delivered,
   concluded, removed.
2. python's bz2 *max-decompressed-size* bound (`Resource.py:687`,
   `max_length = max_decompressed_size = AUTO_COMPRESS_MAX_SIZE`) is now enforced:
   `ResourceCompression.decompress` / `bz2Decompress` cap the output buffer at
   `AUTO_COMPRESS_MAX_SIZE` (64 MB) and throw `BZ2Error.exceedsMaxDecompressedSize`
   on overflow, so an over-compressible ("bz2 bomb") payload can't exhaust memory
   (`assemble()` passes the advertised size as the buffer hint). **Now wired
   (2026-06-14):** python's overflow *response* additionally `reject()`s
   (RESOURCE_RCL) and tears the link down (the CORRUPT branch of `cancel()`,
   `Resource.py:688-692` → `:1081-1084`). `assemble()` distinguishes this case as
   `corruptReason == .decompressionOverflow`, and `handleResourceData`'s assembly
   catch now routes it through `cancelIncomingResource(_:corrupt:true)` (RESOURCE_RCL
   reject + `close()` teardown) rather than the ordinary drop+conclude path — matching
   RNS. It does NOT call `resourceConcluded` (python returns before
   `Resource.py:723`, so no last-window is recorded). The ordinary per-segment
   hash-mismatch / decrypt corrupt case (`corruptReason == .hashMismatch`,
   `Resource.py:715/721`) still takes the quiet drop+conclude path above.

### Resource SEGMENTATION — disk-streaming port (perf/resource-disk-streaming 2026-06-02)

**Sites:** `Sources/ReticulumSwift/Resource/Resource.swift` — segmentation
members, outbound segment init, `prepare()` + `resolveSegmentPlaintext()`,
`stageInputFile()`/`openInputHandle()`, `getAdvertisement()`,
`prepareNextSegment()` / `transferInputFileOwnership()` / `adoptInputFile()`,
`assemble()` + `appendToStorage()`/`storageURL()`, `cleanup(abandonChain:)`;
`Sources/ReticulumSwift/Resource/ResourceAdvertisement.swift` —
`create(... originalHash: ...)`; `Sources/ReticulumSwift/Link/Link.swift` —
`handleResourceProof` + `advertiseNextSegment`, `handleResourceData`
segment-aware completion, cancel/reject/close cleanup calls.

**Python reference:** `RNS/Resource.py` `__init__` staging (`:273-314`),
`total_segments`/seek/read (`:285-313`), bytes→tempfile copy (`:274-279`),
metadata prefix (`:266`, prepend `:331-333`), `assemble` (`:672-749`, append to
storagepath `:708-710`, per-segment hash check `:694-695`, metadata strip
`:696-704`, final-segment surface+unlink `:725-747`), `prove` (`:752-763`),
`__prepare_next_segment` (`:765-780`) + its `advertise()` trigger (`:516-518`),
`validate_proof` segment continuation (`:782-821`), `ResourceAdvertisement`
fields (`:1281-1307`, `pack(segment=0)` `:1333-1339`), storagepath naming
(`:199`).

**Behavior (faithful):** data with `metadata_size + len(data) >
MAX_EFFICIENT_SIZE` (1 MiB-1) is staged to a tempfile and split into a chain of
`ceil(total_size / MAX_EFFICIENT_SIZE)` segments, each an independent `Resource`
reading its plaintext chunk via seek/read from the shared input file (segment 1
reads `MAX_EFFICIENT_SIZE - metadata_size`, later segments read
`MAX_EFFICIENT_SIZE` from `first_read_size + (seek_index-1)*MAX_EFFICIENT_SIZE`).
Each segment independently compresses/encrypts/hashes its chunk; the
advertisement carries `i`=segment_index, `l`=total_segments, `o`=first-segment
hash, `d`=total chain plaintext size, `s`/`x` flags. After a segment's proof
validates, the next segment is prepared and advertised (re-keyed in
`outboundResources` by its own hash). Inbound: each segment decrypts, validates
`full_hash(plaintext+random_hash)==hash`, strips the metadata prefix on segment
1, and APPENDS plaintext to a per-resource storagepath; the chain concludes
(delivery + callback + unlink) only when `segment_index == total_segments`.
Data <= MAX_EFFICIENT_SIZE keeps the single in-RAM segment path
(`total_segments=1`, no tempfile) — no behavior change for small resources.

**Deviations (category a — runtime/structural — and the noted new feature):**
1. **Temp-file location.** Python uses `tempfile.TemporaryFile()` for the
   outbound stage (`:277`) and `RNS.Reticulum.resourcepath + "/" +
   original_hash.hex()` for the inbound storagepath (`:199`). This port has no
   `resourcepath`; both live under `NSTemporaryDirectory()` (per-extension
   private, sandbox-valid — already the pattern at `Link.swift:27`). OUTBOUND
   staging is named `rns_resource_out_<uuid>` (a single Resource owns it; the
   resource hash isn't known until after hashing). INBOUND storagepath is named
   `rns_resource_in_<original_hash hex>` — DETERMINISTIC, no uuid, because each
   inbound segment is a fresh `Resource` (one accepted advertisement per
   segment) and they must all `open(...,"ab")`-append to the SAME file; a
   per-instance uuid would break cross-segment append. This matches python's
   hash-keyed storagepath exactly.
2. **Staging deferred to `prepare()`.** Python decides staging in `__init__`
   (`:273-314`). This port defers it to `prepare()` because staging needs the
   part size + metadata size, which the swift port resolves at prepare-time, and
   because the public `Resource(data:link:)` init is non-throwing/sync. Observable
   wire output is identical.
3. **Async next-segment preparation.** Python prepares the next segment on a
   daemon thread (`__prepare_next_segment` via `threading.Thread`, `:517/768`)
   and `validate_proof` busy-waits `while self.next_segment == None`
   (`:811`). This port prepares it in an `async` call inside
   `advertiseNextSegment` (actor-model equivalent); the next segment is never
   advertised before its preparation completes, same as python.
4. **`linkEncryptClosure` capture.** Python segments call
   `self.link.encrypt(...)` directly (`:427`). The swift `Resource` doesn't reach
   into `Link` for the token, so `prepare()` captures the `linkEncrypt` closure
   and threads it to child segments via the segment initializer. No behavioral
   change.
5. **`assembledFileURL` (category b — new feature).** Python surfaces the
   assembled resource as a file handle (`self.data = open(storagepath,"rb")`,
   `:737`). This port preserves the existing in-RAM `assembledData: Data`
   contract (reads the file back) AND adds `assembledFileURL: URL?` as a forward
   hook so callers can stream large assembled resources from disk. NOTE: the URL
   currently points at the storagepath which `cleanup()` unlinks on conclusion —
   callers wanting the on-disk file must copy it out before the resource
   concludes. A future change can defer the unlink when a file-consuming callback
   is registered (mirroring python's `meta_storagepath`/callback split).
6. **Inbound metadata parsed-and-dropped.** Python writes segment-1 metadata to
   `meta_storagepath` and decodes it for the assembled callback (`:700-702`,
   `:727-735`). This port has no metadata-consuming resource API yet, so the
   receive path parses the 3-byte length + metadata bytes off segment 1 (so the
   stored data stream matches python's `data = self.data[3+metadata_size:]`,
   `:704`) but DROPS the metadata rather than persisting a sidecar. Outbound:
   this port's callers attach no metadata (`metadata` stays empty,
   `metadataSize=0`), so `total_size == data_size` and the `x` flag is unset —
   identical wire output to python invoked without metadata. The receive-side
   parsing exists purely for interop with a metadata-bearing python sender.
7. **`cleanup(abandonChain:)` parameter.** Python unlinks the inbound storagepath
   only after the final-segment callback (`:744`). This port adds an
   `abandonChain` flag so abnormal teardown (corrupt segment, cancel, reject,
   link close) unlinks a PARTIAL storagepath unconditionally to avoid leaking it;
   normal per-segment conclusion still unlinks only on the final segment. No
   wire/behavioral divergence — purely a temp-file lifecycle guard.
8. **Per-segment size guard replaces whole-resource size check.** The prior swift
   `assemble()` asserted `finalData.count == originalSize`. With segmentation,
   `originalSize`/`d` is the WHOLE chain plaintext size, not a single segment's,
   so that check is replaced by python's per-segment integrity check
   (`full_hash(plaintext+random_hash)==hash`, `:694-695`) — strictly more
   faithful. The encrypted-side `assembled.count == transferSize` check is
   retained (transferSize is per-segment `t`).

### `RNodeInterface` host-injectable inner transport (new feature)

**Sites:** `Sources/ReticulumSwift/Interfaces/RNodeInterface.swift` — the
`makeInnerTransport` stored factory + the `transportFactory:` init parameter
(default `{ BLETransport(deviceName: $0) }`), consumed in `setupTransport()`.

**Python reference:** `../Reticulum/RNS/Interfaces/RNodeInterface.py` —
`__init__`/`open_port` select the byte-I/O backend by config and assign it to
`self.serial`: `pyserial.Serial(...)` (`:367`), a BLE adapter `self.serial =
self.ble` (`:392`), or `self.serial = self.tcp` (`:408`). Python picks the
backend internally from configuration.

**Reason:** Category (b) — new feature for the swift host surface. The swift
port already abstracts python's pluggable `self.serial` as the `Transport`
protocol (`BLETransport` ≈ the python `self.ble` path). This change makes that
inner transport *injectable by the host process* instead of always constructing
`BLETransport` internally, so Columba's iOS **Network Extension** can supply an
**App-Group seam transport** — the CoreBluetooth radio runs in the app process
(Model B) while `RNodeInterface` + KISS framing run in the NE. It is the RNode
analogue of `BLEInterface`'s already-injectable `driver`. **No protocol-semantics
change:** KISS framing, RNode command handling, reconnect/backoff, and flow
control are untouched; only the source of the inner byte-transport is injectable.
The default preserves the previous behaviour exactly (`BLETransport` from
`config.host`).

### `RNodeInterface` async reconnect loop — guard against reconnecting a live link

**Sites:** `Sources/ReticulumSwift/Interfaces/RNodeInterface.swift` —
`startReconnectLoop()` (the `reconnectTask` loop, `attemptReconnect`, phase-1/2
waits) and the guard added before `attemptReconnect()`.

**Python reference:** `../Reticulum/RNS/Interfaces/RNodeInterface.py` —
`reconnect_port()`/the reconnect path gated by `self.reconnecting` (`:208`, `:358`
`if not self.detached and not self.reconnecting:`) and `self.online` (`:462`).

**Reason:** Category (a) — language/runtime. Python reconnects from a dedicated
thread (`reconnect_port`), serialized by the `reconnecting` flag; the swift port
expresses this as a single `reconnectTask` (`Task` + `ExponentialBackoff`). The
guard added before `attemptReconnect()` — bail if `state == .connected ||
isConfiguring` — restores python's invariant that a reconnect cycle never tears
down a link that is already up/configuring (python only reconnects from the
read-loop's disconnect/error path, never while `online`). Without it the async
loop could fire its pending `attemptReconnect()` (which builds a fresh transport)
just as `BLETransport` reused an already-connected peripheral and `configureDevice()`
began its firmware-init wait, orphaning the live link mid-detect. No semantic
change vs python; it makes the async port honour the same "don't reconnect a live
link" guarantee.

### BLE data-path liveness probe — per-peer loop + grace-detach reconnect (fix/ble-peer-grace-period-detach 2026-06-10)

**Sites:** `Sources/ReticulumSwift/Interfaces/BLE/BLEPeerInterface.swift` —
`lastRealData`, `probeCapable`, `probeTask`, `handleProbeFrame`, `sendProbe`,
`runDataPathProbe`, and the `lastRealData` refresh in `handleFragment`.
`Sources/ReticulumSwift/Interfaces/BLE/BLEMeshConstants.swift` — `probePingByte`
(0x04) / `probePongByte` (0x05) and the three interval constants.

**Python reference:** ble-reticulum `BLEInterface.py` — `_run_data_path_probes`,
`_handle_probe_frame`, `_send_probe`, `_last_real_data`, `_probe_capable`
(protocol v0.4.0, `BLE_PROTOCOL_v0.4.0.md`). The wire format (2-byte
PING `0x04` / PONG `0x05`, capability auto-negotiated on first frame, the
thresholds) matches the python reference exactly.

**Reason:** Category (b) — structural adaptation to the swift per-peer actor
model, semantics identical. Three deviations from the python structure:

1. **Per-peer loop, not centralized.** Python runs ONE timer in the parent
   `BLEInterface` iterating `spawned_interfaces`; the swift port runs the probe
   loop per-peer in `BLEPeerInterface` (`probeTask`, alongside the existing
   per-peer `keepaliveTask`/`rssiTask`), because the swift port already models
   each peer as its own actor with its own background loops.
2. **No address normalization.** Python `_handle_probe_frame` strips a
   `dev:`-prefixed peripheral address to resolve the peer's identity under the
   dual-role collision; here the frame already arrives on this peer's own
   connection, so identity is implicit and no lookup is needed.
3. **Reconnect via the owner's `onDataPathDead` → `driver.disconnect(address)`,**
   matching python. A peer interface's `connection.close()` only ends the receive
   stream; it does NOT cancel the BLE link, so on a dead data path the probe delegates
   to `BLEInterface`, which forces a real driver-level disconnect (central role:
   `cancelPeripheralConnection` → the peer re-advertises → reconnect via re-discovery,
   then grace-detach holds the route during the gap).
   **Known limitation (TODO, needs on-device validation):** for a *peripheral-role*
   peer CoreBluetooth cannot force-disconnect a subscribed central, so
   `driver.disconnect` is a no-op there; full recovery additionally requires the driver
   to drop `subscribedCentrals`/`centralConnections` for that address + emit
   `connectionLost` so the central's next write re-handshakes (the
   `didReceiveWrite` else-branch). Central-role recovery (the common case) works today.

Additionally, swift adds a `lastRealData` clock (updated only on real data +
probe frames, not keepalives/handshake). Python already has `_last_real_data`;
swift previously had only `lastActivity` (which counts keepalives). `lastActivity`
/ `checkZombies` are retained unchanged as the link-liveness backstop; the new
clock drives data-path liveness.

### Link resource-hooks — registry/queue/conclusion bookkeeping (Link.swift, resource-hooks 2026-06-14)

**Sites:** `Sources/ReticulumSwift/Link/Link.swift` — `resourceConcluded(_:)`,
`registerOutgoingResource`/`registerIncomingResource`/`cancelOutgoingResource`/
`cancelIncomingResource(_:corrupt:)`/`hasIncomingResource`/`readyForNewResource`/
`getLastResourceWindow`, `incomingResourceCount`/`outgoingResourceCount`,
`sendResource(autoCompress:)` + `pendingOutgoingQueue`/`drainOutgoingQueue`,
`receiveResourceAdvertisement`/`acceptInboundAdvertisement`.

Python ref: `RNS/Link.py:1281-1330` (resource_concluded / register_* / cancel_* /
has_incoming_resource / ready_for_new_resource / get_last_resource_window),
`RNS/Link.py:1065-1098` (RESOURCE_ADV q/u/p dispatch), `RNS/Resource.py:508-538`
(`__advertise_job` QUEUED gate), `RNS/Resource.py:216-235` (accept body).

1. **`incomingResourceCount` / `outgoingResourceCount` getters.** Category (a):
   RNS exposes `incoming_resources` / `outgoing_resources` as plain lists
   (`RNS/Link.py:245-246`); the swift registries are `private` actor state, so
   read-only count getters provide the same observability the conformance bridge
   needs without leaking mutable storage. Semantics identical (list length).

2. **Event-driven outgoing-resource queue instead of a 0.25s poll.** RNS
   `Resource.__advertise_job` spins `while not link.ready_for_new_resource():
   sleep(0.25)` (`RNS/Resource.py:522-524`) on a per-resource thread, staying in
   `QUEUED`. The swift port has no per-resource thread and Torlando's standing
   prefer-event-driven rule forbids polling, so `sendResource` either advertises
   immediately (link free) or parks the prepared resource in `pendingOutgoingQueue`
   (its prepared, non-advertised state is the swift analogue of RNS `QUEUED`), and
   `resourceConcluded(_:)` drains the next one when the in-flight transfer
   concludes. Category (a) — same one-at-a-time gate, push instead of poll.
   All three send paths (`sendResource`, `drainOutgoingQueue`, `advertiseNextSegment`)
   `registerOutgoingResource` BEFORE advertising, which REORDERS vs RNS's
   advertise-then-register (`RNS/Resource.py:527→534`). RNS runs those two steps as
   consecutive SYNCHRONOUS statements with no yield, so a `RESOURCE_REQ` cannot
   interleave between them; in this actor port `sendAdvertisement` and
   `registerOutgoingResource` each suspend the Link actor (the latter via
   `await resource.hash`), so advertising first would leave a window where the
   advertisement is on the wire but the resource is untracked in `outboundResources`
   and a fast peer's `RESOURCE_REQ` would be dropped. Registering first preserves RNS's
   effective atomicity. Category (a) — actor await points create an interleaving window
   RNS's synchronous code does not have. Each path unregisters the resource on an
   advertise failure so the one-at-a-time gate is not left stuck. A synchronous
   `outgoingReservationActive` flag (also checked by `readyForNewResource()`) closes
   the remaining register WINDOW: `registerOutgoingResource` itself suspends on
   `await resource.hash` while `outboundResources` is still empty, so the flag is set
   SYNCHRONOUSLY before that await and cleared once registered — preventing a
   concurrent `sendResource`/`drainOutgoingQueue`/`advertiseNextSegment` from seeing
   the link as free and advertising a competing resource mid-commit (which would put
   two resources in `outboundResources` and confuse the receiver's request/hashmap
   machinery). RNS needs no such flag because `register_outgoing_resource` runs
   synchronously with no yield. Every send path clears the reservation on all exit
   paths (success-after-register, no-next-segment, and each failure branch) so the
   link can never be permanently wedged.

3. **`resourceConcluded(_:)` omits `expected_rate`.** RNS recomputes
   `self.expected_rate` here (`RNS/Link.py:1287/1290`); nothing in this port
   consumes it, so it is omitted. Category (b) — faithful drop of an unused field.
   The window record (`last_resource_window = resource.window`, `RNS/Link.py:1284`)
   IS ported.

4. **`cancelIncomingResource(_:corrupt:)` — `corrupt:true` flag (Plan-A seam).**
   Category (a)/(b): `corrupt:false` mirrors RNS `cancel_incoming_resource`
   exactly (`RNS/Link.py:1324-1326`, plain registry removal). `corrupt:true` is a
   port addition that routes the receiver-side CORRUPT teardown (RNS
   `Resource.cancel()` CORRUPT branch — reject + bz2-overflow teardown,
   `RNS/Resource.py:688-692`/`:1079-1085`) through the **Link** rather than letting
   the `Resource` actor re-enter the `Link` mid-cancel (reentrancy hazard).
   **Now wired (2026-06-14):** `handleResourceData`'s assembly catch calls
   `cancelIncomingResource(_:corrupt:true)` when `assemble()` reports
   `corruptReason == .decompressionOverflow`, so the production receive path now
   exercises this teardown (it is no longer a dormant seam).

5. **RESOURCE_ADV `acceptNone` no longer sends a reject (RNS fidelity fix).**
   Previously the swift handler rejected on every non-accept path; RNS sends a
   reject ONLY from the declined `ACCEPT_APP` branch (`RNS/Link.py:1094`) and does
   `pass` for `ACCEPT_NONE` (`RNS/Link.py:1087`). `receiveResourceAdvertisement`
   now matches RNS. This is a fix toward upstream, not a divergence; noted here for
   traceability.

6. **`request_id`-without-`p`-flag response fallback (open risk).** RNS keys
   response-resource detection on the `p` flag (`is_response`,
   `RNS/Resource.py:1251-1257`). This port additionally accepts an advertisement
   that carries a `request_id` matching a pending request even when `p` is unset,
   preserving the pre-existing live LXMF/Columba request/response behaviour. If
   real senders are confirmed to always set `p`, drop this fallback. Category (b),
   provisional. **Re-confirmed 2026-06-14:** still accurate — RNS `is_response`
   (`RNS/Resource.py:1254`) is `adv.q != None and adv.p`; this fallback remains a
   deliberate permissive divergence kept for live interop, not yet retired.

7. **`sendResource(autoCompress:)` default is `false` (RNS default is `true`).**
   Category (b), intentional. RNS `Resource.__init__` defaults `auto_compress=True`
   (`RNS/Resource.py:248`, applied `:366-372`). This port plumbs `autoCompress`
   faithfully through `sendResource` → `Resource.init` → `prepare()` (no longer
   hardcoded), but the DEFAULT is `false` because this port's BZ2 output has not
   been interop-verified against the Python receiver (see inline note
   `Link.swift:1455-1459`/`1489-1491`). Wire effect: a caller relying on the RNS
   default gets an UNcompressed resource. Flip the default to `true` once E2E BZ2
   interop is verified. **Re-confirmed 2026-06-14:** still accurate and still
   intentional.

8. **`sendResource(metadata:)` pass-through** — `Link.swift` `sendResource`.
   Category (a)/faithful. RNS has no `Link.send_resource`; an outbound resource is
   sent by constructing `RNS.Resource(data, link, metadata=…, advertise=True)`
   (`RNS/Resource.py:248`). The swift `sendResource` is the port-convenience wrapper
   for that construction, so adding a `metadata: Data? = nil` argument it forwards to
   `Resource.init(metadata:)` mirrors RNS exactly. Default `nil` keeps every existing
   call site (and its byte layout / `total_size`) unchanged — `metadataSize` stays 0,
   adv flag bit 5 stays clear. Added 2026-06-14 so the conformance bridge can drive a
   metadata-bearing live transfer (wire_resource_send metadata round-trip).

**Wired in this file (2026-06-14 fidelity pass):**
- `acceptInboundAdvertisement` now calls
  `applyInheritedWindow(getLastResourceWindow())` BEFORE `resource.accept()`, so a
  second inbound transfer on the same link inherits the prior receiver window
  exactly as RNS `Resource.accept` (`RNS/Resource.py:216-219`). Previously only the
  conformance bridge wired this, leaving the production path stuck on slow-start.
- `handleResourceProof` now routes through the faithful port
  `Resource.validate_proof` (`Resource.swift:1696`), which enforces
  `proof_data[32:] == expected_proof` (`RNS/Resource.py:782-787`) before
  concluding/advancing — the prior inline `transitionState(.complete)` path
  concluded on the 32-byte hash match alone and dropped the integrity check. On a
  proof mismatch the resource now stays awaiting-proof (RNS fall-through,
  `RNS/Resource.py:822-823`).
- `handleResourceData`'s assembly catch now branches on `corruptReason`: the bz2
  over-size case tears the link down (see the corrupt-assembly entry above), the
  ordinary hash-mismatch case concludes quietly.

**Still deferred to Plan A (Resource.swift) integration — NOT yet wired in this file:**
`acceptInboundAdvertisement` does not yet call `deriveReceiverPartCount(self.mdu)`
(RNS `Resource.accept:187`), explicit `hashmapUpdate(0, adv.m)` (RNS `:233`), or
per-instance `maxDecompressedSize`; `handleResourceRequest` has no
`registerRequestHash` dedup; and `handleResourceHMU` still calls
`appendHashmapSegment` (the future `hashmapUpdate(segment:hashmap:)` alias). These
depend on Plan A's Resource API surface, which is not present in this tree; the
existing receive/HMU behaviour is preserved so the regression suite stays green
until Plan A lands. (Consistent in practice because both peers share the negotiated
link MDU, so receiver part-count derivation from the advertisement matches
`ceil(size/self.mdu)` except under asymmetric/renegotiated MDU.)

### Link watchdog/timing observability + identify/request gaps (Link.swift, Link+Identify.swift, Link+Request.swift, RequestReceipt.swift, W-LINK 2026-06-15)

**Sites:** `Sources/ReticulumSwift/Link/Link.swift` — `staleTime` field +
`setWatchdog`/`updateKeepalive`/`checkLiveness`, `lastInboundAt`/`lastKeepaliveAt`/
`lastKeepaliveByte`/`lastDataAt`/`activatedAt` accessors + `noInboundForMs()`,
`encrypt`/`decrypt`/`sendKeepalive`/`processKeepalive`/`transitionState`,
response-resource `has_metadata` fork + `handleRequestResponse(...,metadata:)`;
`Sources/ReticulumSwift/Link/Link+Identify.swift` — `identify(identity:)`;
`Sources/ReticulumSwift/Link/Link+Request.swift` — `respond(to:file:metadata:)`;
`Sources/ReticulumSwift/Request/RequestReceipt.swift` — `metadata` field +
`timeoutInterval` accessor + `receiveResponse(_:metadata:)`.

Python ref: `RNS/Link.py:248-266` (timing fields), `:657-663` (no_inbound_for),
`:689-692` (had_outbound), `:792-808/:844-846` (watchdog + __update_keepalive),
`:459-475` (identify), `:884-895/:906-954` (handle_request file response /
handle_response metadata / response_resource_concluded), `:1149-1153` (keepalive
echo), `RequestReceipt` `:1369/:1377/:1457-1461` (metadata/timeout/response_received).

1. **Public timing accessors for private actor fields.** Category (a): RNS exposes
   `last_inbound`/`last_keepalive`/`last_data`/`activated_at`/`stale_time`/
   `keepalive` as plain attributes (`RNS/Link.py:248-266`); Swift actor
   encapsulation hides them, so `lastInboundAt`/`lastKeepaliveAt`/`lastDataAt`/
   `activatedAt`/`staleTime` (read-only) and `noInboundForMs()` (mirrors
   `no_inbound_for()`, `RNS/Link.py:657-663`: `now - max(last_inbound, activated_at)`,
   returning nil only when neither reference exists) provide the same
   observability the conformance bridge reads. Semantics identical.

2. **`staleTime` is a stored, settable field read by the watchdog (was inline
   `keepaliveInterval * 2`).** RNS `__watchdog_job` reads `self.stale_time`
   directly (`RNS/Link.py:796`) and `__update_keepalive` keeps
   `stale_time = keepalive * STALE_FACTOR` (`:846`). The port previously hard-coded
   `keepaliveInterval * 2.0` inside `checkLiveness()`, so neither knob could be
   driven at runtime. `staleTime` now defaults to `keepaliveInterval * STALE_FACTOR`
   (2) — identical to the old inline value for any un-driven link, so the 454-test
   regression behavior is unchanged — and `setWatchdog(keepalive:staleTime:)`
   overrides both (RNS sets `link.keepalive`/`link.stale_time` as plain attributes,
   `RNS/Link.py:262-263`). `updateKeepalive(forRTT:)` recomputes both together at
   RTT measurement, mirroring `__update_keepalive`. Category (a) (settable knob via
   explicit method instead of attribute assignment). `checkLiveness` also folds
   `activatedAt` into its activity baseline to match `RNS/Link.py:789`.

3. **`lastKeepaliveByte` / `lastKeepaliveAt` recorded on emit + echo.** New
   observability for the bytes RNS puts on the wire (`send_keepalive` 0xFF,
   `RNS/Link.py:849`; non-initiator answers 0xFE, `:1149-1153`). `sendKeepalive`
   records both; `processKeepalive` additionally sets `lastKeepaliveByte = 0xFE`
   synchronously when answering an inbound 0xFF, so the read-back is race-free
   despite the echo send being dispatched on a detached `Task` (the swift
   keepalive echo is already async — a pre-existing structural deviation). Category
   (a).

4. **`lastDataAt` (last_data) split from `last_inbound`.** RNS bumps `last_data`
   only for non-KEEPALIVE traffic (`RNS/Link.py:691` outbound / `:979-980`
   inbound). The swift port centralizes inbound/outbound timestamping in
   `decrypt()`/`encrypt()` (a pre-existing structural deviation — there is no single
   `receive()`); since keepalives are raw bytes routed through `processKeepalive`
   (never `decrypt`), every `encrypt`/`decrypt` is payload and advances both
   `lastDataAt` and `lastOutbound`/`lastInbound`, while a keepalive advances only
   `lastInbound` (+`lastKeepaliveAt`). Net semantics match RNS. Category (a).

5. **`identify(identity:)` — restriction removed + silent ACTIVE-only guard.**
   BEHAVIOR CHANGE. RNS `identify` signs `link_id + identity.get_public_key()` with
   the PRESENTED identity and reveals it, with NO check that the identity matches
   the link's local identity, and is a silent no-op when `not (initiator and
   status == ACTIVE)` (`RNS/Link.py:468-475`). The port previously (a) threw
   `LinkError.invalidState` when `identity.hash != localIdentity.hash` and (b) threw
   on a non-initiator / non-established link. Both were Swift-only restrictions
   diverging from RNS; removed. Guard failures now return silently (no throw, no
   packet) — backing identify-on-PENDING-is-a-no-op — while genuine crypto/send
   errors still throw. No existing reticulum-swift test relied on the old throwing
   contract (no test exercises `identify()`). The `had_outbound()` after send
   (`:475`) is covered by `encrypt()` bumping `lastOutbound`/`lastDataAt`.

6. **RequestReceipt `metadata` + `timeoutInterval` + `receiveResponse(_:metadata:)`
   and the response-Resource `has_metadata` fork.** Category (a)/feature parity:
   RNS `RequestReceipt.metadata`/`.timeout` are plain attributes
   (`RNS/Link.py:1369/:1377`) and `response_received(response, metadata)` stores
   metadata (`:1457-1461`); `response_resource_concluded` delivers a metadata-bearing
   (file) response as raw bytes + metadata rather than `umsgpack([request_id,
   response])` (`:939-954`). The port adds a read-only `metadata` field, a
   `timeoutInterval` accessor (exposes the real `rtt*TRAFFIC_TIMEOUT_FACTOR(6) +
   RESPONSE_MAX_GRACE_TIME*1.125` value), a default-nil `metadata:` param on
   `receiveResponse` (existing call sites unchanged), the has_metadata fork in the
   Link response-resource delivery path (keyed on `Resource.receivedMetadata`), and
   `Link.respond(to:file:metadata:)` to emit a file response Resource. NOTE: the
   end-to-end (file,metadata) round-trip ALSO needs server-side request dispatch
   (`Destination.request_handlers` + REQUEST routing), which lives in Destination/
   Transport (a sibling agent's files) and is NOT implemented here.

## Resolved deviations

### `ReticulumTransport.sendLinkData` — incorrectly converted link DATA to HEADER_2 (resolved 2026-05-10)

**Site:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` —
`sendLinkData(packet:)` (was `sendLinkData(packet:destinationHash:)`
prior to this fix; the `destinationHash` parameter was the input the
buggy path-table lookup consumed and was dropped to prevent
regressions).

**Python reference:** `RNS/Transport.py:1034-1130` — `Transport.outbound`.
The path-table lookup at `:1063` keys on `packet.destination_hash`. For
link DATA packets, `destination_hash == link_id`, and link_ids are
NEVER inserted into `Transport.path_table`. The lookup therefore always
misses, and execution falls through to the broadcast loop at `:1122`.
The LINK destination guard at `:1128-1130` (`if interface !=
packet.destination.attached_interface: should_transmit = False`) then
restricts transmission to the link's `attached_interface` only, as
HEADER_1.

**Bug:** the prior swift implementation looked up the path by the
peer's destination hash (passed as a separate `destinationHash`
parameter, since the packet's destination is `linkId` for links) and
performed HEADER_2 conversion when `hopCount > 1`. This produced
HEADER_2 packets with `destination_hash = linkId`, which downstream
transport nodes (rnsd) interpret as transport-routed packets but
cannot route — link_ids aren't routable destinations — and silently
drop. Symptom on iOS smoke pipeline `direct_echo`: phone hits
`state=SENT`, rnsd validates the LRPROOF, link DATA disappears
without forwarding, echo bot's `on_delivery` never fires.

**Fix:** `sendLinkData` now sends the unmodified HEADER_1 packet to
the link's `attachedInterfaceId` (set during `handleLinkProof` /
`handleLinkRequest`). The `destinationHash` parameter was removed;
the public signature is now `sendLinkData(packet:)`. Any caller
using the old `sendLinkData(packet:destinationHash:)` form will
get a compile error and must be updated.
Mirrors python `Transport.outbound:1122-1130`.

**Why this needs a deviation entry even though it's a fix:** The
prior buggy implementation was itself an undocumented divergence
(the python upstream has no path-table lookup for link DATA). This
entry records the bug for future re-syncers and codifies the
correct semantic so the divergence doesn't reappear.

### L4 transport memory caps — audited, NOT ported (python-faithful); NE bound deferred to GATE

**Sites:** none changed. Audit covered `Transport/FramedTransport.swift`
(`receiveBuffer`), `Transport/ReticulumTransport.swift` (`pendingPackets`,
`discoveryPathRequests`, `discoveryPrTags`), `Routing/PathTable.swift`, and
`Link/Link.swift` (resource strategy).

**Python reference:** `../Reticulum/RNS/Interfaces/TCPInterface.py:380-398`
(HDLC read loop); `../Reticulum/RNS/Transport.py:121-128` (`path_requests` /
`discovery_path_requests` dicts; `pending_discovery_prs = deque(maxlen=32)`);
`Transport.py:788-799` (expiry culling).

**Finding:** A planned hardening task ("L4") proposed bounding the HDLC
`receiveBuffer`, an LRU cap on the pending-destination count, a hard entry
ceiling on the path table, and a per-link concurrent-resource cap. Checked
against the reference: python bounds NONE of these. The python HDLC read loop
(`TCPInterface.py:382` `frame_buffer += data_in`) appends unconditionally and
only trims when a complete `FLAG…FLAG` frame is found — the `HW_MTU` guard at
`:362` lives in the KISS branch only, which `FramedTransport` (HDLC) does not
mirror. The path table and `discovery_path_requests` are expiry-managed dicts
with no count ceiling. `pending_discovery_prs` (the only count-capped structure,
`deque(maxlen=32)`) is a work queue feeding a python worker thread; the swift
port forwards path requests inline via async with no equivalent handoff queue to
bound. Swift's existing `pendingPackets` per-destination cap (10) and
`discoveryPrTags` cap already match-or-exceed python's bounding.

**Decision (2026-06-02):** add NONE of the proposed caps — each would be a
divergence from a reference that is itself unbounded / expiry-only. This entry
exists so a future re-syncer does NOT "helpfully" re-add them believing they are
missing: they are faithfully absent.

**Deferred NE-hardening note:** the unbounded `receiveBuffer` is a genuine risk
for the memory-constrained iOS Network Extension (~60 MB budget) that python's
desktop reference never faced — a malicious relay streaming an unterminated HDLC
frame could grow it without limit and trigger jetsam. Per owner decision this is
NOT pre-emptively bounded (a speculative divergence); it is revisited at GATE
Phase 1b (under-load NE memory measurement). If the NE actually OOMs on this
path, an `HW_MTU`-style bound is added THEN as a measured, explicitly documented
category-(a) divergence (a runtime constraint the python pattern cannot express
in the NE sandbox), and this entry is updated to record it.

### `TCPTransport.bypassTunnelEgress` — iOS Network Extension egress pin (defensive; new feature)

**Site:** `Sources/ReticulumSwift/Transport/TCPTransport.swift` — static
`bypassTunnelEgress` (default `false`) and its use in `connect()`, where it sets
`NWParameters.prohibitedInterfaceTypes = [.other]` on the outbound
`NWConnection`.

**Python reference:** `../Reticulum/RNS/Interfaces/TCPInterface.py:142-202` —
upstream creates a raw BSD socket (`socket.socket` / `socket.create_connection`,
`setsockopt` for `TCP_NODELAY`/`SO_KEEPALIVE`/timeouts). There is no
Network.framework, no `NWParameters`, and no concept of binding a connection to
an interface *type*. The python desktop reference never runs inside an iOS
packet-tunnel provider, so this concern does not arise upstream.

**Reason:** Category (a) — a platform construct (Network.framework interface
scoping) the python pattern cannot express. When `TCPTransport` runs *inside* a
`NEPacketTunnelProvider`, an outbound connection can in principle bind to the
provider's own tunnel (utun, interface type `.other`) and loop instead of
egressing the LAN. `prohibitedInterfaceTypes = [.other]` pins it to a physical
interface (wifi/cellular). Only the NE host sets it `true`; the normal in-app
path is unaffected.

**Honesty note (2026-06-02 on-device bring-up):** this was originally added
believing it was *the* fix for "announces not propagating," but that diagnosis
was wrong — the real root cause was a **wedged Mac relay daemon** (`lxmd` had
crashed days earlier on `[Errno 28] No space left on device` while persisting a
ratchet, so it accepted TCP connections but ingested no announces). The
"phantom `.ready` / zero SYN" observation that motivated this was a **tcpdump
filter artifact** — I was filtering the device's stale DHCP IP, not its current
one; the NE's stock-`NWParameters` connection had been egressing fine the whole
time. So `bypassTunnelEgress` is **retained as a defensive belt-and-suspenders
pin** (cheap insurance against a future tunnel-routing regression binding the
NE's relay to its own utun), NOT as a verified-necessary fix. **Revert
candidate:** returning `connect()` to stock `NWConnection(using: .tcp)` and
deleting this flag would also be correct — on-device delivery + announce-in/out
were later confirmed working with it in place, but were never shown to *require*
it.

### PathTable persistence — iOS NE-safe SQLite open (fix/pathtable-ne-safe 2026-06-07)

**Sites:** `Routing/PathTable.swift` `init(databasePath:)` — `#if os(iOS)` blocks:
`PRAGMA synchronous=NORMAL` + `PRAGMA busy_timeout=5000` + `journal_mode=WAL`
(set via prepare/step so the resulting mode is verified), and
`FileManager.setAttributes(.protectionKey: .completeUntilFirstUserAuthentication)`
on the db + its `-wal`/`-shm` sidecars.

**Python reference:** `../Reticulum/RNS/Transport.py` persists the path table by
pickling to `<storagepath>/destination_table` (`save_path_table()` /
`persist_data()`) — an in-memory dict flushed to a plain file on a desktop
process that is never suspended-while-locked. No SQLite, no data-protection.

**Reason:** Category (a) — a platform/runtime need python's pickle-on-desktop
model cannot express. The swift port already backs the path table with SQLite (a
pre-existing storage-layer choice; the record/lookup/cleanup *logic* still
mirrors Transport.py). When that store is the **iOS Network-Extension writer**
(Columba Model B — the NE owns it, the app opens it read-only), it must be opened
NE-safe: WAL + `busy_timeout` ride out cross-process contention with the app's
handle, and `completeUntilFirstUserAuthentication` lets the NE read/write after
first unlock even while the device is later locked — otherwise the NE faults
(`0xDEAD10CC` / protected-file) touching the store while suspended. Mirrors how
`LXMFDatabase` opens its store. Guarded `#if os(iOS)`; other platforms keep the
default open (unchanged).

**Not a logic divergence:** the path-table decision trees (`record`, `lookup`,
`cleanup` incl. the interface-absent cull at `Transport.py:778-785`) are
unchanged and faithful — only the storage backend's iOS open is platform-specific.

### BLE per-peer interface — grace-period detach + identity reuse (fix/ble-peer-grace-period-detach 2026-06-07)

**Sites:** `Interfaces/BLE/BLEInterface.swift` (`pendingDetach`, `scheduleDetach`,
`finalizeDetach`, `handleDisconnection`, `addPeer` reuse), `BLEPeerInterface.swift`
(`onConnectionLost` / `handleConnectionLost`, `detach` made teardown-only),
`BLEMeshConstants.swift` (`detachGracePeriod`).

**Python reference:** `../ble-reticulum/src/ble_reticulum/BLEInterface.py` —
`_device_disconnected_callback` (1295) schedules `_pending_detach[identity_hash]`
instead of detaching inline; `_process_pending_detaches` (771) detaches after the
grace period if no address reconnected; `_spawn_peer_interface` (1892) reuses the
existing per-peer interface on reconnect and clears `_pending_detach`;
`_pending_detach_grace_period = 2.0` (393). Both stacks register identity-keyed
per-peer interfaces with core RNS `Transport.interfaces`, whose `jobs()` culls
paths of absent interfaces (`../Reticulum/RNS/Transport.py:778-785`).

**What now matches python:** a dropped BLE connection no longer removes the peer
interface immediately. It is held (registered with the transport) for
`detachGracePeriod`; a reconnect with the same identity reuses it (existing
hot-swap `updateConnection`) and cancels the pending detach, so a transient drop
(MAC rotation) does not cull the learned route. Absent a reconnect, the peer is
removed after grace. This is the actual fix for BLE transient-drop route loss;
the core RNS interface-absent cull stays intact (it is correct and matches
upstream — see the H4 revert in the NE-safe-PathTable PR).

**Deviations from the python shape (and why):**

1. **One-shot timer, not a maintenance-loop poll.** Python calls
   `_process_pending_detaches` from its periodic maintenance loop; the swift port
   arms a single `Task.sleep(detachGracePeriod)` per scheduled detach
   (`scheduleDetach`). Same semantics, but event-driven (no steady ~1s poll),
   matching Torlando's standing prefer-event-driven-over-polling rule. The
   reconnect-cancels signal is `pendingDetach` being cleared by `addPeer`, which
   `finalizeDetach` re-checks — the analogue of python re-checking
   `has_connected_address`.

2. **No `_identity_cache`.** Python caches peer identity for `_identity_cache_ttl`
   (60s) so a reconnect that arrives *without* a fresh identity handshake (Android
   holding the GATT link) can be re-identified. The swift port performs a full
   identity handshake on *every* connection (`performCentralHandshake` /
   `performPeripheralHandshake`), so identity is always re-derived on reconnect and
   the cache is unnecessary. Category (b) — a faithful simplification the swift
   handshake model permits.

3. **Teardown is owned by the peer's cancellation-safe loops, not inline in the
   disconnect handler.** Python serializes disconnect vs reconnect with
   `peer_lock`. Swift actors can't hold a lock across `await`, so `scheduleDetach`
   is deliberately synchronous (no `await` into the peer) and does **not** tear the
   connection down: a reconnect's `updateConnection` cancels the peer's old
   receive/keepalive tasks, and their existing `!Task.isCancelled` guards suppress
   the self-detach — so a stale teardown can never kill a freshly-reconnected
   connection. If no reconnect arrives, `removePeer` (at finalize) does the
   teardown. Category (a) — Swift's actor/reentrancy model vs python's thread+lock.

4. **Three disconnect signals funnel into one scheduler.** Python has a single
   driver callback. Swift has three ("connection died" via the driver's
   `connectionLost` stream, the peer's receive-stream end, and keepalive
   double-fail); all route to `scheduleDetach`, which is idempotent per identity
   (`pendingDetach[hex] == nil` guard). The `addPeer` reject-duplicate rule also
   gains an `isDetaching` check so an in-grace peer (still reading `.connected`
   until its loops wind down) does not reject the very reconnect it is waiting for.

**Grace value:** `detachGracePeriod = 2.0s` mirrors python exactly. iOS BLE
reconnect latency (RPA rotation + scan/connect) may warrant tuning it up after
on-device observation; raising it only widens the transient-drop window the route
survives, so it is safe to increase.

**Not a logic divergence in the cull:** core RNS path-table `record`/`lookup`/
`cleanup` (incl. the interface-absent cull) are unchanged. This PR fixes the
*interface lifecycle* so a transient drop keeps its interface registered long
enough to be reused — the layer ble-reticulum fixes it at.

---

## Resource core: cancel / request / validate_proof / prove / metadata / CORRUPT / hashmap_update

These cover the receiver/sender Resource APIs added so the Link's resource hooks
(`receiveResourceAdvertisement`, `resourceConcluded`, `cancelIncomingResource(corrupt:)`,
the QUEUED gate) and the conformance bridge's `wire_resource_*` / `wire_inject_*`
commands can drive real production logic instead of working around library gaps.

1. **`.corrupt` as a distinct `ResourceState` case** — `Resource/ResourceState.swift`.
   RNS models CORRUPT as a status code `0x08` alongside FAILED `0x07`
   (`RNS/Resource.py:151`). The swift port adds a real enum case `.corrupt`
   (terminal, not active, not complete). `canTransition` is RELAXED to mirror RNS:
   (a) any non-terminal state may go to `.failed` (RNS `cancel()` sets `FAILED`
   for any `status < COMPLETE`, `RNS/Resource.py:1086-1087`); (b) `.transferring` /
   `.assembling` may go to `.corrupt` (`assemble()` CORRUPT outcomes,
   `RNS/Resource.py:689/715`). Category (a) (Swift's exhaustive enum vs python's
   loose int status). The three ConformanceBridge status mappers
   (`WireTcp.swift` `rawValueForBridge`, `WireTcp+Resource.swift`
   `wireResourceStatusCode`/`wireResourceStatusName`) were updated in lockstep —
   forced because Swift `switch` over the enum is exhaustive — and UNIFIED to RNS
   codes: `corrupt -> 8 / "CORRUPT"`, `rejected -> 0` (RNS REJECTED == NONE == 0),
   `cancelled -> 7` (RNS `cancel()` -> FAILED).

2. **`ResourceError.corruptResource` (new error case)** — `Resource/ResourceErrors.swift`.
   `assemble()` throws this (replacing the generic `transferFailed`) on the CORRUPT
   path so the Link can `catch ResourceError.corruptResource` and branch on
   `corruptReason`. Category (b) (new typed error for the new CORRUPT contract).
   Equatable + LocalizedError updated for the case (exhaustive switch).

3. **`assemble()` does NOT call back into the Link** — `Resource/Resource.swift`.
   RNS `assemble()` calls `self.link.resource_concluded(self)` and the final-segment
   callback inline (`RNS/Resource.py:723-747`). The swift actor port instead RETURNS
   the assembled bytes on success and THROWS `corruptResource` on failure; the Link
   calls `resourceConcluded` after `assemble()` returns/throws. This avoids
   Resource(actor) → Link(actor) reentrancy while `assemble()` still holds the
   Resource's executor. Category (a) (actor reentrancy).

4. **Auto-prove + idempotent `prove()` / `sendProof()` alias** — `Resource/Resource.swift`.
   `assemble()` auto-proves on success via `prove()` (`RNS/Resource.py:713`).
   `prove()` is idempotent (`proveCallCount`, sends at most one RESOURCE_PRF) and
   `sendProof()` is retained ONLY as a thin alias so the Link's legacy receive path
   and the bridge keep compiling: because `prove()` is send-once, a stray
   `sendProof()` after auto-prove is a no-op and cannot emit a second proof (would
   break `test_resource_no_per_part_proofs`). `prove()` hashes `provePlaintext`
   (the FULL per-segment plaintext, metadata INCLUDED — `self.data` at RNS
   `:684/755`), retained separately from the metadata-stripped `assembledData`, so a
   metadata transfer's proof still matches the sender's `expectedProof =
   full_hash(plaintext + hash)` (`RNS/Resource.py:443`). Category (a)/(b)
   (idempotency added for the cross-agent transitional double-call; the
   per-segment-plaintext proof source is a faithful port that also fixes the
   metadata-proof mismatch).

5. **`validate_proof(_:)` does NOT advance the Link** — `Resource/Resource.swift`.
   RNS `validate_proof` calls `link.resource_concluded` and advertises the next
   segment inline (`RNS/Resource.py:786-821`). The swift port only sets `state =
   .complete`; the Link calls `validate_proof` then inspects `state` to choose
   conclude-vs-advance. Category (a) (actor reentrancy / single-source segment
   chaining in the Link).

6. **`cancel()` CORRUPT branch delegated to the Link** — `Resource/Resource.swift`.
   `cancel()` recurses into `nextSegment`, then: if already `.corrupt` it is a
   no-op (the Link owns RESOURCE_RCL + teardown via `cancelIncomingResource(corrupt:
   true)`, mirroring `RNS/Resource.py:1081-1084` but driven from the Link to avoid
   reentrancy); otherwise it sets `.failed`, emits RESOURCE_ICL via the
   `sendCallback` closure (not an actor hop) when `isInitiator` and the link is
   active, and calls `link.cancelOutgoingResource` / `cancelIncomingResource` +
   `resourceConcluded`. Category (a) (actor reentrancy).

7. **Receiver hashmap kept as a CONTIGUOUS blob (not a `[None]*total_parts` slot
   list)** — `Resource/Resource.swift` `hashmapUpdate(segment:hashmap:)` /
   `hashmapHeight`. RNS stores per-slot entries and writes `hashmap[i + segment *
   HASHMAP_MAX_LEN]` (`RNS/Resource.py:492-503`). This port keeps the existing
   contiguous representation that grows as sequentially-numbered HMU segments arrive
   (the order RNS's HMU handshake actually uses), preserving the existing
   `handlePartPacket` search / `getPartHash` / `receivePart` validation readers with
   no off-by-one slot arithmetic. `hashmapHeight` is the contiguous coverage
   (`bytes/4`); `hashmapUpdate` returns whether coverage grew (false on a duplicate
   segment) and is idempotent for re-applied segments. Out-of-order HMU segments are
   not slotted (logged) — RNS requests them in order. Category (a) (representation
   choice; observable height/grew/idempotency contracts preserved).
   `appendHashmapSegment(_:wireSegment:)` is retained as a thin forwarding alias to
   the canonical `hashmapUpdate(segment:hashmap:)`.

8. **Receiver init keeps loading the advertisement hashmap chunk directly** —
   `Resource/Resource.swift` `init(advertisement:link:)`. RNS `accept` preallocates
   `[None]*total_parts` then calls `hashmap_update(0, hashmap_raw)`
   (`RNS/Resource.py:210/233`). The swift inbound init loads `adv.m` into the
   contiguous hashmap directly so a Resource built straight from an advertisement
   (unit tests; bridge) is immediately usable; a later Link-driven
   `hashmapUpdate(0, adv.m)` is idempotent (segment 0 already covered → false).
   Category (a).

9. **`deriveReceiverPartCount(sdu:)` is a separate async step** —
   `Resource/Resource.swift`. RNS computes `total_parts = ceil(size/sdu)` inside
   `accept` from `link.mtu`/`link.mdu` (`RNS/Resource.py:187`). The swift actor
   `init` cannot `await link.mdu`, so the Link calls `deriveReceiverPartCount(self.mdu)`
   exactly once right after construction (and before routing the initial hashmap).
   It resizes the `parts`/`partsReceived` buffers; the hashmap is (re)loaded by the
   Link's `hashmapUpdate(0, adv.m)`. Category (a) (actor init can't await).

10. **`applyInheritedWindow` async + `ResourceWindow.setInitialWindow`** —
    `Resource/Resource.swift`, `Resource/ResourceWindow.swift`. RNS seeds
    `resource.window = link.get_last_resource_window()` inline in `accept`
    (`RNS/Resource.py:216-219`). The swift port exposes `applyInheritedWindow(_:)
    async` (cross-actor call from the Link) which calls a new
    `ResourceWindow.setInitialWindow(_:)` setter (the window is otherwise
    `private(set)`). Category (a).

11. **`setMapHashInjector` / `injectPartRaw` test seams** — `Resource/Resource.swift`.
    Swift has no monkeypatching, so the collision-guard remap loop
    (`RNS/Resource.py:435-474`) and the per-part map-hash validation
    (`RNS/Resource.py:866`) each expose an inert hook a conformance command can use
    to force a map-hash collision (`wire_resource_force_collision`) or to land a
    deliberately-corrupt part that survives to `assemble()`'s full-stream check
    (`wire_inject_corrupt_assembled_resource`). Both MUST be unset/no-op in
    production. Category (b) (test seams).

### Resource receive-path fidelity-fix pass (2026-06-14)

A review pass (`resource_fidelity_issues.txt`) re-aligned the receiver flow-control
to `RNS/Resource.py`. Several flagged items were GENUINE divergences and are now
fixed (no deviation remains, cited inline):

- **`getAdvertisement` u/p flag derivation** (`Resource/Resource.swift`
  `getAdvertisement`). Now derives `u`(is_request)/`p`(is_response) from
  `request_id` per `ResourceAdvertisement.__init__` (`RNS/Resource.py:1295-1307`):
  both 0 when `request_id == nil`, `u` set for an outbound request, `p` for a
  response. The prior code never set `u`, so a swift-originated request advertised
  with `u=0` and a python peer's `is_request()` (`:1242-1247`) misread it as a
  plain resource (Link request/response interop break). FIXED — faithful, no
  deviation.
- **Window growth on batch drain** (`receivePart`). The window now grows on every
  request-batch drain (`outstanding_parts == 0`, not just at full completion),
  matching `RNS/Resource.py:894-904`. FIXED.
- **`outstanding_parts` reset at request top** (`requestNextParts` →
  `ResourceWindow.resetOutstanding`). Mirrors `self.outstanding_parts = 0` at the
  top of `request_next` (`RNS/Resource.py:937`). FIXED.
- **Part→index resolution scans only the current window** (`handlePartPacket`).
  Now scans `hashmap[height : height+window]` instead of the whole hashmap, so a
  4-byte map-hash collision outside the collision-guard span can no longer return
  a wrong index (`RNS/Resource.py:863-866`). A part not found in-window is dropped
  silently (no throw), matching receive_part. FIXED.
- **Request pacing** (`handlePartPacket`). The next `RESOURCE_REQ` now issues only
  when the batch fully drains (`outstanding == 0`) rather than on every part
  (`outstanding < window`), matching `RNS/Resource.py:897-926`. FIXED.
- **`hashmap_update` sets TRANSFERRING** (`hashmapUpdate`). Now self-heals
  `ADVERTISED → TRANSFERRING` at the top (`RNS/Resource.py:493-494`) instead of
  relying on the Link having ordered accept() before any HMU. FIXED.

The following flagged items are LEFT as constrained/intentional deviations:

12. **Window height model is 0-based exclusive, not python's -1-based inclusive**
    — `Resource/ResourceWindow.swift` (`consecutiveCompletedHeight`),
    `Resource/Resource.swift` (`receivePart` accept window). RNS
    `consecutive_completed_height` starts at -1 and is the INCLUSIVE index of the
    last consecutively-completed part (`RNS/Resource.py:214`); its windows are
    `[cch, cch+window)`. This port's `windowManager.height` is a 0-based EXCLUSIVE
    count of leading completed parts (`== cch_python + 1`), so the accept window
    `[height, height+window)` is shifted UP by one vs python. It is internally
    self-consistent — the request range (`getNextPartIndices`) and the accept
    range share the same lower bound `height`, and a sender only sends requested
    parts, so every accepted part is in-window and **interop is unaffected**. The
    conformance bridge maps to the python value with `height - 1`
    (`ConformanceBridge/WireTcp+Resource.swift`), and the oracle asserts
    `consecutive_height == -1` initially against that mapping. Switching to the
    literal -1 model would require editing the bridge's `-1` compensation (a
    sibling-owned file) and would break that oracle assertion. Category (a)
    (representation choice; interop-neutral).

13. **`ResourceWindow.getRequestRange` scans PAST `height+window`** —
    `Resource/ResourceWindow.swift`. RNS `request_next` requests only the `None`
    slots inside the FIXED slice `parts[cch+1 : cch+1+window]`
    (`RNS/Resource.py:945-957`); this port keeps scanning past `height+window`
    until it has collected `window` incomplete indices, so on a holey transfer it
    can request indices beyond the window (chattier than python). It is NOT changed
    because the regression test `ResourceWindowTests.testGetRequestRangeSkipsIntermediateCompleteParts`
    (out of this pass's edit scope — `Tests/`) asserts the scan-past-window result
    `[2,4,5,6]` for `parts[0,1,3]=true, window=4`, which the RNS fixed-slice would
    instead return as `[2,4,5]`. Latent on in-order transfers (the only shape the
    oracle/regression suites exercise), where both models agree.

14. **`ResourceWindow.onTimeout` halves the window; `updateWindowMin` recomputes**
    — `Resource/ResourceWindow.swift`. RNS decrements `window`/`window_max` by 1
    (and window_min ratchets +1, `RNS/Resource.py:616-621/902-903`); this port
    HALVES `window`/`window_max` on timeout and recomputes
    `window_min = max(WINDOW_MIN, window - WINDOW_FLEXIBILITY)` each call. NOT
    changed because (a) no watchdog drives `onTimeout` in this port (latent), and
    (b) the regression tests `ResourceWindowTests.testTimeoutHalvesWindow`
    (asserts `window <= beforeTimeout/2 + 1`) and the `window_min` recompute curve
    are baked into `Tests/` (out of this pass's edit scope). Fixing the math would
    break those protected tests, which the pass is forbidden to edit.

15. **`assemble()` retains the encrypted-side `assembled.count == transferSize`
    guard** — `Resource/Resource.swift` `assemble()`. RNS has no pre-decrypt size
    check; it relies on the per-segment hash check (`RNS/Resource.py:694-695`,
    ported at the Step-5 hash check). The guard is defensive and CANNOT fire on a
    valid transfer (parts are sized + map-hash-validated on receipt, and
    `transferSize` is this segment's own `t`). Note: if it ever did fire it throws
    `ResourceError.transferFailed` (vs `.corruptResource`), a slightly different
    Link branch than the hash-mismatch CORRUPT path; this is acknowledged and
    accepted as defensive-only. Already covered by deviation #8 above; reconfirmed
    accurate in this pass.

16. **`completionCallback` models RNS `self.callback` for cancel() gating** —
    `Resource/Resource.swift` (`completionCallback`, `setCompletionCallback`,
    `cancel()`). RNS gates `link.resource_concluded(self)` + the conclusion
    callback on `self.callback != None` inside `cancel()`
    (`RNS/Resource.py:1099-1104`). This port routes the normal success conclusion
    through the Link's `ResourceCallbacks`, so it previously had no per-resource
    conclusion callback and called `link.resourceConcluded(self)` unconditionally
    on cancel. This pass adds the optional callback and gates the call on it,
    matching RNS. (Net effect is also neutral because `cancelIncoming/OutgoingResource`
    de-lists the resource first, so `resourceConcluded`'s membership-guarded
    window record is a no-op after cancel either way — but the gate now mirrors the
    python control flow rather than relying on that.) Category (a).

12. **`assemble()` decompresses via `bz2Decompress` to distinguish overflow** —
    `Resource/Resource.swift`. The compressed branch calls
    `ResourceCompression.bz2Decompress(..., maxDecompressedSize:)` directly (rather
    than the `decompress` wrapper) so it can pattern-match
    `BZ2Error.exceedsMaxDecompressedSize` → `corruptReason = .decompressionOverflow`
    (RNS over-size CORRUPT, `RNS/Resource.py:688-692`) vs. any other decompress
    failure → `.hashMismatch`. `maxDecompressedSize` is now a per-instance settable
    field (`RNS/Resource.py:364`). Category (a) (Swift error typing) — faithful to RNS.

13. **Metadata oversize is clamped, not raised** — `Resource/Resource.swift`
    `init(data:metadata:...)`. RNS raises `SystemError` when packed metadata exceeds
    `METADATA_MAX_SIZE` (`RNS/Resource.py:263-264`). The swift initializer cannot
    `throw`, so oversized metadata is dropped (logged) instead. Category (a)
    (non-throwing initializer). Otherwise the metadata SEND packing
    (`BE3(len(packed)) + msgpack.packb(.binary(metadata))`, `RNS/Resource.py:266`)
    and RECEIVE unpack (`receivedMetadata`, `RNS/Resource.py:698-731`) mirror RNS.

    **Tighter bound than RNS (added 2026-06-17):** the clamp ALSO drops metadata whose
    framed size (`packed.count + 3`) exceeds `MAX_EFFICIENT_SIZE` (1 MiB-1), not just
    `METADATA_MAX_SIZE` (16 MiB-1). Segment 1 reserves `firstReadSize =
    MAX_EFFICIENT_SIZE - metadataSize` payload bytes (`resolveSegmentPlaintext`,
    `Resource.swift:1105`/`:1154`); metadata larger than that yields a NEGATIVE read
    size which traps at runtime in Swift (`seek(toOffset: UInt64(negative))` on
    segment 2+, empty read on segment 1) where python's negative-size file ops degrade
    silently. Category (a) runtime-safety — RNS allows 1–16 MiB metadata that this
    port's seek/read math cannot express without a trap, so we reject it at
    construction. Metadata >~1 MiB is pathological for a header field; no real
    LXMF/LXST caller approaches it.

14. **Progress callback propagation is best-effort** — `Resource/Resource.swift`.
    RNS `progress_callback` recurses into `next_segment` synchronously
    (`RNS/Resource.py:1122-1124`). The swift port propagates the callback to a
    segment when it is prepared (`prepareNextSegment`), not retroactively from
    `setProgressCallback`. Category (a) (avoids an async hop in the setter).

15. **Collision-guard remap loop is retry-capped** — `Resource/Resource.swift`
    `prepare()`. RNS's `while not hashmap_ok` loop (`RNS/Resource.py:435-474`) has
    no retry bound because it relies on real link encryption making every part
    unique, so a fresh `random_hash` always breaks a map-hash collision. A fresh
    `random_hash` CANNOT break a collision between two BYTE-IDENTICAL encrypted
    parts (both `full_hash(part + random_hash)[:4]` are equal for any random_hash),
    which an identity/echo encryptor over repetitive plaintext produces — spinning
    the loop forever (observed: `ResourceCompletionTests` prepares
    `Data(repeating: 0xAB, 4096)` with an identity `linkEncrypt`). The port caps the
    retries at `RETRY_LIMIT` (16) and, on the final attempt, builds the hashmap
    accepting duplicate map_hashes — exactly the pre-existing single-pass behavior —
    so `prepare()` always terminates. The realistic (unique encrypted parts) path
    still converges on attempt 1 with no duplicates. Category (a) (termination
    guarantee for degenerate non-encrypting inputs).

### Destination request-handler / proof-strategy / links state — NSLock-guarded (2026-06-15)

**Sites:** `Sources/ReticulumSwift/Crypto/Destination.swift` — `stateLock`,
`_requestHandlers` / `_proofStrategy` / `_proofRequestedCallback` / `_links`, and
the public accessors `proofStrategy` / `proofRequestedCallback` / `links` plus the
mutators `registerRequestHandler` / `deregisterRequestHandler` /
`requestHandler(forPathHash:)` / `setProofStrategy` / `setProofRequestedCallback` /
`appendLink`.

**Python reference:** RNS stores these as plain instance attributes —
`self.request_handlers = {}` (`RNS/Destination.py:157`), `self.proof_strategy`
(`:160`), `self.callbacks.proof_requested` (`:43`,`:357`), `self.links = []`
(`:172`,:`424`) — read/written directly under the GIL.

**Reason:** Category (a) — language/runtime. `Destination` is a non-actor
`final class @unchecked Sendable` shared concurrently by the Transport actor, the
Link actor, and the conformance-bridge threads. Python serializes these
attribute mutations under the GIL; swift has no GIL, so the map/strategy/callback/
links storage is guarded by an internal `NSLock`. `proofStrategy` is exposed as a
lock-guarded computed getter rather than a literal `private(set)` stored property
for the same reason. Semantics, defaults (`PROVE_NONE`, `ALLOW_NONE`), and byte
values are identical to RNS; only the access discipline differs.

### Destination request-handling types — fixed-arity generator + `RequestResponse` enum (new feature)

**Sites:** `Sources/ReticulumSwift/Crypto/Destination.swift` —
`ResponseGenerator` typealias, `RequestResponse` enum, `RequestHandler` struct,
`ProofRequestedCallback` typealias.

**Python reference:** RNS `response_generator(path, data, request_id, link_id,
remote_identity, requested_at)` (`RNS/Destination.py:375`) and the
`Link.handle_request` response fork (`RNS/Link.py:877-901`), where the handler is
the bare python list `[path, response_generator, allow, allowed_list,
auto_compress]` (`:386`) and the generator returns a raw value or `None`.

**Reason:** Category (a) — language/runtime. RNS inspects the generator's arity at
call time (5 vs 6 args); swift has no runtime arity inspection, so the port fixes a
single 6-argument `async` form. RNS's "return a value or `None`" is modeled by the
`RequestResponse` enum (`.none` / `.bytes` / `.file`) so the `.none` (no-response)
branch is type-safe rather than a nil sentinel. Wire-observable response framing is
unchanged (the existing `respond(to:with:)` / `respond(to:file:metadata:)` send
fork is reused). The python `[...]` list is mirrored by the `RequestHandler` struct
field-for-field (`path`, `generator`, `allow`, `allowedList`, `autoCompress`).

### Interface MTU / bitrate / IFAC helpers — `Interface` namespace (no base class)

**Sites:** `Sources/ReticulumSwift/Interfaces/Interface.swift` (new) —
`Interface.optimiseMtu(bitrate:)`, `effectiveBitrate(configured:guess:)`,
`deriveHwMtu(...)`, `resolveIfacSize(bits:)`, and the `tcpClassHwMtu` /
`tcpBitrateGuess` / `MINIMUM_BITRATE` constants.

**Python reference:** `RNS/Interfaces/Interface.py:198-221` (`optimise_mtu` tier
table), `RNS/Reticulum.py:765-768` (configured-bitrate floor), `:719-723` +
`:860-862`/`:1049-1050` (ifac_size bit→byte resolution + DEFAULT_IFAC_SIZE
fallback), `RNS/Interfaces/TCPInterface.py:42/:76/:78` (HW_MTU/BITRATE_GUESS/
AUTOCONFIGURE_MTU).

**Reason:** Category (a) — language/runtime. RNS keeps `optimise_mtu` and the
MTU/bitrate/IFAC constants on the base `Interface` class (mutating `self.HW_MTU`).
reticulum-swift has no base `Interface` class — concrete interfaces conform to the
`NetworkInterface` protocol and expose `hwMtu` as a *computed* property — so the
tier mapping is a pure static (returns `Int?`, mirroring RNS's `HW_MTU = None`
bottom branch) and the gate/floor/derivation are separate statics the concrete
interfaces call. Tier boundaries, the strict-`>`-except-top-tier rule, the
`MINIMUM_BITRATE`(5) floor, and the `ifac_size//8` + `DEFAULT_IFAC_SIZE`(16)
fallback are byte-identical to RNS. `optimiseMtu == nil` (RNS `None`) is surfaced
to the non-optional `hwMtu` as `Reticulum.MTU` (500), the same value link signaling
falls back to (`Link.init: hwMtu ?? 500`); for TCP this branch is unreachable
(bitrate floored to the 10 Mbps guess → 8192).

### InterfaceConfig `fixedMtu` / `autoconfigureMtu` — struct fields, not class attrs

**Sites:** `Sources/ReticulumSwift/Interfaces/InterfaceConfig.swift` —
`fixedMtu: Int?`, `autoconfigureMtu: Bool`; `TCPInterface.swift` /
`TCPServerInterface.swift` `hwMtu`/`autoconfigureMtu`/`fixedMtu`/`classHwMtu`
computed properties + `fixedMtu < MTU` init validation.

**Python reference:** `RNS/Interfaces/TCPInterface.py:110-116` (fixed_mtu →
FIXED_MTU=True / AUTOCONFIGURE_MTU=False / HW_MTU=fixed_mtu, ValueError if
`< RNS.Reticulum.MTU`), `:599-600`/`:626` (spawned child inherits parent
bitrate→optimise_mtu then `HW_MTU = parent.HW_MTU`).

**Reason:** Category (a) — language/runtime. RNS stores FIXED_MTU/AUTOCONFIGURE_MTU
as per-class interface attributes set during `__init__`; reticulum-swift's
`InterfaceConfig` is a Codable struct constructed by the bridge/API (HARD RULE 5:
no INI/.conf pipeline), so the posture rides on the config struct (default
`fixedMtu=nil`, `autoconfigureMtu=true`; a set `fixedMtu` forces `autoconfigureMtu=
false` in the init, mirroring TCPInterface.py:112-114). Codable stays backward
compatible (`decodeIfPresent`, defaults `nil`/`true`). The live `hwMtu` of a
default TCP interface changes from the old hardcoded 262144 ceiling to the
RNS-faithful autoconfigured 8192 — the negotiated link MTU for default TCP links
follows. **Minor behavioral deviation:** RNS's `TCPServerInterface.__init__`
ignores `fixed_mtu` (only `TCPClientInterface` reads it) and spawned children
inherit the server's *autoconfigured* HW_MTU; the swift server honors
`config.fixedMtu` uniformly (the bridge sets it on both peers). The negotiated link
MTU is `min(initiator-signalled, responder)` so the observable result is identical
(the client's fixed value wins either way); honoring it on both sides keeps spawned
children consistent.

### Transport probe / remote-management destinations — registration + posture only

**Sites:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` —
`registerProbeDestination(identity:)`, `registerRemoteManagementDestination(
identity:allowed:)`, `probeDestination`/`remoteManagementDestination`/
`mgmtDestinations`/`mgmtHashes`/`respondToProbes`/`remoteManagementEnabled`/
`remoteManagementAllowed`/`panicOnInterfaceError`; `TransportErrors.swift`
`invalidConfiguration(reason:)`.

**Python reference:** `RNS/Transport.py:396-403` (probe_destination: IN/SINGLE
`rnstransport.probe`, PROVE_ALL, accepts_links(False), mgmt_destinations),
`:252-258` (remote_management_destination: IN/SINGLE `rnstransport.remote.
management`, `/status` + `/path` ALLOW_LIST handlers bound to
remote_management_allowed, mgmt_destinations + mgmt_hashes), `RNS/Reticulum.py:280`
(panic_on_interface_error default False).

**Reason:** Mostly category (a). The destination construction, hashes
(`full_hash(full_hash(name)[:10] + identity.hash)[:16]`), proof strategy (0x23),
ALLOW_LIST(0x02) handler binding, and mgmt_destinations/mgmt_hashes tracking are
RNS-faithful. Deviations: (1) the `/status` and `/path` response generators are
stubs returning `RequestResponse.none` — remote status/path *response bodies* are
not modeled (out of scope; only registration + ACL binding round-trip). (2)
`panicOnInterfaceError` is posture-only instance state: it round-trips the config
flag but does NOT actually abort the process on a real interface error (RNS crashes
the instance). (3) These registrations are triggered explicitly by the bridge from
the captured `respond_to_probes` / `enable_remote_management` knobs rather than from
RNS's `Transport.start` / config pipeline. `transportEnabled` already defaults
false (Reticulum.py:253) — no change there.

---

## Identity/Destination ratchets + announce recall (Identity.swift, Crypto/Destination.swift, Crypto/RatchetManager.swift)

This subsystem ports RNS's received-ratchet store, known_destinations recall,
the Destination-level ratchet lifecycle, and the SINGLE auto-ratchet
encrypt/decrypt path. Most logic is byte-faithful to RNS; the deviations below
are all category (a) (value-type / actor / no-global-singleton accommodations) or
explicit feature stubs.

### Static Identity stores backed by an NSLock singleton

**Sites:** `Sources/ReticulumSwift/Crypto/Identity.swift` — `IdentityStore`
(fileprivate `@unchecked Sendable` final class), `Identity.known*`/`remember`/
`recall`/`recallAppData`/`rememberRatchet`/`getRatchet`/`cleanRatchets`/
`registerLocalDestination`/`save`/`loadKnownDestinations`/`storagePath`.

**Python reference:** `RNS/Identity.py:94-98` (class dicts `known_destinations`,
`known_ratchets` + `threading.Lock`s), `:101-265` (remember/recall/recall_app_data/
save/load), `:424-522` (_remember_ratchet/get_ratchet/_clean_ratchets/
current_ratchet_id/_get_ratchet_id/_ratchet_public_bytes).

**Reason:** Category (a). RNS keeps these as module-level mutable dicts on the
`Identity` class guarded by `threading.Lock`. Swift `Identity` is a value type, so
the process-wide mutable state cannot live on it; it lives in the `IdentityStore`
NSLock-guarded singleton, with `Identity` exposing RNS-named static methods that
delegate. `RNS.Reticulum.storagepath` (a global) becomes the settable static
`Identity.storagePath` (nil ⇒ in-memory only). `recall` skips RNS's
`_used_destination_data` LRU bookkeeping (`:135/:146`) — there is no Reticulum
instance in the library to mark usage against; the `used` element is stored as 0
and round-trips, but is not incremented. The recall Transport.destinations
fallback (`:151-159`) is served from an explicit `localDestinations` registry
(`registerLocalDestination`) the owner/bridge populates on destination
registration, because the library `Transport` is an actor that a synchronous
static `recall` cannot await.

### Identity.app_data as a stored property

**Site:** `Identity.swift` — `public var appData: Data?`.

**Python reference:** `RNS/Identity.py:138/:149/:156` (recall attaches
`identity.app_data = entry[3]`, or `None` for the local fallback).

**Reason:** Category (a). RNS dynamically attaches `app_data` to the recalled
identity object. Swift has no dynamic attributes, so it is a settable stored
property (default nil) that `recall` populates on the value-type copy it returns.

### RatchetManager factors Destination ratchet state into an actor

**Sites:** `Crypto/RatchetManager.swift` — `rotate(interval:retained:)`,
`cleanRatchets(retained:)`, `previousRatchetPublicBytes()`, `latestTime()`;
`Crypto/Destination.swift` — `rotateRatchets()`, `setRatchetInterval`,
`setRetainedRatchets`, `encrypt`, `decrypt`, `latestRatchetId`, `ratchetInterval`,
`retainedRatchets`.

**Python reference:** `RNS/Destination.py:205-241` (_clean_ratchets/rotate_ratchets),
`:466-531` (enable/enforce/set_retained/set_ratchet_interval), `:585-643`
(encrypt/decrypt). `RNS/Identity.py:865-913` (Identity.decrypt with
`ratchet_id_receiver`).

**Reason:** Category (a). RNS stores `self.ratchets` (the private key list) and
rotation timing directly on the `Destination` and mutates them under the GIL; the
swift port keeps the key list in the `RatchetManager` actor, so
`Destination.decrypt`/`rotateRatchets`/`setRetainedRatchets` are `async` (they
await the actor). `Destination.encrypt` stays synchronous — it selects via
`Identity.getRatchet(self.hash)` (the NSLock store), not the actor. The
`ratchet_id_receiver=self` pattern becomes the `RatchetIdReceiver` protocol
(`AnyObject`) that `Destination` conforms to, so `Identity.decrypt` can write
`latestRatchetId` back. `_clean_ratchets` faithfully preserves RNS's quirk: the
gate compares `len > retained_ratchets` but truncates to the static `RATCHET_COUNT`
(512), not to the retained cap (Destination.py:206-207).

### enable/rotate remember the current ratchet (announce-time effect)

**Site:** `Destination.swift` — `enableRatchets` (and conceptually the announce
path) call `Identity.rememberRatchet(self.hash, currentPub)`.

**Python reference:** `RNS/Destination.py:284-287` — RNS calls
`Identity._remember_ratchet(self.hash, ratchet)` inside `Destination.announce()`,
not in `enable_ratchets`.

**Reason:** Category (a). The swift port has no `Destination.announce()` method —
announces are assembled separately (the `Announce` type / bridge). To keep
`Destination.encrypt`'s RNS-faithful `Identity.getRatchet(self.hash)` selection
finding the destination's own current ratchet (the end state RNS reaches after its
enable→announce→remember sequence), the remember is performed at `enableRatchets`.
The end state is identical to RNS post-announce.

### validate_announce app_data None-vs-empty helper

**Site:** `Identity.swift` — `Identity.announceAppData(rawAppData:hasRatchet:)`.

**Python reference:** `RNS/Identity.py:542,560-561` (app_data starts b"", becomes
the trailing field if present, then is set to None only when the packet is not
longer than KEYSIZE+NAME_HASH+10+SIG — i.e. a ratcheted no-app_data announce keeps
b"" while a ratchetless one becomes None).

**Reason:** New feature surface (category b). RNS computes this inline in
`validate_announce`. The swift announce-reception path lives in
`Routing/AnnounceHandler.swift` + `Protocol/AnnounceValidator.swift` (outside this
subsystem's files), whose parser returns nil for any no-trailing-field announce,
losing the ratcheted-empty-vs-ratchetless-none distinction. This static helper
centralises the RNS rule so the integration site can call
`remember(... appData: Identity.announceAppData(rawAppData:hasRatchet:))`.

**Wiring (done 2026-06-15):** `AnnounceHandler.process` now calls
`Identity.remember(... appData: Identity.announceAppData(rawAppData: parsed.appData,
hasRatchet: parsed.ratchet?.isEmpty == false))`. `parsed.appData` is nil whenever the
announce carried no trailing field (AnnounceValidator.swift:329), and a ratchet adds
the 32 bytes that push the announce past the 148-byte threshold, so `hasRatchet`
faithfully reconstructs RNS's len>148 test: ratcheted-no-app_data -> b"" (empty),
ratchetless-no-app_data -> None. Fixes `test_recall_app_data_none_vs_empty` and
`test_explicit_empty_app_data_matches_omitted`.

### AnnounceHandler.process performs validate_announce's remember/ratchet side-effects

**Site:** `Routing/AnnounceHandler.swift` — `process(...)` now calls
`Identity.remember(packetHash:destinationHash:publicKey:appData:)` and
`Identity.rememberRatchet(destinationHash:ratchet:)` immediately after
`AnnounceValidator.parseAndValidate` succeeds, before `PathTable.record`.

**Python reference:** `RNS/Identity.py:591` (`Identity.remember(packet.get_hash(),
destination_hash, public_key, app_data)`) and `:612` (`if ratchet:
Identity._remember_ratchet(destination_hash, ratchet)`) — both live inside
`Identity.validate_announce`, which `RNS/Transport.py:1712` (`received_announce`)
calls before the `should_add` path-table acceptance block (Transport.py:1740+).

**Reason:** Category (a) structural split. RNS bundles the known_destinations /
known_ratchets refresh inside `validate_announce`. The swift port's
`AnnounceValidator` is a pure `Sendable` parser/signature-checker with no
`IdentityStore` access, so the remember/ratchet side-effects are performed at the
single call site (`AnnounceHandler.process`) right after validation, preserving
RNS's exact ordering: the refresh is UNCONDITIONAL and runs before — and
independent of — `PathTable.record`'s freshness/hop acceptance gate. This is what
lets a same/near-second re-announce refresh recalled app_data
(`test_reannounce_refreshes_recalled_app_data`) and replace the adopted ratchet
(`test_newer_announce_replaces_adopted_ratchet`) even when the path table rejects
the duplicate path. `app_data` is now sourced from
`Identity.announceAppData(rawAppData: parsed.appData, hasRatchet: parsed.ratchet?
.isEmpty == false)` (the None-vs-empty helper documented above), matching RNS
overwrite-in-place semantics (Identity.py:108-113) AND the validate_announce
threshold-null rule (Identity.py:542,560-561).

## Transport — best-effort outbound + synchronous inbound entry

### Graceful-shutdown link teardown: `activeLinkList()` + `Link.closeAndFlush()`

**Sites:** `Transport/ReticulumTransport.swift` — `activeLinkList() -> [Link]`;
`Link/Link.swift` — `closeAndFlush(reason:) async`.

**Python reference:** `RNS/Transport.py` `Transport.active_links` (the established-
link registry RNS's exit handler iterates) and `RNS/Link.py:694-708` (`teardown` →
`__teardown_packet`, role-derived `teardown_reason`).

**Reason:** Category (a) concurrency/observability for a process-exit teardown path.
`activeLinkList()` exposes the otherwise-private `activeLinks` map so a graceful-
shutdown caller can enumerate every established link (RNS reaches these via the
class-level `active_links`). `Link.close()`/`finishClose(emitClose:true)` detaches
the LINKCLOSE send in a `Task { try? await send(...) }` so callers aren't blocked;
that detached task does NOT run if the process exits immediately afterwards (e.g. the
conformance bridge hitting stdin EOF), so the peer never sees the close and falls
back to a watchdog TIMEOUT instead of DESTINATION_CLOSED. `closeAndFlush()` builds +
encrypts the SAME LINKCLOSE frame `finishClose` would (RNS `__teardown_packet`,
Link.py:694-697), `await`s its delivery inline, then runs the shared teardown with
`emitClose:false` so the packet is sent exactly once. The local teardown reason is
derived from role exactly like RNS `teardown()` (Link.py:706-707): initiator ⇒
INITIATOR_CLOSED, responder ⇒ DESTINATION_CLOSED (overridable). Both are additive —
the existing `close()`/`finishClose` paths are unchanged, so the 454-suite is
unaffected. The bridge process-exit handler that calls these (main.swift EOF path) is
the complementary bridge-layer step.

### Outbound send paths are best-effort (no spurious noInterfacesAvailable)

**Sites:** `Transport/ReticulumTransport.swift` —
- `send(packet:)` empty-interfaces guard (was `throw .noInterfacesAvailable`,
  now logs and returns).
- `sendToAllInterfaces(_:)` zero-success branch.
- `sendRawBytes(_:interfaceId:)` zero-success branch.

**Python reference:** `RNS/Transport.py:1090-1326` — `Transport.outbound`
iterates every OUT interface, calls `Transport.transmit`, and returns a plain
`sent` boolean (`return sent` at the tail). It NEVER raises. `Transport.transmit`
(:1050-1087) wraps `interface.process_outgoing` in `try/except` and only logs on
error. There is no peer-connected gate — an interface with no connected peer is
still attempted, and zero successes simply yields `sent == False`.

**Reason:** Bug fix toward RNS fidelity (the previous throw was the divergence).
The port was raising `TransportError.noInterfacesAvailable` whenever the connected-
interface loop produced zero successes (no interface registered yet, or all
registered interfaces not `.connected`). That made announce/transmit *fail* when a
send was issued before a peer connected — e.g. a TCP server whose interface map is
momentarily empty/racing. RNS treats this as a normal best-effort no-op. The three
sites now log and return instead of throwing `noInterfacesAvailable`.

**Retained conservative deviation:** when a *genuine* per-interface send error
occurred (`lastError != nil`, i.e. an interface's `send` actually threw),
`sendToAllInterfaces`/`sendRawBytes` still `throw .sendFailed(...)`. Strict RNS
swallows even this (the `transmit` try/except). The port keeps surfacing a real
transmit failure so Columba call sites are not silently blinded to an actual I/O
error — this is an additive safety deviation that does NOT affect the
no-peer/empty case the fix targets. `sendLinkData(packet:)` deliberately STILL
throws `.noInterfacesAvailable` on a truly empty interface map: that is a
separate, test-pinned Columba protection (`LinkDataSendTests
.testSendLinkDataThrowsWhenNoInterfaces`) preventing "state=SENT but never
delivered" link-DATA regressions, and is left unchanged.

### Transport.inbound(frame:interface:) — synchronous public inbound entry

**Site:** `Transport/ReticulumTransport.swift` — new
`public func inbound(frame:interface:) async -> Bool`.

**Python reference:** `RNS/Transport.py:1387-1447` — `Transport.inbound(raw,
interface)` runs the short-packet guard (`if len(raw) > 2: ... else: return`,
:1397) and the IFAC pre-unpack guards (flag-on-open / flag-missing / min-length /
IFAC-mismatch drops) before unpacking.

**Reason:** Category (a) + observability. The existing delegate sink
`handleReceivedData(data:from:)` runs the identical IFAC validation + parse but
dispatches `receive` on a detached `Task` (fire-and-forget), which forces callers
to sleep-and-poll for results. `inbound` mirrors RNS's entry name/semantics and
additionally `await`s `receive` to completion so an injector (e.g. the conformance
bridge raw-frame path) gets a deterministic learned-result and returns a `Bool`
indicating the frame passed IFAC + parsed (vs a pre-unpack drop). The IFAC unmask
math itself lives in the existing `validateIFAC`/`applyIFAC`
(RNS/Transport.py:1398-1447 / :1050-1080); the `frame.count > 2` short-packet
guard is added in `inbound` because `validateIFAC` only enforces the
`>2+ifac_size` min-length on the IFAC-configured path, not RNS's top-level
`len(raw) > 2` gate for the IFAC-less path.

### Per-transport implicit/explicit single-packet PROOF policy

**Sites:** `Transport/ReticulumTransport.swift` — `_useImplicitProof` (stored),
`shouldUseImplicitProof()`, `setUseImplicitProof(_:)`, and the SINGLE-destination
opportunistic prove branch in `handleRegularData` (proof-data implicit/explicit
selection).

**Python reference:** `RNS/Identity.py:959-970` (`Identity.prove`: signs the FULL
`packet.packet_hash`; `proof_data = signature` when implicit, else
`packet.packet_hash + signature`); `RNS/Reticulum.py:256` (default `True`),
`:555-558` (config knob), `:1699-1705` (`should_use_implicit_proof()`).

**Reason:** Category (a) — language/runtime. RNS stores the implicit-proof flag as
a **process-global** class attribute (`Reticulum.__use_implicit_proof`). The swift
port hosts MULTIPLE concurrent transports/wire-peers in one process (e.g. the
conformance bridge), so a process-global would let peers cross-contaminate each
other's proof policy. The flag is therefore scoped **per-transport**. The emitted
bytes are byte-identical to RNS: implicit ⇒ `sign(getFullHash())` (64 B); explicit
⇒ `getFullHash() || sign(getFullHash())` (96 B), signing the FULL (not truncated)
hash. Default remains `true` (RNS parity). The previous prove path hardcoded the
64-byte implicit form; honoring the policy is additive (default unchanged).

### `ReticulumTransport` proof-carrying delivery-receipt callback overloads

**Sites:** `Transport/ReticulumTransport.swift` — `ReceivedProofPacket` struct,
`registerReceipt(hash:timeout:proofCallback:)`,
`send(packet:proofReceiptCallback:receiptTimeout:)`, the `receipts` storage type
(callback now `(ReceivedProofPacket?) async -> Void`), and the proof-dispatch site
that populates `ReceivedProofPacket(data: packet.data, raw: packet.encode())`.

**Python reference:** `RNS/Packet.py:498-537` (`PacketReceipt.validate_proof`
stashes the matched PROOF packet as `receipt.proof_packet`, whose `.data` is the
proof payload and `.raw` the full encoded proof packet); `RNS/Transport.py:2155-2165`
(proof routed to the receipt).

**Reason:** Category (a) — language/runtime / observability. The existing swift
delivery-receipt callback is `() async -> Void` and discards the received PROOF
packet's bytes, so a caller cannot read `proof_data`/`proof_raw` to classify
IMPLICIT (64 B) vs EXPLICIT (96 B). The proof-carrying overloads surface those
bytes ADDITIVELY: the legacy `() async -> Void` `registerReceipt`/`send` overloads
are retained and wrap onto the same storage (discarding the proof), so existing
Columba/LXMFSwift delivery-receipt call sites are byte-for-byte unchanged.

### `Link.setInboundPacketObserver(_:)` — per-link inbound packet observation hook

**Sites:** `Link/Link.swift` — `inboundPacketObserver` (stored),
`setInboundPacketObserver(_:)`, and its invocation in `handleResponsePacket`
(RESPONSE 0x0A) and `handleResourcePacket` (RESOURCE_ADV 0x02).

**Python reference:** `RNS/Link.py:897-901` — `Link.receive` routes a sub-MDU
handler response as a single RESPONSE (0x0A) packet vs forking a >MDU response into
a response Resource (observable as a RESOURCE_ADV 0x02); `RNS/Packet.py` context
bytes 0x0A/0x02.

**Reason:** Category (b) — new instrumentation feature. RNS routes inbound RESPONSE
/ RESOURCE_ADV frames through `Link.receive` with no app-visible wrap point. The
hook exposes each observed inbound frame's wire context byte + decrypted plaintext
so a conformance/instrumentation consumer can assert the sub-MDU-vs-Resource fork
and the RESPONSE msgpack `[request_id, response]` layout. It is a no-op when unset
and runs before dispatch WITHOUT altering routing, ordering, or timing.

### `RatchetManager` public persist/reload wrappers + ratchet-inflate instrument

**Sites:** `Crypto/RatchetManager.swift` — `persistRatchets()`, `reloadRatchets()`
(public wrappers over the private `persist()`/`load()`), `_padRatchets(to:)`.

**Python reference:** `RNS/Destination.py:210-225` (`_persist_ratchets`: signed
`msgpack({"signature": sign(packed), "ratchets": packed})`), `:426-464`
(`_reload_ratchets`: signature-validated reload, raises on bad signature),
`:205-208`/`:504-517` (`_clean_ratchets` / `set_retained_ratchets` pad+truncate;
`_generate_ratchet()`).

**Reason:** `persistRatchets()`/`reloadRatchets()` are category (a) —
encapsulation: RNS exposes `Destination.ratchets` as a plain attribute and calls
`_persist_ratchets`/`_reload_ratchets` directly; the swift `persist()`/`load()` are
private, so public wrappers let an instrument drive a REAL signed write +
signature-validated reload. Semantics are unchanged (reload throws on bad
signature; the in-memory list is replaced byte-for-byte; `latestRatchetTime` is
left untouched, matching RNS `_reload_ratchets`). `_padRatchets(to:)` is category
(b) — instrument-only: it appends freshly generated ratchets (mirroring repeated
`Identity._generate_ratchet()`) to inflate the in-memory list PAST the retained cap
so `cleanRatchets` truncation to `RATCHET_COUNT` (512) is observable; it appends at
the END so the current (index-0) ratchet is preserved, and is not part of RNS's
runtime path.

### RNS.Discovery subsystem port (interface auto-discovery)

**Sites:** `Sources/ReticulumSwift/Discovery/` — `DiscoveryConstants.swift`,
`DiscoveryAddress.swift`, `DiscoveryStamp.swift`, `DiscoveredInterface.swift`,
`InterfaceAnnouncer.swift`, `InterfaceAnnounceHandler.swift`,
`InterfaceDiscovery.swift`. Bridge wiring: `Sources/ConformanceBridge/Ext+Discovery.swift`.

**Python reference:** `RNS/Discovery.py` (InterfaceAnnouncer
`get_interface_announce_data`:96-186 / identity selection:54-58; InterfaceAnnounceHandler
`sanitize_name`:205-212 / `received_announce`:214-362; InterfaceDiscovery
`interface_discovered`:450-505 / `list_discovered_interfaces`:402-448; address
grammar:769-790; constants:12-38,189-190,365-377). The msgpack info-map key
numbering, flag bits, STAMP_SIZE, work-block expansion rounds, hostname grammar
and per-type `config_entry` format strings are ported byte/string-for-byte.

The autoconnect / monitor / teardown / `BlackholeUpdater` halves of Discovery.py
(Transport interface lifecycle, `BackboneClientInterface`, the daemon `job()`
announce loop) are intentionally OUT OF SCOPE and not ported.

The following category-(a)/(b) deviations are documented:

1. **LXStamper PoW inlined (forced).** RNS imports the proof-of-work from
   `LXMF.LXStamper` (`stamp_workblock`/`stamp_value`/`stamp_valid`/`generate_stamp`,
   used at Discovery.py:172,235-237). reticulum-swift has NO LXMF dependency, so
   `DiscoveryStamp` inlines the PoW on the library's own primitives
   (`KeyDerivation.deriveKey` == HKDF, `Hashing.fullHash` == SHA-256,
   `packMsgPack(.uint(round))` == msgpack salt). Wire-identical: the work-block is
   the concat of 20 HKDF(256B) expansions salted with SHA-256(material||msgpack(round)),
   the value is the leading-zero-bit count of SHA-256(workblock||stamp), validity is
   the 256-bit `<= 2^(256-cost)` compare. Ref: LXMF/LXStamper.py.

2. **Record dict -> typed struct (category a).** RNS models the discovered-interface
   record as a dynamic dict whose key set varies by interface type (Discovery.py:263-357).
   `DiscoveredInterface` is a Swift struct with typed core fields plus per-type
   optionals; `toDictionary()` OMITS nil keys so the projection mirrors RNS's
   per-type-varying dict (a Weave record carries no `sf`/`cr`, a Backbone record no
   radio keys) — satisfying the receiver-info negative assertions.

3. **In-memory record store (category a).** RNS persists one msgpack file per
   `discovery_hash` under `Reticulum.storagepath/discovery/interfaces`
   (Discovery.py:394-395,459-495). `InterfaceDiscovery` uses an in-memory
   `[Data: DiscoveredInterface]` keyed by `discovery_hash` with the identical
   one-record-per-hash dedup / heard_count / list-time purge semantics, avoiding
   iOS-sandbox filesystem coupling. The store is reset per inject/store invocation.
   Cross-launch persistence is deferred (not needed for conformance; may matter for
   Columba UX later — see open risks).

4. **Feature-default gates as spec literals (forced).** `DiscoveryFeatureDefaults`
   surfaces the opt-in gates (Interface.py:105-106 `discoverable`/`supports_discovery`;
   Reticulum.py:259-260,1802-1807 `discover_interfaces` /
   `should_autoconnect_discovered_interfaces()` / `max_autoconnected_interfaces()`)
   as their RNS spec-literal defaults (all OFF), because reticulum-swift models no
   Reticulum config object nor per-Interface discovery flags to read live state from.
   A future genuinely-configurable discovery toggle would need a real config source.

5. **`hops` injectable constant (category a).** RNS reads `Transport.hops_to(dest)`
   in `received_announce` (Discovery.py:271). The conformance/library context has no
   live Transport path table, so `InterfaceAnnounceHandler.hops` is an injectable
   constant (default 0); the receive path still emits an int, as RNS does.

**Build/verification:** `swift build -c release` clean; the 454-test ReticulumSwift
regression suite passes 0 failures with these additions.

### Resource part-split SDU = link.mtu - 36 (cluster-C/D interop fix, 2026-06-15)

**Bug fix, not a deviation — restores RNS fidelity.** `Link.sendResource`
(Link.swift:~1748) previously sized outbound resource parts at `self.mdu` (the
link-*encrypted* MDU, 431 @ MTU 500). RNS sizes resource parts at the resource
SDU = `self.link.mtu - Reticulum.HEADER_MAXSIZE - Reticulum.IFAC_MIN_SIZE`
(RNS/Resource.py:338), i.e. `mtu - 35 - 1 = mtu - 36 = 464 @ MTU 500`. Resource
data parts (context 0x01) are sent UNENCRYPTED at the link layer — the Resource
pre-encrypts the whole stream once (RNS/Resource.py:~430) — so they ride the
larger Reticulum-level MDU, not the smaller link MDU. The python receiver IGNORES
the advertised part count and re-derives `total_parts = ceil(size/sdu)` from its
OWN sdu=464 (RNS/Resource.py:187), so a swift sender splitting at 431 advertised
~115 parts where the python receiver allocated a 106-slot hashmap; `hashmap_update`
then IndexErrored on the surplus parts ("Could not decode... dropping resource")
and the transfer never completed. swift<->swift only "worked" because both ends
agreed on the wrong 431. Now `partSize = self.mtu - 35 - TransportConstants.IFAC_MIN_SIZE`
and it propagates to child segments via `Resource.prepareNextSegment`
(Resource.swift:1362, which reuses the parent's stored `partSize`).
Ref: RNS/Resource.py:338 (sdu), :187 (receiver total_parts), :432/:454 (sender
split at sdu). HEADER_MAXSIZE=2+1+(128//8)*2=35 (RNS/Reticulum.py:147),
IFAC_MIN_SIZE=1 (:148).

**Port-structure note (category a):** RNS computes `self.sdu` inside
`Resource.__init__`; this port computes the equivalent value in `Link.sendResource`
and threads it through `Resource.prepare(partSize:)`. Same value, different
ownership boundary (the Swift `Resource` takes `partSize` as a construction param
rather than reading `link.mtu` directly). No behavioral divergence.

**Three sizes deliberately NOT conflated (decision record):** This fix touches ONLY
the part-split SDU. Two adjacent sizes intentionally stay put because RNS keeps them
distinct:
  1. **Part-split SDU** = `link.mtu - 36` — the FIXED value above (Resource part data).
  2. **Link MDU** = 431 @ MTU 500 (`self.mdu`) — used ONLY as the >MDU request/response
     fork THRESHOLD (`Link+Request.swift:82,220`, RNS/Link.py:496/898). Correctly
     stays `self.mdu`.
  3. **HASHMAP_MAX_LEN cap** = `hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)` = 74,
     the per-segment hashmap-chunk cap (advertisement + HMU). RNS derives this from
     the **class constant** `RNS.Link.MDU` (=431), NOT the per-link negotiated mdu:
     `ResourceAdvertisement.HASHMAP_MAX_LEN = floor((RNS.Link.MDU - 134)/4) = 74`
     (RNS/Resource.py:1236). It is therefore a fixed 74 at every negotiated MTU.
     A sibling diagnosis suggested re-pointing the advertisement/HMU `linkMDU:`
     params (Link.swift:1568/1760/2130/2139/2143/2487, Resource.swift sendHashmapUpdate)
     to `self.mdu` for "high-MTU fidelity" — that would DIVERGE from RNS (which uses
     the class constant), so it was deliberately NOT done. These params stay
     `LinkConstants.LINK_MDU`.

**`deriveReceiverPartCount` guidance corrected (Resource.swift:~2493):** the
docstring previously said the Link should call it "with `self.mdu`". Corrected to
`self.mtu - 36` (the resource SDU) — passing `self.mdu` would re-derive a smaller
sdu than a correct sender splits at and over-count parts. The method stays UNWIRED
(the receiver keys `numParts` off the advertised `n` at init, which is exactly right
once the sender splits at mtu-36). RNS/Resource.py:187.

**Build/verification:** `swift build -c release` clean. Fixes (swift-sender arm):
test_hmu_handshake_over_small_mtu_link, test_metadata_x_flag_round_trip,
test_multi_segment_transfer_reassembles_byte_exact,
test_three_segment_transfer_reassembles_byte_exact (cluster D), and the response-
Resource completion for test_link_request_large_response_round_trips_as_resource /
test_large_response_forks_to_resource_not_response_packet (cluster C). Clean-disconnect
DESTINATION_CLOSED (test_clean_peer_disconnect) relies on the already-present
`Link.closeAndFlush()` (Link.swift:1348, gated on state.isEstablished) plus the
bridge exit handler + `Transport.activeLinkList()` (sibling-owned).

## Announce: dispatch subsystem + replay-gate alignment (cluster A/B, 2026-06-15)

### Removed non-RNS `AnnounceHandler.seenAnnounces` per-announce-hash dedup

**Site:** `Routing/AnnounceHandler.swift` — deleted the `seenAnnounces: Set<Data>`
field, its `seenAnnouncesMaxSize` cap, the `computeAnnounceHash`/`addToSeenAnnounces`
helpers, the top-of-`process` early-return, the add-on-reject/add-on-accept call
sites, and the `seenCount`/`hasSeen`/`clearSeen` test hooks.

**Python reference:** `RNS/Transport.py:1687-1823` — RNS re-processes EVERY
signature-valid announce. There is no per-announce-hash dedup set; replay/loop
forging is prevented SOLELY by the random_blob membership test inside the path-table
decision (`if not random_blob in random_blobs`, Transport.py:1763/1796/1808). SINGLE
announces are also explicitly exempted from the packet-hashlist filter
(Transport.py:1376-1378).

**Reason:** Bug fix — the `seenAnnounces` set was a category-(b)-style addition with
NO RNS counterpart, and it over-deduped: a re-heard byte-identical announce was
dropped at the top of `process` before reaching `PathTable.record`, so the
expired-path (Transport.py:1790-1801) and equal-emission-unresponsive
(Transport.py:1818-1823) replacement branches could never run on a repeat sighting.
Removing it makes replay protection RNS-exact (the random_blob check in
`PathTable.record` is the sole gate) and fixes
`test_path_replace_expired_path_larger_hops` and
`test_path_replace_equal_emission_unresponsive`. Verified non-regressing:
`test_announce_random_blob_replay_is_rejected` stays green (a re-heard identical blob
is `isNewBlob==false` -> `record` returns false -> `.ignored`, no announce_table
churn), and `test_duplicate_single_announce_is_not_deduplicated` is a `packet_filter`
test unaffected by this layer. As a side effect `Identity.remember`/`rememberRatchet`
now run on every re-heard announce (previously short-circuited) — this is MORE
RNS-faithful (`validate_announce` runs unconditionally) and idempotent (overwrite in
place, Identity.py:108-113).

### External announce-handler dispatch subsystem (`AnnounceHandlerProtocol` + dispatch loop)

**Site:** `Routing/AnnounceHandler.swift` — new public protocol
`AnnounceHandlerProtocol` (AnyObject, Sendable). `Transport/ReticulumTransport.swift`
— new `announceHandlers` registry, `registerAnnounceHandler(_:) -> Bool`,
`deregisterAnnounceHandler(_:)`, `announceHandlerCount`, the
`dispatchAnnounceToHandlers(packet:destinationHash:)` loop, and the
`announceHandlerExpectedHash(aspectFilter:identity:)` helper. Dispatch is invoked
from `processAnnounce` in BOTH the `.recorded` and `.recordedAndRebroadcast` result
arms (== RNS `should_add==True`), BEFORE/outside the `if transportEnabled || isLocal`
rebroadcast block, passing the ORIGINAL packet.

**Python reference:** `RNS/Transport.py:2034-2086` (the dispatch loop nested inside
`if should_add:`, which sits inside `if local_destination == None and
validate_announce(packet):` — i.e. it runs for every accepted announce regardless of
`transport_enabled`), `:2465-2477` (`register_announce_handler`: guard on
`hasattr(handler, "aspect_filter")`), `:2481-2489` (`deregister_announce_handler`),
`RNS/Destination.py:139-148` (`hash_from_name_and_identity` / `app_and_aspects_from_name`).

**Reason:** Genuinely-missing behavior (category b, new subsystem). The port had only
the fixed internal `AnnounceHandler` actor (dedup/validate/record-path) and NO
externally-registered handler registry or dispatch loop, so apps (LXMF registers
`lxmf.delivery` + `lxmf.propagation` handlers) were never notified. The loop mirrors
RNS exactly: aspect_filter `nil` matches all else compares
`Destination.hash(identity, app, *aspects) == destination_hash`; the PATH_RESPONSE
delivery gate (`packet.context==PATH_RESPONSE` delivered only to
`receivePathResponses` handlers); the recalled `announced_identity`/`app_data` come
from the process-global `known_destinations` populated by `process`'s unconditional
`remember`; `announce_packet_hash == packet.getFullHash()`.

**Forced deviations within this subsystem (category a):**
  1. **Explicit `callbackParameterCount`.** RNS selects 3/4/5-arg delivery via
     `len(inspect.signature(handler.received_announce).parameters)` (Transport.py:
     2055/2063/2071). Swift cannot introspect a closure's arity, so the handler
     declares its arity explicitly; the single protocol method
     `receivedAnnounce(...)` always takes all params and the dispatch passes nil for
     `announcePacketHash` (arity 3) and `isPathResponse` (arity 3/4). Semantically
     identical.
  2. **Throwing protocol method for per-handler exception isolation.** RNS wraps each
     callback in try/except (Transport.py:2083-2086); the swift dispatch wraps each
     `receivedAnnounce` call in do/catch (a raising handler is logged and cannot block
     a later handler).
  3. **Synchronous in-actor delivery.** RNS spawns a daemon `threading.Thread` per
     delivery (Transport.py:2057 etc.); the swift dispatch records synchronously
     inside the Transport actor. Observably equivalent and race-free for the
     poll-based conformance tests; avoids leaking detached Tasks.
  4. **`hasAspectFilter` models `hasattr`.** RNS's registration guard is
     `hasattr(handler, "aspect_filter")` (a handler with NO aspect_filter attribute is
     silently not registered). Swift has no dynamic attribute test, so the protocol
     exposes `hasAspectFilter` (distinct from `aspectFilter == nil`, which means
     "match all"). `registerAnnounceHandler` returns the registered Bool.

Fixes `test_aspect_filter_none_matches_all`, `test_aspect_filter_match_and_mismatch`,
`test_path_response_delivery_gate`, `test_callback_arity_packet_hash`,
`test_registration_guard_and_exception_isolation`.

### `Transport.packetHashlistCount()` / `packetHashlistContains(_:)` accessors

**Site:** `Transport/ReticulumTransport.swift`.

**Python reference:** `RNS/Transport.py:1469-1480` (`add_packet_hash` /
`packet_hashlist` membership) — RNS exposes `Transport.packet_hashlist` as a plain
list attribute.

**Reason:** Category (a) observability. The swift `PacketHashlist` actor is held
privately; these async accessors surface the count and membership so the conformance
bridge can prove an inbound frame was accepted+recorded (count delta) for the inbound
IFAC-gate tests. No behavioral change. `PacketHashlist.count`/`shouldAccept` were
already public; only the actor-held instance was internal.

### `Transport.linkTableSnapshot()` / `seedLinkTableEntry(key:entry:)` / `reverseTableSnapshot()` / `seedReverseTableEntry(key:entry:)` accessors

**Site:** `Transport/ReticulumTransport+Transport.swift` (after `cullTransportTables()`).

**Python reference:** `RNS/Transport.py` `link_table` / `reverse_table` are plain dict
attributes mutated/read directly (under `link_table_lock` / `reverse_table_lock`) by the
forwarding paths and, in the conformance harness, by
`reference/behavioral_transport.py` `cmd_behavioral_seed_link_table` /
`_seed_reverse_table` (`RNS.Transport.link_table[dest] = link_entry`) and
`_read_link_table` / `_read_reverse_table` (`table.items()` iteration).

**Reason:** Category (a) language/runtime. The swift `linkTable` / `reverseTable` are
actor-isolated `var`s on `ReticulumTransport`; an out-of-module caller (the bridge)
cannot do python's direct `Transport.link_table[key] = entry` / `dict.items()` across the
actor boundary. These four accessors are the actor-isolation-required equivalent of that
direct dict access — pure seed mutators + value-copy snapshots over the *same* tables the
production inbound-deferral / hop-count gate / PROOF return-routing / cull already use.
No routing behavior is added. Mirrors the existing `packetHashlistCount()` /
`getPathTable()` accessor precedent. Wires `behavioral_seed_link_table` /
`behavioral_read_link_table` / `behavioral_seed_reverse_table` /
`behavioral_read_reverse_table` to the real tables (previously LIBRARY-GAP shadows/no-ops).

### `AnnounceTable.entryPacketHash(_:)` accessor

**Site:** `Transport/AnnounceTable.swift` (additive accessor mirroring the existing
`entryTimestamp` precedent; outside cluster A's named 4-file set but required by the
cluster-A bridge observable — see scope note in the agent report).

**Python reference:** `RNS/Transport.py:3559-3567` — the announce_table entry stores
the packet whose `.packet_hash` the cross-check reads.

**Reason:** Category (a) observability. Returns the stored entry packet's
`getFullHash()`. The stored packet is the rebroadcast packet (hops+1) but
`Packet.getHashablePart` excludes the hop byte, so its hash equals the dispatched
original announce's packet hash — the equality `test_callback_arity_packet_hash`
cross-checks. No behavioral change.

### `ReticulumTransport.detachInterfaces()` — link-teardown + 150ms drain prefix only (fix/conformance-endpoint-resolve 2026-06-16)

**Site:** `Transport/ReticulumTransport.swift` (new `public func detachInterfaces() async`);
called from the conformance bridge's stdin-EOF shutdown handler
(`Sources/ConformanceBridge/main.swift`).

**Python reference:** `RNS/Transport.py:3076-3088` (`detach_interfaces`: tear down every
`active_links` then `pending_links` via `link.teardown()`, counting `closed_links`, then
`if closed_links: time.sleep(0.15)` — a 150ms window so the LINKCLOSE teardown packets
leave local transport). The full python method continues at `:3090-` to enumerate and
socket-`detach()` every interface / local_client_interface on RNS teardown.

**Reason:** Category (a) language/runtime + scoped role. The swift port reproduces the
link-teardown + 150ms-drain prefix faithfully (active links first, then pending; the 150ms
value is RNS's exact constant — not enlarged), using `Link.closeAndFlush()` as the swift
analog of `link.teardown()` (it emits the CONTEXT_LINKCLOSE packet and `await`s the
`NWConnection` send). It intentionally **omits** the subsequent interface socket-detach loop
(`Transport.py:3090+`): in the swift port a connection's socket lifecycle is owned by its
`NWConnection` and is closed when the bridge process exits, and there is no
`Interface.detach()` threading model to mirror here. The method's role is specifically to
flush in-flight LINKCLOSE bytes before process exit so a peer records `DESTINATION_CLOSED`
rather than a watchdog `TIMEOUT`
(`test_clean_peer_disconnect_closes_destination_closed`), not to perform a full RNS
interface teardown. A genuinely SIGKILL'd peer still yields `TIMEOUT` (the drain only runs
on the graceful stdin-EOF path).

### `fireResourceConcludedOnce` — centralized once-per-resource app callback (fix/conformance-greploop 2026-06-18)

**Site:** `Link/Link.swift` (`firedResourceConclusions: Set<Data>` + `fireResourceConcludedOnce(_:)`);
every app-facing conclusion site routes through it (inbound handlers cancel/reject/data/proof,
the outbound segment chain, `drainOutgoingQueue`, and `finishClose`'s cancel-on-close Task).

**Python reference:** `RNS/Resource.py:738` / `:792` — RNS fires the resource's `self.callback(self)`
EXACTLY ONCE per resource, from synchronous code.

**Reason:** Category (a) language/runtime concurrency. This actor port concludes the same resource from
several racing paths, and the `await resource.hash` suspension between matching a resource and firing
its callback lets two of them interleave — most reachably `finishClose`'s detached cancel-on-close Task
vs. an inbound handler on an overlapping BLE teardown — double-firing the app callback (which the LXMF
layer is not required to tolerate). RNS has no such race (synchronous, single conclusion site per path).
The fix ENFORCES RNS's once-per-resource invariant rather than diverging from it: dedup on the resource
hash via a per-link `Set`; `Set.insert` is synchronous, so even when both racers pass the preceding
`await`, exactly one observes `inserted == true` and fires. The set is bounded by the link's lifetime
resource count and freed on dealloc. Supersedes the earlier per-site `removeValue != nil` double-fire
guards (those remain for cleanup/queue-drain ownership, which fire-once does not dedup).

### Wire-input hardening — reject hostile msgpack/sizes that would trap (fix/proactive-bugclass-audit 2026-06-18)

**Sites:** `Resource/ResourceAdvertisement.swift` (`unpack` getInt → `Int(exactly:)`, flags →
`UInt8(exactly:)`), `Link/Link.swift` (`receiveResourceAdvertisement` numParts range-drop +
`Resource.init(advertisement:)` `max(0, numParts)` clamp), `Protocol/MessagePack.swift`
(`decodeArray`/`decodeMap` `reserveCapacity` bounded by remaining bytes).

**Python reference:** `RNS/vendor/umsgpack.py` (no pre-allocation; unbounded python ints) and
`RNS/Resource.py` accept path (derives part count, wraps decode in try/except → log + drop).

**Reason:** Category (a) language/runtime safety. Python ints are unbounded and its lists are lazy,
so a hostile RESOURCE_ADV / msgpack payload is at worst a caught exception. In Swift the same values
are UNCATCHABLE traps: `Int(uint64 > Int64.max)`, `UInt8(>255)`, `Array(repeating:count: <0)` (a
fatalError), and eager `reserveCapacity(2^32-1)` (allocation abort) — three of them are single-packet
remote process-aborts from any authenticated peer, reachable even on a `resourceStrategy=.acceptNone`
node. The fixes make hostile input a clean decode-failure / dropped-advertisement (mirroring RNS's
graceful drop) and are NO-OPS for every valid value, so behaviour matches RNS for all reachable
non-malicious inputs. Found by a proactive bug-class sweep, not by a reviewer.

### `Channel` receive buffer — sequence-keyed dictionary vs RNS sorted rx_ring deque (fix/conformance-failures 2026-06-23)

**Site:** `Channel/Channel.swift` — `Channel.inboundBuffer: [UInt16: Envelope]`, `Channel.receive(data:)`
(emplace + contiguous-drain), `Channel.rxRingDepth`.

**Python reference:** `RNS/Channel.py:392-413` (`_emplace_envelope` — sorted-deque insertion with the
half-space modular ordering check) and `:447-466` (`_receive` contiguous-run drain that scans the
ordered `rx_ring` deque once per receive).

**Reason:** Category (a) language/runtime data-structure choice. RNS keeps received out-of-order
envelopes in a `collections.deque` kept in ascending sequence order (with a half-space wrap check so a
numerically-smaller wrapped-forward sequence is appended rather than inserted early), then drains the
contiguous run by scanning that ordered deque. This port stores the same envelopes in a dictionary
keyed by sequence and drains the contiguous run by looking up the next expected sequence directly
(`removeValue(forKey: rxSequence)` in a wrapping-increment loop). The observable behaviour is
identical — keep-first de-duplication (a key already present is not overwritten, mirroring
`_emplace_envelope` returning `False`), in-order contiguous delivery, and correct 0xFFFF->0 wrap — but
the explicit deque ordering / half-space insertion positioning is unnecessary because exact-key lookup
does not depend on iteration order. The stale-drop window (`Channel.py:431-439`, WINDOW_MAX=48) and the
unpack-before-advance MSGTYPE gate (`Channel.py:429`/`468-469`) are mirrored exactly. `rxRingDepth`
reports `inboundBuffer.count`, equivalent to RNS's `len(rx_ring)`.

**Added defensive forward-window bound (greploop hardening 2026-06-24).** RNS's `_rx_ring`
(`Channel.py:290`) is an unbounded `collections.deque` — the stale-drop only rejects sequences BEHIND
`next_rx_sequence`; FORWARD emplacement (`sequence >= next_rx`) is uncapped, so a peer ignoring the
flow-control window could grow the ring up to `SEQ_MODULUS` (64Ki) undelivered messages. `receive(data:)`
now drops any sequence whose mod-2^16 forward distance from `rxSequence` exceeds `WINDOW_MAX_FAST` (48),
bounding the buffer to ≤49 entries. This is interop-safe: a conformant sender never has more than
`window_max` (≤ `WINDOW_MAX_FAST`) envelopes outstanding, so its furthest in-flight sequence is below
`next_rx + WINDOW_MAX_FAST` and is never rejected. The drop threshold uses the SAME inclusive boundary as
the wrapped stale-drop branch above (keep distance ≤ 48, drop > 48), so the two checks agree at the edge.
Category (a)-adjacent hardening: a bound RNS lacks, but a no-op for every sequence a reference RNS peer
can emit.

### `Channel` TX reliability layer — outlet split + transport proof-hook injection (fix/conformance-failures 2026-06-23)

**Sites:** `Channel/Channel.swift` (`TxEnvelope`, `performSend`, `sendTracked`, `sendStream`,
`packetDelivered`, `packetTimeout`, `armTimeout`, `awaitEnvelope`, `shutdownInternal`,
`initializeProfileIfNeeded`); `Link/Link+Channel.swift` (`channelBuildPacket`, `channelTransmit`,
`channelRegisterDelivery`/`channelDeregisterDelivery`, `channelOutletTimedOut`, `channelOutletMdu`/
`channelOutletRtt`); `Link/Link.swift` (`channelProofRegistrar`/`channelProofDeregistrar` +
`setChannelProofHooks`); `Transport/ReticulumTransport.swift` (both `setSendCallback` sites also call
`setChannelProofHooks`).

**Python reference:** `RNS/Channel.py:471-625` (`is_ready_to_send`, `_packet_tx_op`, `_packet_timeout`,
`send`), `:375-390` (`_shutdown`/`_clear_rings`), `:296-308` (window profile), and `:658-740`
(`LinkChannelOutlet`). RNS's `LinkChannelOutlet` holds a direct reference to the `Link`, and
`Packet.send()` registers a `PacketReceipt` with `Transport` SYNCHRONOUSLY, so the returning PROOF
resolves the receipt's delivery/timeout callbacks (`RNS/Packet.py`, `RNS/Transport.py`).

**Reason:** Category (a) language/runtime (actor isolation + per-message encryption). Three structural
adaptations, all observably equivalent:
  1. **Build/transmit split.** RNS packs the CHANNEL `Packet` ONCE (encryption done once) and
     `resend()` re-transmits the same bytes, so the packet hash (the outlet packet id the receipt is
     keyed on) is stable across tries. Swift's `encrypt` uses a fresh random IV per call, so the outlet
     is split into `channelBuildPacket` (encrypt+encode ONCE, returns wire bytes + full hash) and
     `channelTransmit` (re-send the stored bytes). This reproduces RNS's stable-hash retransmission.
  2. **Proof-hook injection.** The `Channel` actor cannot synchronously reach the transport's
     receipt table the way RNS's outlet reaches `Transport`. Instead the transport injects two closures
     (`setChannelProofHooks`) at the same point it wires `sendCallback`; the channel registers a
     delivery callback keyed by the sent packet's truncated hash BEFORE transmitting (race-free, exactly
     as RNS registers the receipt inside `Packet.send()` before the PROOF can return). The transport's
     existing `handleDataProof` matches the inbound PROOF's leading packet hash against this
     registration — the same resolution RNS performs via `PacketReceipt`.
  3. **Timer/await model.** RNS drives retransmission off `PacketReceipt` timeout callbacks on a
     background thread; the port uses per-envelope `Task.sleep` timers and a `CheckedContinuation` so a
     caller (the conformance bridge) can await an envelope's delivery/teardown. The window growth/shrink,
     `pow(1.5,tries-1)` backoff, `_max_tries=5` teardown, medium/fast rate-round promotion, ME_TOO_BIG /
     ME_LINK_NOT_READY / sequence-reservation rollback, and `_shutdown` ring+handler clearing all mirror
     `Channel.py` line-for-line. The one-time window-profile realization (`initializeProfileIfNeeded`)
     happens on first send/window-read instead of in `__init__` because the actor cannot read the link
     RTT synchronously at construction; the stored defaults already equal the non-degenerate profile, so
     the only observable effect is the degenerate (RTT>RTT_SLOW) downgrade, applied before the first send.
  4. **Send serialization (`acquireSendLock`/`releaseSendLock`, added greploop hardening 2026-06-24).**
     RNS `send()` holds `self._send_lock` (a `threading.Lock`, `Channel.py:288/606`) across the ENTIRE
     send — `is_ready_to_send` → reserve → `outlet.send()` → emplace — so only one send runs end-to-end
     and both the sequence reservation AND the no-receipt rollback (`self._next_sequence =
     reserved_sequence`, `Channel.py:608`) are atomic. The swift actor's isolation is the `_lock` (RLock)
     equivalent for synchronous regions only; because `channelOutletMdu`/`channelBuildPacket`/
     `channelTransmit` are `await`-based, a second `performSend` (reachable from `send`/`sendStream`/
     `sendTracked`/`streamSendMessage`) would otherwise interleave at a suspension point and reserve the
     SAME sequence, or clobber the rollback. A `threading.Lock` cannot express a critical section held
     across `await`, so `performSend` now wraps its body in a FIFO hand-off async mutex (`sendLocked` +
     `sendLockWaiters`): acquire grabs the free lock or suspends; release hands ownership directly to the
     next waiter (the lock stays held, the resumed waiter does not re-check). Only the fresh-send path
     takes it — `packetDelivered`/`packetTimeout` and the timeout-driven resend run under `_lock` only in
     RNS (`_send_lock` is NOT held there), so their swift equivalents must not acquire it. `shutdownInternal`
     additionally deregisters each tx envelope's transport-side delivery callback (the `async`
     `channelDeregisterDelivery`, done in the `packetTimeout` teardown since `shutdownInternal` is sync),
     mirroring `_clear_rings` (`Channel.py:382-385`) dropping each packet's delivered/timeout callbacks —
     without it the registration leaks and a late PROOF could fire `packetDelivered` on a dead channel.
     Because that deregistration (and `channelOutletTimedOut`) AWAIT — releasing the actor mid-teardown,
     where RNS's `_shutdown` is synchronous and atomic under `_lock` (`Channel.py:375-377`) — `performSend`
     also guards on the `shutDown` flag after its own awaits: a send queued during the teardown window
     would otherwise find an empty `txRing`, pass `isReadyToSend()`, and transmit on a dead channel. RNS
     needs no such flag (its `is_ready_to_send` `is_usable` gate is hardcoded `True`, `Channel.py:690`, and
     synchronous teardown can never interleave a send); the guard restores that no-send-after-teardown
     invariant for the awaiting swift teardown.

---

### `Buffer.swift` — RawChannelWriter blocking-on-window + close drain split

**Port site:** `Sources/ReticulumSwift/Channel/Buffer.swift` (`RawChannelWriter.writeChunk`, `write`,
`close`; `StreamDataMessage.unpack`).

**Python reference:** `RNS/Buffer.py:231-279` (`RawChannelWriter.write`/`close`), `:87-97`
(`StreamDataMessage.unpack`).

**Reason:** Category (a) language/runtime (actor isolation + sync-vs-async send model). The chunking +
COMPRESSION_TRIES=4 decision, the MAX_DATA_LEN(423) raw cap, and the MAX_CHUNK_LEN(16384) bz2
decompression bound mirror `Buffer.py` exactly. Two structural adaptations, observably equivalent:
  1. **Window admission.** RNS `write()` is non-blocking: on `ChannelException(ME_LINK_NOT_READY)` it
     returns 0 and the caller retries. The swift writer's `writeChunk` instead awaits window admission
     inside `Channel.streamSendMessage` (bounded, mirroring the `is_ready_to_send()` gate RNS polls in
     `close()`), then performs the same non-blocking `performSend`. The reserved Channel sequence is
     returned so the conformance bridge can build the per-message manifest (RNS reads it off the
     `Envelope` the wrapped `channel.send` returns).
  2. **close() drain.** RNS `close()` waits for the tx ring to drain (`while not is_ready_to_send:
     sleep`) before flushing the empty EOF. The swift `close()` flushes the EOF (via `writeChunk`); the
     drain-to-empty wait is performed by the bridge `wire_buffer_stream` loop, which polls
     `Channel.windowSnapshot().txRing` until 0 — the same settle the python command performs around its
     `RawChannelWriter.close()`.
  3. **One-shot EOF flag + public `setEof()` (greploop hardening 2026-06-24).** RNS `write()` builds
     `StreamDataMessage(..., self._eof, ...)` and never resets `_eof` (`Buffer.py:258`); it does not need
     to, because `_eof` is set only inside the terminal `close()` (`Buffer.py:278`) which writes exactly
     once and never writes again. The swift port additionally exposes `setEof(_:)` as a public per-message
     control (used by the conformance bridge's `eof_with_data` path), so a sticky `eofFlag` would stamp
     EOF onto every subsequent emitted message — e.g. a compressible final write that `writeChunk` splits
     across sub-chunks. `writeChunk` therefore consumes the flag (`eofFlag = false`) right after building
     the message, making EOF a correct one-shot marker. This is a no-op for the `close()`-terminal path
     and for the bridge (which re-asserts `setEof` per final sub-chunk), so observable behaviour for every
     RNS-faithful usage is unchanged.

---

### `Channel.swift` / `Link.swift` — receiver-side conformance observability hooks

**Port sites:** `Sources/ReticulumSwift/Channel/Channel.swift` (`decompressionAborted` /
`decompressionError`, `registerStreamReader`, `streamSendMessage`); `Sources/ReticulumSwift/Link/Link.swift`
(`proofObserver` / `setProofObserver`).

**Python reference:** `RNS/Channel.py:425-466` (`_receive`), `RNS/Buffer.py:115-129`
(`RawChannelReader.__init__`); the receiver-side recorders mirror the conformance harness's own hooks at
`reference/wire_tcp.py:1431-1441` (wrapping `link.prove_packet`) and `:1551-1559`
(`_DetectingStreamDataMessage.unpack` recording the bz2-bound abort onto `buffer_state`).

**Reason:** Category (b) added (test-only) observability — no production-path behavior change.
`Channel._receive` already unpacks the inner message before the sequence advance (Channel.py:429); the
port now does the same so a raising bz2 unpack (the MAX_CHUNK_LEN bound) aborts WITHOUT advancing
`_next_rx_sequence`, faithfully. The new `decompressionAborted` flag only RECORDS that swallowed abort
(RNS discards it in `_receive`'s except); `proofObserver` only records the context byte RNS already
proves. `registerStreamReader` / `streamSendMessage` expose the existing `RawChannelReader` registration
and `Channel.send`-returns-sequence behaviors to the listener-side recorder.
