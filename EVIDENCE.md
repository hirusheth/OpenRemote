# How the Google Home remote works — protocol evidence

This dossier documents how the remote-control feature inside the Google Home
app works, as extracted with **REA** (https://github.com/morluto/rea) from
`Google+Home_4.34.22.2_APKPure.xapk` (main APK
`com.google.android.apps.chromecast.app.apk`, SHA-256
`6c28ee752764f0940b485fb42856e6c77780cd0f9eab9eb5493c9931f1fcb0cc`).

Analysis stack: REA archive graph (MCP) + REA JADX headless provider
(`jadx-headless-mcp-0.7.1-all.jar`, SHA-256
`6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75`, run
through `rea-agents@6.7.0` with Temurin JDK 21). Every finding below cites REA
Evidence IDs; raw JSON evidence outputs are reproducible with the same
toolchain. The app's classes are R8-obfuscated; decompiled classes are
referenced by their obfuscated names (`defpackage.asup`, etc.).

## Executive summary

The Google TV remote in Google Home ("virtual remote") does **not** use the
classic Cast protocol (`urn:x-cast:...`, port 8009) for remote control. It
speaks the **Android TV Remote v2** protocol:

```
AtvRemoteControlActivity (manifest component, intent extra "device_id")
 └─ fragment tag "atv_remote_control_fragment" (defpackage.vko)
     ├─ hardware volume keys ──► vko.mW(KeyEvent)        (24/25 only)
     ├─ UI/IME/trackpad keys ─► vko.r(keyCode, astr)
     │                            └─► protobuf "SendKeyCommand.Request" (asvg)
     │                                 └─► astt.a(envelope) → asri.b (channel)
     │                                      └─► asry.b → Handler msg 3
     │                                           └─► envelope.writeDelimitedTo(TLS socket)
     └─ discovery: assz/astd browse "_androidtvremote2._tcp.local." (mDNS)
         └─ assu endpoint (SRV host/port + TXT records)
```

## Evidence table (REA)

| ID (prefix) | Operation | Finding |
|---|---|---|
| ev_524d83e7 / ev_b6d7a769 / ev_7fcb0e56 | inspect_artifact / inventory | APK archive graph: 7,587 entries, 0 integrity contradictions |
| ev_ad1d4ee5 | inspect_android_package | `com.google.android.apps.chromecast.app` 4.34.22.2 (30586976), min SDK 29, target 36, **52,267 classes** |
| ev_7696b13c | search "AtvRemote" | `...remotecontrol.atv.AtvRemoteControlActivity` |
| ev_d56217cf | search "tv.remote" | `TrackpadView`, `DpadView`, `VirtualRemoteAssistantButton`, `RemoteTextEdit`, `Lc3Encoder` |
| ev_193abec7 / ev_eea60c7e | class inventories | activity & D-pad structure |
| ev_f627959b | dispatchKeyEvent | activity forwards keys to fragment `vse.mW(KeyEvent)` |
| ev_b34d16b8 | onCreate | intent extra `device_id` required; fragment via `tsh.bx(deviceId)` |
| ev_8764d99a | vko.mW | hardware volume keys 24/25 (ACTION_DOWN) only |
| ev_36c64e38 | vko.r(keyCode, astr) | **send-key implementation** (below) |
| ev_51c4d890 | asup.dynamicMethod | **outbound envelope schema** (below) |
| ev_d6b98009 | asvg.dynamicMethod | **key-inject schema**: field 1 int key_code, field 2 enum direction |
| ev_4534b034 | astt.a(asup) | sender → channel `asri.b(asup)` |
| ev_a682a2a7 | asry.b(asup) | channel impl; POWER (26) consults TXT `isDeviceInStandbyMode`; queues socket write |
| ev_86d4c7cd | asry.\<init\> | reads TXT key `"wp"`; client name = app package |
| ev_f2bc304a | asru.b() | **TLS connect**: SSLSocket from client-cert KeyManagers (`asqa.c()`), handshake, keepAlive+tcpNoDelay; read loop `asvo.parseDelimitedFrom(...)`; WifiLock "AndroidTVRemote"; **case 40** = `asvk` standby → updates TXT map; dispatch `asrd.f(asvo)` |
| ev_a335ed20 | asrs.handleMessage | **framing**: msg 3 → `asup.writeDelimitedTo(outputStream)` |
| ev_7cbe8f3a / ev_ee96f927 | asru class/\<init\> | connection: Socket/In/OutputStream, HandlerThread "ATVRemote.Network", `(Context, InetAddress, port, ...)` |
| ev_333e3023 | assl | endpoint abstraction: `a(): Uri`; TXT-bearing subclass `assu` |
| ev_f5c99ae3 | assz | hand-rolled mDNS client (MulticastSocket + threads); scanner `astd` ("AtvRemote.MdnsDvcScnner") |
| ev_3a602f46 | asrd.f(asvo) | **inbound state machine** (2→3→4): case 1 = TV configuration |
| ev_2ecec7ed | asub.\<clinit\> (smali) | **capability bit values** (below) |
| ev_c58d27f2 / trace asri→asry | channel wiring | `asry` implements `asri` over `asru` |
| ev_bbaa2f0a | asqa.\<init\> | client certificate KeyStore provider |

## Wire protocol (decoded)

### Discovery (mDNS)
Service type `_androidtvremote2._tcp.local.` (const-string evidence; used by
`assp`/`astd`/`astt`). TXT keys observed: `isDeviceInStandbyMode` (read and
locally updated), `wp`. Host/port from the SRV record.

### Transport
TLS `SSLSocket` with a **client certificate**; TCP keepAlive + noDelay; the
TV's certificate is self-signed and not CA-verified by the app.
**Framing**: protobuf *delimited* — `varint(byteLength) || messageBytes` on
both directions (`writeDelimitedTo` / `parseDelimitedFrom`).

### Outbound envelope `asup` — oneof with 18 fields
Decoded from the protobuf-lite RawMessageInfo string (upstream
`MessageSchema` format, version 4). Message-typed fields at wire numbers
**1, 2, 8, 9, 10, 11, 20, 21, 22, 30, 32, 50, 51, 60, 61, 70, 90** and a
**bytes** field at **31**.

### Inbound envelope `asvo` — oneof, 17 fields
1 = TV configuration (`asvm`), 40 = start/standby (`asvk`), plus the mirror
set of outbound numbers. Decoded from `asvo.dynamicMethod`.

### Handshake (asrd.f)
On connect the TV sends **case 1** `asvm`:
- capability bitmask (`asvm.c`; decoded via the `asub` enum),
- build info (`asvm.d` = `asum`: model, manufacturer, os type 0/1/2,
  os_version, app_name, app_version) — logged by the app as
  *"Build information received: ..."*.

The client replies with **field 1** `asun`: its own capability mask plus
`asum{model=Build.MODEL, manufacturer=Build.MANUFACTURER, ...}`.

### Capability bits (`asub`, from smali)
INPUT=0x2, IME=0x4, VOICE=0x8, PTT_ASSISTANT=0x10, POWER=0x20, VOLUME=0x40,
GAMEPAD=0x100, AUDIO_DEVICES=0x200, FIND_MY_REMOTE=0x400, APP_LINK=0x800.
The app gates key sending on `contains(INPUT) || contains(GAMEPAD)`; POWER
handling checks bit 0x20 (`asuo.c & -33`) and the standby TXT flag.

### Key events (field 10)
`SendKeyCommand.Request` (`asvg`): `key_code = 1` (int, **raw Android
KeyEvent keycode**), `direction = 2` (enum: 0 unknown, 1 start-long, 2
end-long, 3 short). Evidence: vko.r sends Android keycodes (volume 24/25,
home 3, back 4, dpad 19-23...); `asry.b` inspects `key_code == 26` (POWER).

### Voice input
The app embeds `com.google.android.tv.remote.virtual.audio.compression.Lc3Encoder`
— its newer audio path streams **LC3-encoded** microphone audio. The
interoperable path used by public clients (and current firmwares) sends
**raw 16-bit PCM, 8 kHz, mono** in `remote_voice_payload` (field 31, the
bytes member) after a `remote_voice_begin`/`KEYCODE_SEARCH` handshake.
OpenRemote implements the PCM path; the wire structure is identical either
way (opaque bytes payload).

### Pairing
**The app contains no PIN-pairing code** — no POLO/pairing strings exist in
the APK. It presents an already-provisioned client certificate loaded from a
KeyStore (`asqa`), provisioned out-of-band during device setup. A standalone
client therefore pairs its own self-signed certificate via Google's public
**POLO** pairing protocol (AOSP `external/google-tv-pairing-protocol`):
`OuterMessage` protobufs (pairing_request → ack → options → configuration →
configuration_ack → secret → secret_ack) over the same TLS channel, with the
secret derived from both endpoints' RSA public keys and a 6-digit hex PIN
shown on the TV. OpenRemote implements this in `atv_remote/pairing.py`.

## Cross-validation

The APK-derived schema was cross-checked against the public
`remotemessage.proto` (Apache-2.0, github.com/tronikos/androidtvremote2,
itself from github.com/louis49/androidtv-remote and AOSP
keycodes.h). Field-for-field agreement:

| Wire # | APK (obfuscated) | Public name |
|---|---|---|
| 1 | asun (reply in asrd.f) | remote_configure (RemoteConfigure{code1, device_info}) |
| 2 | asuo (bitfield `c`) | remote_set_active |
| 3 | — | remote_error |
| 8 / 9 | — | remote_ping_request / response |
| **10** | **asvg (SendKeyCommand.Request)** | **remote_key_inject (RemoteKeyInject{key_code, direction})** |
| 20/21/22 | asvi/asvj/asvh | IME key inject / batch edit / show request |
| 30 | asvp | remote_voice_begin |
| **31** | **ONEOF_BYTES** | **remote_voice_payload (bytes samples)** |
| 32 | asvs | remote_voice_end |
| **40** | **asvk (bool)** | **remote_start (RemoteStart{started})** |
| 50/51 | asvx/asvv | remote_set_volume_level / adjust_volume_level |
| 60/61 | asul/asuk | set/reset preferred audio device |
| 70 | asur | (not in public proto — newer extension) |
| 90 | asui | remote_app_link_launch_request |

## Notes on the standalone implementation

OpenRemote re-implements the observed behavior independently: mDNS discovery →
TLS with a self-signed client certificate (POLO PIN pairing on first use) →
length-delimited protobuf envelopes → configuration handshake → key/text/
volume/app-link commands, keep-alive ping responses, standby tracking, and
PCM microphone streaming for voice search.
