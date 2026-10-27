# OpenRemote

A **standalone remote control for Google TV / Android TV** — no Google Home, no
phone app, no cloud. It speaks the same *Android TV Remote v2* protocol that
the Google Home app uses for its built-in virtual remote, reconstructed by
reverse-engineering the Google Home APK (4.34.22.2) with
[REA](https://github.com/morluto/rea). The full evidence trail lives in
[EVIDENCE.md](EVIDENCE.md).

```
┌──────────────────────────────────────────────┐
│  Your PC ── mDNS ──► Google TV / Android TV  │
│           TLS + protobuf (Remote v2)          │
│  D-pad · keys · text · volume · voice         │
└──────────────────────────────────────────────┘
```

## Features

- **Discovery** — finds TVs on the local network via mDNS
  (`_androidtvremote2._tcp.local.`), the same service the Google Home app
  browses.
- **Pairing** — POLO PIN pairing (the 6-digit code shown on your TV) that
  registers a locally generated client certificate; nothing leaves your
  network.
- **Remote control** — D-pad, back/home, volume, power, media keys, digits,
  and more (raw Android `KeyEvent` codes on the wire, exactly like the app).
- **Text input** — type into the TV's focused text field over the IME channel.
- **Voice search** — streams your microphone to the TV's assistant
  (16-bit PCM 8 kHz mono, the interoperable voice path; see EVIDENCE.md).
- **Live state** — power/standby notifications, current app, volume level.
- **Zero heavyweight deps for the protocol** — the protobuf codec is
  hand-rolled and byte-exact (no protoc/gencode); only discovery, TLS certs
  and audio use libraries.

## Test without a TV (fake TV emulator)

OpenRemote ships a barebones Android TV emulator so you can test the whole
flow on one PC with no real TV and no firewall configuration:

```powershell
# Terminal 1 — the fake TV (prints a pairing PIN when asked):
openremote fake-tv --name "Fake Living Room"

# Terminal 2 — OpenRemote:
openremote wizard        # scan -> pick "Fake Living Room" -> type the PIN
# or: openremote discover / pair --host 127.0.0.1 / remote --host 127.0.0.1
```

The emulator advertises itself over mDNS, runs the POLO pairing handshake
(generating a valid 6-digit PIN and verifying your client's secret), then logs
every key press, text input, app link and voice session it receives — like a
TV screen would show them. The remote session speaks to `127.0.0.1`, which
Windows Firewall never blocks.

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/cyberbuddhy/OpenRemote.git
cd OpenRemote
pip install -e .
```

This installs the `openremote` command and the dependencies:
`zeroconf` (mDNS), `cryptography` (client certificate), `sounddevice` +
`numpy` (voice input).

## Quick start

### 1. Find your TV

```bash
openremote discover
```

```
Searching for _androidtvremote2._tcp (5.0s)...
  Living Room TV._androidtvremote2._tcp.local.   192.168.1.42:6467
```

The TV must have **Settings → Apps → Android TV Remote Service** available and
both devices must be on the same network.

### 2. Pair (first time only)

```bash
openremote pair --host 192.168.1.42
```

A 6-digit PIN appears on the TV; type it when prompted. Your client
certificate is generated on first run and stored in
`~/.config/openremote/` (`client.pem` / `key.pem`). Copy that folder to any
other PC to reuse the pairing — that's the only state that exists.

### 3. Use the remote

```bash
openremote remote --host 192.168.1.42
```

| Key | Action | Key | Action |
|---|---|---|---|
| Arrows | D-pad | `Enter`/`Space` | OK / play-pause |
| `Backspace` | Back | `h` | Home |
| `+` / `-` | Volume up/down | `m` | Mute |
| `p` | Power | `i` / `g` / `s` | Info / guide / settings |
| `n` / `b` | Media next / previous | `k` / `j` | Seek fwd / back |
| `t` | Type text to the TV | `v` | Start/stop voice dictation |
| `q` | Quit | | |

The status line shows the TV power state, current app and volume.

## Using it as a library

```python
import asyncio
from atv_remote import ATVRemoteClient, RemoteConfig, KeyCode, discover

async def main():
    devices = await discover(timeout=5)
    tv = devices[0]

    config = RemoteConfig(host=tv.host, port=tv.port)
    client = ATVRemoteClient(config)
    await client.connect()

    await client.tap_key(KeyCode.DPAD_CENTER)      # OK
    await client.tap_key(KeyCode.VOLUME_UP)        # volume up
    await client.send_text("blade runner")         # type into the TV
    await client.launch_app("https://youtube.com")  # app link

    await client.close()

asyncio.run(main())
```

## How it works

OpenRemote is a faithful independent re-implementation of what the Google Home
app does, evidenced class-by-class (see [EVIDENCE.md](EVIDENCE.md)):

1. **mDNS** `_androidtvremote2._tcp.local.` → host/port (SRV) + TXT records
   (`isDeviceInStandbyMode`, `wp`).
2. **TLS** to the TV's remote service with a self-signed client certificate;
   the TV trusts it after POLO PIN pairing.
3. **Framing**: every message is `varint(length) || protobuf` (the app calls
   `writeDelimitedTo` on the socket).
4. **Envelope**: a single-oneof `RemoteMessage`; the TV announces its
   capabilities (`remote_configure`), the client answers with its own mask and
   device info; the TV then pings every ~5s (the client must answer).
5. **Keys**: `remote_key_inject{key_code, direction}` where `key_code` is a
   raw Android `KeyEvent` code (HOME=3, BACK=4, VOLUME_UP=24, POWER=26, …).
6. **Voice**: `KEYCODE_SEARCH` → `remote_voice_begin` → PCM chunks in
   `remote_voice_payload` → `remote_voice_end`.

## Project layout

```
atv_remote/
  __main__.py   CLI: discover / pair / remote
  discovery.py  mDNS browsing (zeroconf)
  certs.py      self-signed client certificate
  pairing.py    POLO PIN pairing over the TLS channel
  wire.py       hand-rolled protobuf wire codec (byte-exact, tested)
  client.py     protocol state machine + command API
  keys.py       Android KeyEvent codes
  voice.py      microphone streaming (sounddevice)
  ui.py         terminal UI
tests/          wire codec unit tests
protos/         reference .proto of the wire schema
EVIDENCE.md     REA reverse-engineering dossier with Evidence IDs
```

## Troubleshooting

- **No devices found** — check the TV is on, on the same network, and that
  "Android TV Remote Service" is present/enabled (Settings → Apps → Show
  system apps). Some TVs need *Settings → Network → Remote control* enabled.
- **`pair` says "pairing failed with status 400/402"** — the PIN was mistyped
  or expired; re-run the command. If pairing consistently fails, clear the
  storage of "Android TV Remote Service" on the TV (the same advice Google's
  own app gives).
- **`remote` connects then drops after ~16s** — the TV pings and closes idle
  sessions; OpenRemote answers pings automatically, but if your network
  blocks the connection check your firewall allows outbound TCP 6467.
- **Voice does nothing** — press `v`, *then* speak, press `v` again to stop;
  the assistant UI should open on the TV. If no mic is found, install
  `sounddevice` and check the default input device.
- **Reusing pairing on another PC** — copy `~/.config/openremote/`
  (`client.pem` + `key.pem`) to the same path on the other machine.

## Legal

This is an independent interoperability implementation. It contains no code
from Google, no Google APIs, and talks only to your own TV on your local
network. The protocol analysis is documented in EVIDENCE.md for transparency.
"Google TV", "Android TV" and "Google Home" are trademarks of Google LLC;
this project is not affiliated with or endorsed by Google.

## License

MIT — see [LICENSE](LICENSE).
