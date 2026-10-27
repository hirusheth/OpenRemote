"""OpenRemote — standalone Google TV / Android TV remote control.

Commands:
  discover   find TVs on your network (mDNS)
  pair       pair with a TV using the PIN shown on its screen
  remote     start the interactive remote control
  wizard     do all of the above interactively (recommended first run)

Running `openremote` with no arguments prints a getting-started guide.
"""

from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys

from . import __version__
from .client import ATVRemoteClient, RemoteConfig
from .discovery import TVDevice, discover
from .pairing import PairingClient, make_ssl_context
from .certs import ensure_client_cert

DOCS_URL = "https://github.com/cyberbuddhy/OpenRemote"

GUIDE = f"""\
OpenRemote {__version__} — standalone Google TV / Android TV remote control
Speaks the Android TV Remote v2 protocol (reverse-engineered from the Google
Home app — see EVIDENCE.md).

Commands:
  discover   Find TVs on your network (mDNS)
  pair       Pair with a TV using the 6-digit PIN shown on its screen
  remote     Start the interactive remote (D-pad, volume, text, voice)
  wizard     Do everything interactively — recommended on first run

Typical first run:
  openremote wizard
  (or step by step:)
  openremote discover                # 1. find your TV's IP
  openremote pair --host <tv-ip>     # 2. type the PIN shown on the TV once
  openremote remote --host <tv-ip>   # 3. control it

Help:
  openremote --help                  full usage and examples
  openremote <command> --help        options for one command
  {DOCS_URL}          README + EVIDENCE.md (how it works)

Notes:
  - If the `openremote` command is not found, run it as:
      python -m atv_remote wizard
  - Pairing is stored in ~/.config/openremote/ (client.pem/key.pem);
    copy that folder to use the same pairing on another PC.
"""


def _print_guide() -> None:
    print(GUIDE)


def _config_from(args: argparse.Namespace) -> RemoteConfig:
    return RemoteConfig(
        host=args.host or "",
        port=args.port,
        client_name=args.name,
        cert_path=args.cert or "~/.config/openremote/client.pem",
        key_path=args.key or "~/.config/openremote/key.pem",
    )


def _require_host(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str | None:
    if not args.host:
        print("No --host given. Find your TV first:\n"
              "  openremote discover\n"
              "or let the wizard do everything:\n"
              "  openremote wizard")
        return None
    return args.host


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


async def cmd_discover(args: argparse.Namespace) -> int:
    print(f"Searching for _androidtvremote2._tcp ({args.timeout}s)...")
    devices = await discover(timeout=args.timeout)
    if not devices:
        print("No TVs found. Checklist:")
        print("  - Is the TV powered on (not off) and connected to this network?")
        print("  - On the TV: Settings > Apps > See all apps > Show system apps >")
        print("    'Android TV Remote Service' — must be enabled (or present).")
        print("  - Some TVs also need Settings > Network > Remote control enabled.")
        print("  - Check that your firewall allows Python/UDP 5353 (mDNS).")
        print("\nOr run the guided flow:  openremote wizard")
        return 1
    for index, device in enumerate(devices, start=1):
        standby = "" if device.standby is None else f"  standby={device.standby}"
        print(f"  [{index}] {device.name:40s} {device.host}:{device.port}{standby}")
    print("\nNext steps:")
    print(f"  openremote pair --host {devices[0].host}   (once)")
    print(f"  openremote remote --host {devices[0].host}  (after pairing)")
    return 0


# ---------------------------------------------------------------------------
# pair
# ---------------------------------------------------------------------------


async def cmd_pair(args: argparse.Namespace) -> int:
    if _require_host(args, None) is None:
        return 2
    config = _config_from(args)
    cert_path, key_path = ensure_client_cert(
        pathlib.Path(config.cert_path).expanduser(),
        pathlib.Path(config.key_path).expanduser(),
    )
    ctx = make_ssl_context(str(cert_path), str(key_path))
    print(f"Connecting to {config.host}:{config.port} ...")
    reader, writer = await asyncio.open_connection(config.host, config.port, ssl=ctx)
    pairing = PairingClient(reader, writer, config.client_name, cert_path.read_bytes())
    print("Starting pairing; a 6-digit PIN should now appear on the TV...")
    await pairing.start()
    pin = input("Enter the PIN shown on the TV: ").strip()
    try:
        await pairing.finish(pin)
    except ValueError as exc:
        print(f"Pairing failed: {exc}", file=sys.stderr)
        print("The PIN may have been mistyped or expired — just try again.",
              file=sys.stderr)
        return 1
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass
    print(f"Paired. Client certificate saved to {cert_path}")
    print(f"Now start the remote:  openremote remote --host {config.host}")
    return 0


# ---------------------------------------------------------------------------
# remote
# ---------------------------------------------------------------------------


async def _run_remote_session(config: RemoteConfig, no_voice: bool) -> int:
    from .ui import run_ui

    client = ATVRemoteClient(config)
    streamer = None
    if not no_voice:
        try:
            from .voice import VoiceStreamer

            streamer = VoiceStreamer(client.send_voice_chunk)
        except RuntimeError as exc:
            print(f"voice disabled: {exc}", file=sys.stderr)
    await client.connect()
    try:
        await run_ui(client, streamer)
    finally:
        if streamer:
            await streamer.stop()
        await client.close()
    return 0


async def cmd_remote(args: argparse.Namespace) -> int:
    if _require_host(args, None) is None:
        return 2
    return await _run_remote_session(_config_from(args), args.no_voice)


# ---------------------------------------------------------------------------
# wizard
# ---------------------------------------------------------------------------


async def _pick_device(devices: list[TVDevice]) -> TVDevice:
    if len(devices) == 1:
        print(f"Found one TV: {devices[0].name} ({devices[0].host}:{devices[0].port})")
        return devices[0]
    print("Multiple TVs found:")
    for index, device in enumerate(devices, start=1):
        print(f"  [{index}] {device.name:40s} {device.host}:{device.port}")
    while True:
        choice = input("Select a TV [1-{}]: ".format(len(devices))).strip()
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            return devices[int(choice) - 1]
        print(f"Please enter a number between 1 and {len(devices)}.")


async def _pair_interactive(config: RemoteConfig, reason: str) -> bool:
    print(reason)
    print("Starting pairing — a 6-digit PIN should appear on the TV...")
    cert_path, key_path = ensure_client_cert(
        pathlib.Path(config.cert_path).expanduser(),
        pathlib.Path(config.key_path).expanduser(),
    )
    ctx = make_ssl_context(str(cert_path), str(key_path))
    reader, writer = await asyncio.open_connection(config.host, config.port, ssl=ctx)
    pairing = PairingClient(reader, writer, config.client_name, cert_path.read_bytes())
    await pairing.start()
    pin = input("Enter the PIN shown on the TV: ").strip()
    try:
        await pairing.finish(pin)
    except ValueError as exc:
        print(f"Pairing failed: {exc}")
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
    print("Paired. Connecting again...")
    return True


async def cmd_wizard(args: argparse.Namespace) -> int:
    print(f"OpenRemote wizard — let's find and connect to your TV.\n")
    print(f"Searching for TVs ({args.timeout}s)...")
    devices = await discover(timeout=args.timeout)
    if not devices:
        print("No TVs found. Checklist:")
        print("  - TV powered on and on this network")
        print("  - 'Android TV Remote Service' enabled on the TV (system apps)")
        print("  - firewall allows UDP 5353 (mDNS)")
        print(f"\nDocs: {DOCS_URL}")
        return 1

    device = await _pick_device(devices)
    config = RemoteConfig(
        host=device.host,
        port=device.port,
        client_name=args.name,
        cert_path=args.cert or "~/.config/openremote/client.pem",
        key_path=args.key or "~/.config/openremote/key.pem",
    )
    ensure_client_cert(
        pathlib.Path(config.cert_path).expanduser(),
        pathlib.Path(config.key_path).expanduser(),
    )

    # Try to connect; pair interactively if the TV doesn't know us yet.
    paired_already = False
    for attempt in range(2):
        client = ATVRemoteClient(config)
        try:
            await asyncio.wait_for(client.connect(), timeout=10.0)
        except Exception as exc:  # noqa: BLE001 - wizard reports any failure
            if attempt == 0:
                paired = await _pair_interactive(
                    config,
                    f"Could not establish the remote session ({exc.__class__.__name__}).",
                )
                if not paired:
                    return 1
                continue
            print(f"Still cannot connect after pairing ({exc.__class__.__name__}: {exc})")
            print("If pairing was accepted, try:  openremote remote --host "
                  f"{config.host}  (or clear the storage of 'Android TV Remote")
            print("Service' on the TV and re-run the wizard).")
            return 1
        paired_already = True
        # Connected: run the remote UI.
        from .ui import run_ui

        streamer = None
        if not args.no_voice:
            try:
                from .voice import VoiceStreamer

                streamer = VoiceStreamer(client.send_voice_chunk)
            except RuntimeError as exc:
                print(f"voice disabled: {exc}", file=sys.stderr)
        try:
            await run_ui(client, streamer)
        finally:
            if streamer:
                await streamer.stop()
            await client.close()
        return 0

    return 1  # unreachable; loop returns above


# ---------------------------------------------------------------------------
# argument parser
# ---------------------------------------------------------------------------

EPILOG = """\
examples:
  openremote                       print the getting-started guide
  openremote wizard                guided: discover -> pair -> remote
  openremote discover              list TVs on this network
  openremote pair --host 192.168.1.42
                                   pair using the PIN shown on the TV
  openremote remote --host 192.168.1.42
                                   start the interactive remote
  openremote remote --host 192.168.1.42 --port 6467 --no-voice
                                   explicit port, microphone disabled

the pairing lives in ~/.config/openremote/ (client.pem + key.pem); copy that
folder to another PC to reuse it. If `openremote` is not on PATH, use:
  python -m atv_remote wizard
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openremote",
        description="Standalone Google TV / Android TV remote control "
                    "(Android TV Remote v2 protocol).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"openremote {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    p_discover = sub.add_parser(
        "discover",
        help="find TVs on your network via mDNS",
        description="Scan the local network for the Android TV remote service "
                    "(_androidtvremote2._tcp) and list host/port for each TV.",
    )
    p_discover.add_argument(
        "--timeout", type=float, default=5.0, help="scan duration in seconds"
    )
    p_discover.set_defaults(func=cmd_discover)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--host", help="TV IP address or hostname")
        p.add_argument(
            "--port",
            type=int,
            default=6467,
            help="remote service port (from mDNS; default: 6467)",
        )
        p.add_argument(
            "--name", default="OpenRemote", help="client name shown on the TV"
        )
        p.add_argument("--cert", help="client certificate PEM path")
        p.add_argument("--key", help="client key PEM path")

    p_pair = sub.add_parser(
        "pair",
        help="pair with a TV using the PIN shown on it",
        description="Connect to the TV, run the POLO pairing handshake and "
                    "register this PC's client certificate. A 6-digit PIN "
                    "appears on the TV; type it when prompted. Do this once.",
    )
    common(p_pair)
    p_pair.set_defaults(func=cmd_pair)

    p_remote = sub.add_parser(
        "remote",
        help="start the interactive remote",
        description="Open the interactive remote control (arrows = D-pad, "
                    "t = type text, v = voice, q = quit). Pair first.",
    )
    common(p_remote)
    p_remote.add_argument(
        "--no-voice", action="store_true", help="disable microphone streaming"
    )
    p_remote.set_defaults(func=cmd_remote)

    p_wizard = sub.add_parser(
        "wizard",
        help="guided first run: discover, pair if needed, then remote",
        description="Scan for TVs, let you pick one, pair with it (PIN shown "
                    "on the TV) if it doesn't know this PC yet, then start the "
                    "interactive remote. Recommended the first time.",
    )
    p_wizard.add_argument(
        "--timeout", type=float, default=5.0, help="scan duration in seconds"
    )
    p_wizard.add_argument(
        "--name", default="OpenRemote", help="client name shown on the TV"
    )
    p_wizard.add_argument("--cert", help="client certificate PEM path")
    p_wizard.add_argument("--key", help="client key PEM path")
    p_wizard.add_argument(
        "--no-voice", action="store_true", help="disable microphone streaming"
    )
    p_wizard.set_defaults(func=cmd_wizard)
    return parser


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    if not args_list:
        _print_guide()
        return 0
    args = build_parser().parse_args(args_list)
    try:
        return asyncio.run(args.func(args))
    except KeyboardInterrupt:
        print()
        return 130
    except ConnectionError as exc:
        print(f"connection error: {exc}", file=sys.stderr)
        print("Check the TV is on and reachable:  openremote discover",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
