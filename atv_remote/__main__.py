"""OpenRemote - standalone Google TV / Android TV remote control.

Bare `openremote` opens the interactive menu (sticky: pick actions with
numbers/arrow keys, return to the menu after each action). All commands
remain available for scripting/automation:

  discover   find TVs on your network (mDNS)
  pair       pair with a TV using the PIN shown on its screen
  remote     start the interactive remote control
  wizard     guided first run: discover -> pair -> remote
  key        send a single button press (automation)
  text       type text into the TV (automation)
  volume     volume up/down/mute/status (automation)
"""

from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys

from . import __version__
from .client import ATVRemoteClient, RemoteConfig
from .discovery import TVDevice, find_devices
from .pairing import PairingClient, make_ssl_context
from .certs import ensure_client_cert

DOCS_URL = "https://github.com/cyberbuddhy/OpenRemote"

DEFAULT_CERT = "~/.config/openremote/client.pem"
DEFAULT_KEY = "~/.config/openremote/key.pem"

GUIDE = f"""\
OpenRemote {__version__} - standalone Google TV / Android TV remote control
Speaks the Android TV Remote v2 protocol (reverse-engineered from the Google
Home app - see EVIDENCE.md).

Run `openremote` with no arguments for the interactive menu (pick actions
with numbers/arrow keys; you stay inside the app until you quit).

Command line (scripts / automation):
  openremote discover                     find TVs (mDNS)
  openremote pair --host <tv-ip>          pair once (type the TV's PIN)
  openremote remote --host <tv-ip>        interactive remote
  openremote wizard                       guided first run
  openremote key --host <ip> power        one button press
  openremote key --host <ip> dpad_down --direction long
  openremote text --host <ip> "hello"     type into the TV
  openremote volume --host <ip> up        volume up/down/mute/status

Help:
  openremote --help                       full usage and examples
  openremote <command> --help             options for one command
  {DOCS_URL}               README + EVIDENCE.md (how it works)

Notes:
  - If the `openremote` command is not found, run it as:
      python -m atv_remote
  - Pairing lives in ~/.config/openremote/ (client.pem/key.pem);
    copy that folder to use the same pairing on another PC.
"""


def _print_guide() -> None:
    print(GUIDE)


def _config_from(args: argparse.Namespace) -> RemoteConfig:
    return RemoteConfig(
        host=args.host or "",
        port=args.port,
        client_name=getattr(args, "name", "OpenRemote"),
        cert_path=args.cert or DEFAULT_CERT,
        key_path=args.key or DEFAULT_KEY,
    )


def _require_host(args: argparse.Namespace) -> str | None:
    if not args.host:
        print("No --host given. Find your TV first:")
        print("  openremote discover")
        print("or use the interactive menu:  openremote")
        return None
    return args.host


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


async def cmd_discover(args: argparse.Namespace) -> int:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    with console.status("[cyan]Scanning for TVs (mDNS)...[/cyan]"):
        devices, method = await find_devices(timeout=args.timeout)
    if not devices:
        console.print("[red]No TVs found.[/red] Checklist:")
        console.print("  - TV powered on and on the same network (no VPN on this PC)")
        console.print("  - TV: Settings > Apps > Show system apps > "
                      "[italic]Android TV Remote Service[/italic] enabled")
        console.print("  - run [bold]openremote fix-firewall[/bold] to allow mDNS "
                      "(one UAC click)")
        console.print("  - or connect by IP directly: "
                      "[bold]openremote pair --host <tv-ip>[/bold]")
        console.print("\nGuided flow: [bold]openremote wizard[/bold]  |  "
                      "interactive menu: [bold]openremote[/bold]")
        return 1
    if method != "mDNS":
        console.print("[dim](mDNS unavailable - used the outbound network scan; "
                      "run 'openremote fix-firewall' for fast named discovery)[/dim]")
    table = Table(title=f"TVs found ({method})", header_style="cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Name")
    table.add_column("Address", style="green")
    for index, device in enumerate(sorted(devices, key=lambda d: d.name), start=1):
        table.add_row(str(index), device.name, f"{device.host}:{device.port}")
    console.print(table)
    first = sorted(devices, key=lambda d: d.name)[0]
    console.print("\nNext steps:")
    console.print(f"  [bold]openremote pair --host {first.host}[/bold]   (once)")
    console.print(f"  [bold]openremote remote --host {first.host}[/bold]  (after pairing)")
    return 0


async def cmd_fix_firewall(args: argparse.Namespace) -> int:
    from rich.console import Console

    from . import firewall

    console = Console()
    console.print("Checking for the mDNS firewall rule (inbound UDP 5353)...")
    if firewall.rule_exists():
        console.print("[green]Already in place - mDNS discovery is allowed.[/green]")
        return 0
    console.print("A [bold]UAC prompt[/bold] will appear - click [bold]Yes[/bold] "
                  "to add the rule (scoped to UDP port 5353 only).")
    ok, message = await asyncio.to_thread(firewall.create_rule_elevated)
    if ok:
        console.print(f"[green]{message}.[/green] Fast mDNS discovery now works.")
        return 0
    console.print(f"[red]{message}.[/red]")
    console.print("[dim]Discovery still works without it: the app automatically "
                  "falls back to an outbound network scan, and you can always "
                  "connect by IP.[/dim]")
    return 0


async def cmd_pair(args: argparse.Namespace) -> int:
    if _require_host(args) is None:
        return 2
    from rich.console import Console

    console = Console()
    config = _config_from(args)
    cert_path, key_path = ensure_client_cert(
        pathlib.Path(config.cert_path).expanduser(),
        pathlib.Path(config.key_path).expanduser(),
    )
    ctx = make_ssl_context(str(cert_path), str(key_path))
    console.print(f"Connecting to [green]{config.host}:{config.port}[/green] ...")
    reader, writer = await asyncio.open_connection(config.host, config.port, ssl=ctx)
    pairing = PairingClient(reader, writer, config.client_name, cert_path.read_bytes())
    console.print("Starting pairing - a [bold cyan]6-digit PIN[/bold cyan] should "
                  "now appear on the TV...")
    await pairing.start()
    pin = input("Enter the PIN shown on the TV: ").strip()
    try:
        await pairing.finish(pin)
    except ValueError as exc:
        console.print(f"[red]Pairing failed:[/red] {exc}")
        console.print("[dim]The PIN may have been mistyped or expired - try again.[/dim]")
        return 1
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass
    console.print(f"[green]Paired![/green] Client certificate saved to {cert_path}")
    console.print(f"Now start the remote:  [bold]openremote remote --host "
                  f"{config.host}[/bold]")
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
    if _require_host(args) is None:
        return 2
    return await _run_remote_session(_config_from(args), args.no_voice)


# ---------------------------------------------------------------------------
# one-shot automation commands: key / text / volume
# ---------------------------------------------------------------------------


def _device_from(args: argparse.Namespace) -> TVDevice | None:
    if _require_host(args) is None:
        return None
    return TVDevice(name=getattr(args, "name", "") or "", host=args.host,
                    port=args.port)


async def cmd_key(args: argparse.Namespace) -> int:
    from .keys import parse_keycode
    from .menu import key_flow

    device = _device_from(args)
    if device is None:
        return 2
    try:
        code = parse_keycode(args.key)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    await key_flow(device, args.key, direction=args.direction, hold=args.hold)
    print(f"keycode {code} sent.")
    return 0


async def cmd_text(args: argparse.Namespace) -> int:
    from .menu import text_flow

    device = _device_from(args)
    if device is None:
        return 2
    message = " ".join(args.text)
    await text_flow(device, message)
    return 0


async def cmd_volume(args: argparse.Namespace) -> int:
    from .menu import volume_flow

    device = _device_from(args)
    if device is None:
        return 2
    await volume_flow(device, args.action, steps=args.steps)
    return 0


async def cmd_fake_tv(args: argparse.Namespace) -> int:
    from rich.console import Console

    from .faketv import run_fake_tv

    console = Console()
    console.print("[bold]Starting the Fake TV emulator...[/bold]")
    await run_fake_tv(name=args.name, port=args.port, advertise=not args.no_mdns)
    return 0


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
    print("Starting pairing - a 6-digit PIN should appear on the TV...")
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
    print("OpenRemote wizard - let's find and connect to your TV.\n")
    print(f"Searching for TVs ({args.timeout}s, mDNS + network scan)...")
    devices, method = await find_devices(timeout=args.timeout)
    if not devices:
        print("No TVs found. Checklist:")
        print("  - TV powered on and on this network")
        print("  - 'Android TV Remote Service' enabled on the TV (system apps)")
        print("  - firewall allows UDP 5353 (mDNS)")
        print(f"\nDocs: {DOCS_URL}")
        return 1

    if method != "mDNS":
        print("(mDNS unavailable - used the outbound network scan; "
              "run 'openremote fix-firewall' for fast named discovery)")
    device = await _pick_device(devices)
    config = RemoteConfig(
        host=device.host,
        port=device.port,
        client_name=args.name,
        cert_path=args.cert or DEFAULT_CERT,
        key_path=args.key or DEFAULT_KEY,
    )
    ensure_client_cert(
        pathlib.Path(config.cert_path).expanduser(),
        pathlib.Path(config.key_path).expanduser(),
    )

    # Try to connect; pair interactively if the TV doesn't know us yet.
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
  openremote                       interactive menu (pick with numbers/arrows)
  openremote wizard                guided first run: discover -> pair -> remote
  openremote discover              list TVs on this network
  openremote pair --host 192.168.1.42
                                   pair using the PIN shown on the TV
  openremote remote --host 192.168.1.42
                                   start the interactive remote
  openremote key --host 192.168.1.42 power
                                   send one button press (automation)
  openremote key --host 192.168.1.42 dpad_down --direction long
                                   long-press a button
  openremote text --host 192.168.1.42 "hello world"
                                   type into the TV's focused field
  openremote volume --host 192.168.1.42 up
                                   volume up / down / mute / status

the pairing lives in ~/.config/openremote/ (client.pem + key.pem); copy that
folder to another PC to reuse it. If `openremote` is not on PATH, use:
  python -m atv_remote
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openremote",
        description="Standalone Google TV / Android TV remote control "
                    "(Android TV Remote v2 protocol). Bare `openremote` opens "
                    "the interactive menu.",
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

    p_key = sub.add_parser(
        "key",
        help="send a single button press (automation)",
        description="Connect to the TV, send one key event and exit. Key names: "
                    "dpad_up/down/left/right/center, home, back, power, volume_up, "
                    "volume_down, volume_mute, play_pause, next, previous, menu, "
                    "search, or KEYCODE_* names, or a raw number.",
    )
    common(p_key)
    p_key.add_argument("key", help="key name, KEYCODE_* name, or raw keycode")
    p_key.add_argument(
        "--direction",
        choices=["short", "long"],
        default="short",
        help="short = tap, long = press, hold, release (default: short)",
    )
    p_key.add_argument(
        "--hold", type=float, default=0.6,
        help="seconds to hold for --direction long (default: 0.6)",
    )
    p_key.set_defaults(func=cmd_key)

    p_text = sub.add_parser(
        "text",
        help="type text into the TV's focused field (automation)",
        description="Connect to the TV and type the given text via the IME "
                    "channel (the TV's on-screen keyboard must be focused).",
    )
    common(p_text)
    p_text.add_argument("text", nargs="+", help="text to type")
    p_text.set_defaults(func=cmd_text)

    p_volume = sub.add_parser(
        "volume",
        help="volume up/down/mute/status (automation)",
        description="Adjust the TV volume or report the current level.",
    )
    common(p_volume)
    p_volume.add_argument(
        "action", choices=["up", "down", "mute", "status"],
        help="what to do",
    )
    p_volume.add_argument(
        "--steps", type=int, default=1,
        help="how many volume steps for up/down (default: 1)",
    )
    p_volume.set_defaults(func=cmd_volume)

    p_fix = sub.add_parser(
        "fix-firewall",
        help="allow mDNS discovery through the Windows firewall (one UAC click)",
        description="Add a narrowly scoped inbound firewall rule (UDP 5353) so "
                    "TV discovery via mDNS works. Only affects discovery; "
                    "controlling a TV by IP never needs this.",
    )
    p_fix.set_defaults(func=cmd_fix_firewall)

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

    p_fake = sub.add_parser(
        "fake-tv",
        help="run a barebones Android TV emulator for testing",
        description="Emulates the remote-control parts of an Android TV: TLS "
                    "service on the remote port, mDNS advertisement, PIN "
                    "pairing (the PIN is printed here), key/text/voice "
                    "logging. Run it in a second terminal and point "
                    "OpenRemote at it to test end to end without a TV.",
    )
    p_fake.add_argument("--port", type=int, default=6467, help="listen port")
    p_fake.add_argument(
        "--name", default="Fake TV", help="device name (shown in discovery)"
    )
    p_fake.add_argument(
        "--no-mdns", action="store_true", help="do not advertise via mDNS"
    )
    p_fake.set_defaults(func=cmd_fake_tv)
    return parser


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    if not args_list:
        # Bare invocation: enter the interactive menu (sticky).
        try:
            from .menu import run_menu
        except ImportError as exc:
            print(f"The interactive menu needs 'rich' and 'questionary' ({exc}).")
            print("Install them with:  pip install rich questionary")
            print("Meanwhile, command mode still works - see the guide below.\n")
            _print_guide()
            return 1
        return run_menu()
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
