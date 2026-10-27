"""Interactive home screen for OpenRemote (sticky menu loop).

Runs when `openremote` is started with no arguments. Pick actions with
arrow keys, number keys or by typing to filter. After each action you return
to the menu until you quit — no retyping `openremote` between steps.

The command-line interface (`openremote discover|pair|remote|key|text|volume|...`)
is untouched and remains the automation/scripting surface. When stdin is not a
TTY (piped/scripted invocation of the bare command), the guide is printed
instead of entering the menu.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .client import ATVRemoteClient, RemoteConfig
from .discovery import TVDevice, discover
from .pairing import PairingClient, make_ssl_context
from .certs import ensure_client_cert

console = Console()

DEFAULT_CERT = "~/.config/openremote/client.pem"
DEFAULT_KEY = "~/.config/openremote/key.pem"
LAST_TV_FILE = Path("~/.config/openremote/last_tv.json").expanduser()


# ---------------------------------------------------------------------------
# last-TV memory
# ---------------------------------------------------------------------------


def load_last_tv() -> TVDevice | None:
    try:
        data = json.loads(LAST_TV_FILE.read_text(encoding="utf-8"))
        return TVDevice(
            name=data.get("name", ""),
            host=data["host"],
            port=int(data.get("port", 6467)),
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None


def save_last_tv(device: TVDevice) -> None:
    try:
        LAST_TV_FILE.parent.mkdir(parents=True, exist_ok=True)
        LAST_TV_FILE.write_text(
            json.dumps({"name": device.name, "host": device.host, "port": device.port}),
            encoding="utf-8",
        )
    except OSError:
        pass


def _config_for(device: TVDevice, client_name: str = "OpenRemote") -> RemoteConfig:
    return RemoteConfig(
        host=device.host,
        port=device.port,
        client_name=client_name,
        cert_path=DEFAULT_CERT,
        key_path=DEFAULT_KEY,
    )


# ---------------------------------------------------------------------------
# flows (async)
# ---------------------------------------------------------------------------


async def scan_flow(timeout: float = 5.0) -> list[TVDevice]:
    with console.status("[cyan]Scanning for TVs on this network...[/cyan]"):
        devices = await discover(timeout=timeout)
    if not devices:
        console.print("[red]No TVs found.[/red] Checklist:")
        console.print("  - TV powered on and on the same network (no VPN on this PC)")
        console.print("  - TV: Settings > Apps > Show system apps > "
                      "[italic]Android TV Remote Service[/italic] enabled")
        console.print("  - allow Python through the firewall (UDP 5353 mDNS)")
        return []
    table = Table(title="TVs found", header_style="cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Name")
    table.add_column("Address", style="green")
    table.add_column("Standby", style="dim")
    ordered = sorted(devices, key=lambda d: d.name)
    for index, device in enumerate(ordered, start=1):
        standby = "?" if device.standby is None else str(device.standby)
        table.add_row(str(index), device.name, f"{device.host}:{device.port}", standby)
    console.print(table)
    return ordered


async def pair_flow(device: TVDevice, client_name: str = "OpenRemote") -> bool:
    """Run POLO pairing for one TV; returns True when paired."""
    cert_path, key_path = ensure_client_cert(Path(DEFAULT_CERT).expanduser(),
                                             Path(DEFAULT_KEY).expanduser())
    config = _config_for(device, client_name)
    console.print(f"Connecting to [green]{device.host}:{device.port}[/green] ...")
    try:
        reader, writer = await asyncio.open_connection(
            device.host, device.port, ssl=make_ssl_context(str(cert_path), str(key_path))
        )
    except OSError as exc:
        console.print(f"[red]Could not reach the TV:[/red] {exc}")
        return False
    pairing = PairingClient(reader, writer, client_name, cert_path.read_bytes())
    try:
        console.print("Starting pairing — a [bold cyan]6-digit PIN[/bold cyan] "
                      "should now appear on the TV...")
        await pairing.start()
        pin = await asyncio.get_event_loop().run_in_executor(
            None, lambda: questionary.text("Enter the PIN shown on the TV:").ask()
        )
        if not pin:
            return False
        await pairing.finish(pin.strip())
    except (ValueError, RuntimeError, OSError) as exc:
        console.print(f"[red]Pairing failed:[/red] {exc}")
        console.print("[dim]The PIN may have been mistyped or expired — try again.[/dim]")
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
    console.print(f"[green]Paired![/green] Certificate saved to {cert_path}")
    save_last_tv(device)
    return True


async def connect_flow(device: TVDevice, no_voice: bool = False) -> ATVRemoteClient:
    """Connect to a TV, offering PIN pairing if the TV doesn't know us yet."""
    config = _config_for(device)
    for attempt in range(2):
        client = ATVRemoteClient(config)
        try:
            with console.status("[cyan]Connecting...[/cyan]"):
                await asyncio.wait_for(client.connect(), timeout=10.0)
            if device.name:
                save_last_tv(device)
            return client
        except Exception as exc:  # noqa: BLE001 - offer pairing on any failure
            await client.close()
            if attempt == 1:
                raise
            console.print(f"[yellow]The TV rejected the session "
                          f"({exc.__class__.__name__}) — it is probably not paired "
                          f"with this PC yet.[/yellow]")
            if not await pair_flow(device, config.client_name):
                raise ConnectionError("pairing was not completed") from exc
    raise ConnectionError("could not connect")  # unreachable


async def remote_flow(device: TVDevice, no_voice: bool = False) -> None:
    """Connect and run the keyboard remote until the user quits it."""
    from .ui import run_ui

    client = await connect_flow(device, no_voice)
    streamer = None
    if not no_voice:
        try:
            from .voice import VoiceStreamer

            streamer = VoiceStreamer(client.send_voice_chunk)
        except RuntimeError as exc:
            console.print(f"[yellow]voice disabled:[/yellow] {exc}")
    try:
        await run_ui(client, streamer)
    finally:
        if streamer:
            await streamer.stop()
        await client.close()
    console.print("[green]Back to the menu.[/green]")


async def key_flow(device: TVDevice, key: str, direction: str = "short",
                   hold: float = 0.6) -> None:
    from .keys import parse_keycode
    from .wire import Direction

    code = parse_keycode(key)
    client = await connect_flow(device, no_voice=True)
    try:
        if direction == "long":
            await client.send_key(code, Direction.START_LONG)
            await asyncio.sleep(hold)
            await client.send_key(code, Direction.END_LONG)
        else:
            await client.tap_key(code)
        console.print(f"[green]Sent[/green] {key} (keycode {code}) "
                      f"to {device.host}")
    finally:
        await client.close()


async def text_flow(device: TVDevice, text: str) -> None:
    client = await connect_flow(device, no_voice=True)
    try:
        await client.send_text(text)
        console.print(f"[green]Sent[/green] {len(text)} characters to the TV.")
    finally:
        await client.close()


async def volume_flow(device: TVDevice, action: str, steps: int = 1) -> None:
    from .keys import KeyCode

    client = await connect_flow(device, no_voice=True)
    try:
        if action == "status":
            await asyncio.sleep(1.5)  # TV pushes volume state on connect
            volume = client.state.volume
            if volume:
                console.print(f"Volume: [bold]{volume.get('level')}[/bold]/"
                              f"{volume.get('max')}"
                              + ("  [muted]" if volume.get("muted") else ""))
            else:
                console.print("Volume: unknown (TV did not report it)")
            return
        for _ in range(steps):
            if action == "up":
                await client.tap_key(KeyCode.VOLUME_UP)
            elif action == "down":
                await client.tap_key(KeyCode.VOLUME_DOWN)
            elif action == "mute":
                await client.tap_key(KeyCode.VOLUME_MUTE)
            await asyncio.sleep(0.15)
        console.print(f"[green]Sent[/green] volume {action}.")
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# interactive pickers
# ---------------------------------------------------------------------------


def choose_device(devices: list[TVDevice]) -> TVDevice | None:
    choices = [
        questionary.Choice(
            title=f"{d.name or '(unnamed TV)'}  —  {d.host}:{d.port}", value=d
        )
        for d in devices
    ]
    return questionary.select("Which TV?", choices=choices).ask()


def choose_action(last: TVDevice | None) -> str | None:
    choices: list[Any] = []
    if last is not None:
        choices.append(
            questionary.Choice(
                title=f"Connect to {last.name or last.host} "
                      f"({last.host}:{last.port})",
                value="connect_last",
            )
        )
    choices += [
        questionary.Choice(title="Scan for TVs", value="scan"),
        questionary.Choice(title="Pair a new TV (PIN)", value="pair"),
        questionary.Choice(title="Remote control", value="remote"),
        questionary.Choice(title=" Send a single key", value="key"),
        questionary.Choice(title="Help / command reference", value="help"),
        questionary.Separator(),
        questionary.Choice(title="Quit", value="quit"),
    ]
    return questionary.select(
        f"OpenRemote {__version__} — what do you want to do?",
        choices=choices,
    ).ask()


def _select_device_or_scan(preselected: TVDevice | None) -> TVDevice | None:
    """Return a device for an action: reuse the preselected one, or scan."""
    if preselected is not None:
        return preselected
    devices = asyncio.run(scan_flow())
    if not devices:
        return None
    return choose_device(devices)


HELP_TEXT = f"""\
[bold cyan]OpenRemote {__version__}[/bold cyan] — Android TV Remote v2, standalone.

[bold]This menu[/bold]: pick with ↑/↓ or a number, Enter confirms. After each
action you come back here. `q`/Esc/Ctrl+C cancels or quits.

[bold]Inside the remote[/bold] (option 🎮):
  arrows = D-pad | Enter/Space = OK | Backspace = back | h = home
  +/- = volume | m = mute | p = power | t = type text | v = voice
  n/b = next/prev | k/j = seek | s = settings | g = guide | q = back here

[bold]Command line (for scripts/automation)[/bold]:
  openremote discover
  openremote pair --host <ip>
  openremote remote --host <ip>
  openremote key --host <ip> dpad_center          (one button press)
  openremote key --host <ip> power --direction long
  openremote text --host <ip> "hello world"
  openremote volume --host <ip> up|down|mute|status
  openremote wizard                               (guided, non-interactive menu)

[bold]Pairing state[/bold] lives in ~/.config/openremote/ (client.pem/key.pem
plus last_tv.json). Copy that folder to reuse it on another PC.
Docs: https://github.com/cyberbuddhy/OpenRemote
"""


def _show_help() -> None:
    console.print(Panel(HELP_TEXT, border_style="cyan", title="Help"))


# ---------------------------------------------------------------------------
# the sticky loop
# ---------------------------------------------------------------------------


def run_menu() -> int:
    """The interactive home screen. Returns a process exit code."""
    if not sys.stdin.isatty():
        # Scripted/piped `openremote` — do not enter interactive mode.
        console.print(
            "[yellow]stdin is not a terminal — use subcommands for "
            "automation:[/yellow] openremote discover|pair|remote|key|text|volume|wizard\n"
            "Run `openremote --help` for everything."
        )
        return 0

    last = load_last_tv()
    while True:
        try:
            action = choose_action(last)
        except KeyboardInterrupt:
            return 0
        if action is None or action == "quit":
            console.print("[dim]Bye![/dim]")
            return 0

        if action == "help":
            _show_help()
            continue

        try:
            if action == "scan":
                devices = asyncio.run(scan_flow())
                if devices:
                    chosen = choose_device(devices)
                    if chosen is not None:
                        last = chosen
                        save_last_tv(chosen)
            elif action == "connect_last":
                if last is None:
                    console.print("[red]No TV remembered yet — scan first.[/red]")
                    continue
                asyncio.run(remote_flow(last))
            elif action == "pair":
                device = _select_device_or_scan(last)
                if device is None:
                    continue
                if asyncio.run(pair_flow(device)):
                    last = device
            elif action == "remote":
                device = _select_device_or_scan(last)
                if device is None:
                    continue
                last = device
                asyncio.run(remote_flow(device))
            elif action == "key":
                device = _select_device_or_scan(last)
                if device is None:
                    continue
                key = questionary.text(
                    "Key to send (e.g. dpad_center, power, volume_up, KEYCODE_SEARCH):"
                ).ask()
                if not key:
                    continue
                try:
                    asyncio.run(key_flow(device, key.strip()))
                except ValueError as exc:
                    console.print(f"[red]{exc}[/red]")
            else:  # pragma: no cover - unknown choice
                continue
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled — back to the menu.[/yellow]")
        except Exception as exc:  # noqa: BLE001 - menu survives any action failure
            console.print(f"[red]Error:[/red] {exc.__class__.__name__}: {exc}")
            console.print("[dim]Back to the menu.[/dim]")
