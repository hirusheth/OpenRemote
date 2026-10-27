"""Terminal UI for the remote control.

Keyboard mapping (single keypress = one button tap, matching the D-pad
semantics of the app's DpadView):
  Arrows      D-pad up/down/left/right
  Enter/Space D-pad center (OK)
  Backspace   Back          Esc: quit
  h           Home          m: volume mute
  + / -       Volume up / down
  p           Power         i: info
  g           Guide         s: settings
  n / b       Media next / previous
  k / j       Media seek forward / back
  space       Play/pause    (also OK)
  t           Type text (prompts for a string, sends it over IME)
  v           Start/stop voice dictation (streams the microphone)
  q / Ctrl-C  Quit
"""

from __future__ import annotations

import asyncio
import sys

from . import wire
from .client import ATVRemoteClient, RemoteConfig, TVState
from .keys import KeyCode
from .voice import VoiceStreamer

SINGLE_KEYS = {
    "\x1b[A": KeyCode.DPAD_UP,
    "\x1b[B": KeyCode.DPAD_DOWN,
    "\x1b[C": KeyCode.DPAD_RIGHT,
    "\x1b[D": KeyCode.DPAD_LEFT,
    "\r": KeyCode.DPAD_CENTER,
    "\n": KeyCode.DPAD_CENTER,
    " ": KeyCode.MEDIA_PLAY_PAUSE,
    "\x7f": KeyCode.BACK,
    "\x08": KeyCode.BACK,
    "h": KeyCode.HOME,
    "m": KeyCode.VOLUME_MUTE,
    "+": KeyCode.VOLUME_UP,
    "-": KeyCode.VOLUME_DOWN,
    "p": KeyCode.POWER,
    "i": KeyCode.INFO,
    "g": KeyCode.GUIDE,
    "s": KeyCode.SETTINGS,
    "n": KeyCode.MEDIA_NEXT,
    "b": KeyCode.MEDIA_PREVIOUS,
    "k": KeyCode.MEDIA_FAST_FORWARD,
    "j": KeyCode.MEDIA_REWIND,
}


def _read_key() -> str:
    """Read a single keypress cross-platform (no external deps)."""
    if sys.platform == "win32":
        import msvcrt

        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):  # special key prefix
            ch += msvcrt.getwch()
        return ch
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            ch += sys.stdin.read(2)
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _print_state(state: TVState) -> None:
    on = "?" if state.is_on is None else ("on" if state.is_on else "off")
    app = state.current_app or "-"
    vol = ""
    if state.volume:
        vol = f" vol={state.volume.get('level')}/{state.volume.get('max')}"
        if state.volume.get("muted"):
            vol += " (muted)"
    print(f"\r[TV: {on} | app: {app}{vol}] ", end="", flush=True)


async def run_ui(client: ATVRemoteClient, streamer: VoiceStreamer | None) -> None:
    print("Connected. Keys: arrows=dpad enter=ok backspace=back h=home +/-=vol "
          "p=power space=play t=text v=voice q=quit")
    _print_state(client.state)
    loop = asyncio.get_running_loop()

    def on_update(state: TVState) -> None:
        _print_state(state)

    client._on_update = on_update  # noqa: SLF001 - UI hook

    voice_active = False
    while True:
        key = await loop.run_in_executor(None, _read_key)
        if key in ("q", "\x1b", "\x03"):
            print()
            break
        if key == "t":
            await _send_text_interactive(client)
            continue
        if key == "v":
            if streamer is None:
                print("\nvoice: sounddevice not available", end="")
                continue
            if not voice_active:
                session = await client.start_voice()
                streamer._send_chunk = client.send_voice_chunk  # noqa: SLF001
                streamer.start()
                voice_active = True
                print("\r[voice: listening... v to stop] ", end="", flush=True)
            else:
                await streamer.stop()
                await client.end_voice()
                voice_active = False
                print("\r[voice: stopped] ", end="", flush=True)
            continue
        code = SINGLE_KEYS.get(key)
        if code is not None:
            await client.tap_key(code)
            _print_state(client.state)


async def _send_text_interactive(client: ATVRemoteClient) -> None:
    print("\rtext> ", end="", flush=True)
    loop = asyncio.get_running_loop()
    text = await loop.run_in_executor(None, input)
    if text:
        await client.send_text(text)
        print(f"\r[sent {len(text)} chars] ", end="", flush=True)
