"""Microphone streaming to the TV's voice assistant.

Protocol (cross-validated, see EVIDENCE.md): the client sends KEYCODE_SEARCH,
the TV answers ``remote_voice_begin{session_id}``, the client echoes it and
streams ``remote_voice_payload{session_id, samples}`` where samples are
16-bit PCM, 8 kHz, mono, split into chunks of at most 20 KB (minimum 8 KB —
smaller chunks get zero-padded, otherwise some TVs drop the connection).
The session ends with ``remote_voice_end{session_id}``.

The Google Home app uses an LC3 encoder for its newer audio path (REA
evidence: com.google.android.tv.remote.virtual.audio.compression.Lc3Encoder);
the raw-PCM path above is the interoperable one used by other public clients
and works on current Google TV firmwares.
"""

from __future__ import annotations

import asyncio
from typing import Callable

import numpy as np

try:  # sounddevice is optional at import time; voice needs it at runtime
    import sounddevice as sd
except ImportError:  # pragma: no cover
    sd = None

SAMPLE_RATE = 8000
SAMPLE_WIDTH = 2  # int16
MIN_CHUNK_BYTES = 8 * 1024


class VoiceStreamer:
    """Captures the microphone and streams it to an open voice session."""

    def __init__(
        self,
        send_chunk: Callable[[bytes], "asyncio.Future[None] | None"],
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if sd is None:
            raise RuntimeError(
                "sounddevice is required for voice input: pip install sounddevice"
            )
        self._send_chunk = send_chunk
        self._loop = loop or asyncio.get_event_loop()
        self._queue: asyncio.Queue[np.ndarray] = asyncio.Queue()
        self._stream: sd.InputStream | None = None
        self._pump_task: asyncio.Task | None = None

    def _callback(self, indata, frames, time_info, status) -> None:  # noqa: ANN001
        # Called from PortAudio's audio thread: only thread-safe queue put.
        if status:
            pass
        self._loop.call_soon_threadsafe(
            self._queue.put_nowait, indata.copy()
        )

    def start(self) -> None:
        self._stream = sd.InputStream(
            samplerate=SAMPLE_RATE,
            channels=1,
            dtype="int16",
            blocksize=2048,
            callback=self._callback,
        )
        self._stream.start()
        self._pump_task = asyncio.ensure_future(self._pump())

    async def stop(self) -> None:
        if self._stream:
            self._stream.stop()
            self._stream.close()
            self._stream = None
        if self._pump_task:
            self._pump_task.cancel()
            try:
                await self._pump_task
            except asyncio.CancelledError:
                pass
            self._pump_task = None
        while not self._queue.empty():
            self._queue.get_nowait()

    async def _pump(self) -> None:
        buffer = bytearray()
        while True:
            block = await self._queue.get()
            buffer += block.tobytes()
            if len(buffer) >= MIN_CHUNK_BYTES:
                await self._send_chunk(bytes(buffer))
                buffer.clear()
