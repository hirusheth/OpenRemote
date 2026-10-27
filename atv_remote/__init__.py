"""OpenRemote — standalone Google TV / Android TV remote control.

Protocol reverse-engineered from the Google Home app (4.34.22.2) with REA;
see EVIDENCE.md for the evidence trail.
"""

__version__ = "0.2.0"

from .client import ATVRemoteClient, RemoteConfig, TVState
from .discovery import TVDevice, discover
from .keys import KeyCode
from .wire import Capability, Direction

__all__ = [
    "ATVRemoteClient",
    "RemoteConfig",
    "TVState",
    "TVDevice",
    "discover",
    "KeyCode",
    "Capability",
    "Direction",
]
