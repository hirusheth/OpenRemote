"""Android KeyEvent key codes (AOSP values) — the wire values for keys.

Evidence: the remote sends raw Android keycodes. REA ev_36c64e38 (vko.r) shows
volume up/down arriving as 24/25, home as 3, back as 4, dpad 19-23, and the
public protocol's RemoteKeyCode enum is the AOSP keycode list verbatim.
"""

from enum import IntEnum


class KeyCode(IntEnum):
    DPAD_UP = 19
    DPAD_DOWN = 20
    DPAD_LEFT = 21
    DPAD_RIGHT = 22
    DPAD_CENTER = 23
    BACK = 4
    HOME = 3
    VOLUME_UP = 24
    VOLUME_DOWN = 25
    VOLUME_MUTE = 164
    POWER = 26
    MENU = 82
    SEARCH = 84
    ASSIST = 231
    ENTER = 66
    DEL = 67
    MEDIA_PLAY_PAUSE = 85
    MEDIA_STOP = 86
    MEDIA_NEXT = 87
    MEDIA_PREVIOUS = 88
    MEDIA_REWIND = 89
    MEDIA_FAST_FORWARD = 90
    CHANNEL_UP = 166
    CHANNEL_DOWN = 167
    INFO = 165
    GUIDE = 172
    SETTINGS = 176
    TV_INPUT = 178
    KEYCODE_0 = 7
    KEYCODE_1 = 8
    KEYCODE_2 = 9
    KEYCODE_3 = 10
    KEYCODE_4 = 11
    KEYCODE_5 = 12
    KEYCODE_6 = 13
    KEYCODE_7 = 14
    KEYCODE_8 = 15
    KEYCODE_9 = 16


#: Remote buttons -> Android keycodes.
BUTTONS = {
    "dpad_up": KeyCode.DPAD_UP,
    "dpad_down": KeyCode.DPAD_DOWN,
    "dpad_left": KeyCode.DPAD_LEFT,
    "dpad_right": KeyCode.DPAD_RIGHT,
    "dpad_center": KeyCode.DPAD_CENTER,
    "back": KeyCode.BACK,
    "home": KeyCode.HOME,
    "menu": KeyCode.MENU,
    "search": KeyCode.SEARCH,
    "volume_up": KeyCode.VOLUME_UP,
    "volume_down": KeyCode.VOLUME_DOWN,
    "volume_mute": KeyCode.VOLUME_MUTE,
    "power": KeyCode.POWER,
    "play_pause": KeyCode.MEDIA_PLAY_PAUSE,
    "next": KeyCode.MEDIA_NEXT,
    "previous": KeyCode.MEDIA_PREVIOUS,
}
