"""Windows collector: reads the Security event log via win32evtlog.

Only importable on Windows - win32evtlog comes from pywin32 and has no
Linux equivalent. main.py only imports this module when
platform.system() == "Windows", so the Linux side of the package never
needs pywin32 installed.
"""
from typing import Iterable

import win32evtlog

from ..models import EventType, LogEvent
from .base import Collector

# Windows Security log event IDs for logon activity.
EVENT_ID_SUCCESS = 4624
EVENT_ID_FAILURE = 4625

# Index of the target account name within StringInserts for 4624/4625.
# This layout is not officially stable across Windows versions - verify
# against a real captured event (print event.StringInserts) and adjust
# if usernames come back wrong on your machine.
_TARGET_USER_INDEX = 5


class WindowsCollector(Collector):
    def __init__(self, server: str = "localhost", log_type: str = "Security"):
        self.server = server
        self.log_type = log_type

    def collect(self) -> Iterable[LogEvent]:
        handle = win32evtlog.OpenEventLog(self.server, self.log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        try:
            while True:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for event in batch:
                    normalized = self._normalize(event)
                    if normalized is not None:
                        yield normalized
        finally:
            win32evtlog.CloseEventLog(handle)

    @staticmethod
    def _normalize(event) -> "LogEvent | None":
        if event.EventID == EVENT_ID_SUCCESS:
            event_type = EventType.AUTH_SUCCESS
        elif event.EventID == EVENT_ID_FAILURE:
            event_type = EventType.AUTH_FAILURE
        else:
            return None

        inserts = event.StringInserts or []
        user = inserts[_TARGET_USER_INDEX] if len(inserts) > _TARGET_USER_INDEX else "unknown"

        return LogEvent(
            timestamp=event.TimeGenerated,
            user=user,
            event_type=event_type,
            raw=str(inserts),
        )
