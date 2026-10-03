"""Shared data model for authentication log events.

This module is platform-agnostic: it defines the common shape that both
the Windows collector (win32evtlog) and the Linux collector (auth.log /
journalctl) normalize their raw log lines into, so detector.py never
needs to know which OS the events came from.
"""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class EventType(Enum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    OTHER = "other"


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    user: str
    event_type: EventType
    raw: str = ""
