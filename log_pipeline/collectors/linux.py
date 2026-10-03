"""Linux collector: parses sudo/PAM auth lines.

Reads from /var/log/auth.log (Debian/Ubuntu) by default, but any file in
the same syslog-style format works - including data/sudo_events.txt,
the sample captured on Fedora and used for local testing. The parsing
rules mirror the original C++ prototype (src/main.cpp: parseLine) so
logs already captured in that format keep working.
"""
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from ..models import EventType, LogEvent
from .base import Collector

# Matches "2026-09-22T14:38:30-04:00" at the start of each line.
_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})")
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

# \b before "user=" avoids matching the tail of "ruser=" / "logname=".
_AUTH_FAILURE_RE = re.compile(r"authentication failure.*\buser=(\S+)")
_COMMAND_RE = re.compile(r"COMMAND=")
_INCORRECT_ATTEMPTS_RE = re.compile(r"incorrect password attempts")


def _parse_line(line: str) -> Optional[LogEvent]:
    match = _TIMESTAMP_RE.match(line)
    if not match:
        return None
    timestamp = datetime.strptime(match.group(1), _TIMESTAMP_FORMAT)

    failure_match = _AUTH_FAILURE_RE.search(line)
    if failure_match:
        return LogEvent(timestamp=timestamp, user=failure_match.group(1), event_type=EventType.AUTH_FAILURE, raw=line)

    if _COMMAND_RE.search(line) and not _INCORRECT_ATTEMPTS_RE.search(line):
        return LogEvent(timestamp=timestamp, user="unknown", event_type=EventType.AUTH_SUCCESS, raw=line)

    return LogEvent(timestamp=timestamp, user="unknown", event_type=EventType.OTHER, raw=line)


class LinuxCollector(Collector):
    def __init__(self, log_path: str = "/var/log/auth.log"):
        self.log_path = Path(log_path)

    def collect(self) -> Iterable[LogEvent]:
        with self.log_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                event = _parse_line(line)
                if event is not None:
                    yield event
