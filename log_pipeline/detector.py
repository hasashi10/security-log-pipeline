"""Brute-force detection over normalized LogEvents.

Ported from the sliding-window check in the original C++ prototype
(github.com/hasashi10/security-log-pipeline, src/main.cpp: hasBruteForce):
flag a user once N auth failures land within a given time window. Works
identically regardless of whether the events came from the Windows or
Linux collector, since both normalize to the same LogEvent shape.
"""
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence

from .models import EventType, LogEvent

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 600


def group_failures_by_user(events: Iterable[LogEvent]) -> Dict[str, List[LogEvent]]:
    failures: Dict[str, List[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type is EventType.AUTH_FAILURE:
            failures[event.user].append(event)
    return failures


def is_brute_force(
    events: Sequence[LogEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> bool:
    """True if `threshold` of these events occurred within `window_seconds` of each other."""
    times = sorted(e.timestamp for e in events)
    for i in range(len(times) - threshold + 1):
        window_start = times[i]
        window_end = times[i + threshold - 1]
        if (window_end - window_start).total_seconds() <= window_seconds:
            return True
    return False


def detect_brute_force(
    events: Iterable[LogEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> Dict[str, List[LogEvent]]:
    """Return {user: failure_events} for every user whose failures look like brute force."""
    failures_by_user = group_failures_by_user(events)
    return {
        user: user_events
        for user, user_events in failures_by_user.items()
        if is_brute_force(user_events, threshold, window_seconds)
    }
