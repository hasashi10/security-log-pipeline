# security-log-pipeline

A small cross-platform tool that reads authentication logs — the Windows
Security event log or Linux's `sudo`/PAM auth log — and flags accounts
with signs of a brute-force attempt: several failed logins in a short
window of time.

The same detection logic runs unmodified on both operating systems. Each
OS has its own thin "collector" that knows how to read its native log
format; everything else (the data model, the brute-force check, the
report) is shared code.

## What it actually does

1. Reads whatever auth log your OS provides.
2. Normalizes every entry into one common shape: `(timestamp, user, event_type)`.
3. Groups failed-login events by username.
4. Flags a user if `N` of their failures occurred within `W` seconds of
   each other (defaults: 5 failures / 600 seconds).
5. Prints a report to the terminal.

That's it — it only reads and prints. It does not write to a file,
database, or network endpoint, and it does not modify the source log in
any way. Nothing it prints is persisted anywhere once the process exits;
the only durable record is the OS's own log file, which exists with or
without this tool.

## How it's structured

```
main.py                        entry point - picks a collector based on platform.system()
log_pipeline/
  models.py                    shared LogEvent / EventType - the common shape both OSes map into
  detector.py                  brute-force sliding-window check (OS-agnostic)
  collectors/
    base.py                    Collector interface
    windows.py                 reads Security.evtx via win32evtlog (event IDs 4624/4625)
    linux.py                   parses sudo/PAM auth-log lines (same format as data/sudo_events.txt)
data/sudo_events.txt           sample Linux auth log, for local testing without a real system log
```

**Data flow:**

```
OS log (Security.evtx  or  /var/log/auth.log)
        │
        ▼
 platform-specific Collector.collect()
        │   normalizes each entry into LogEvent(timestamp, user, event_type)
        ▼
   in-memory list of LogEvent
        │
        ▼
   detector.py: group failures by user, slide a time window per user
        │
        ▼
   printed report (terminal only - nothing written to disk)
```

## Requirements

```
pip install -r requirements.txt
```

`pywin32` is only installed on Windows (`sys_platform == "win32"` marker
in `requirements.txt`) — nothing extra is needed on Linux.

## Usage

### Windows

Reading the Security event log requires administrator privileges.

```powershell
# Open PowerShell/Terminal as Administrator, then:
python main.py
```

If you see `pywintypes.error: (1314, 'OpenEventLogW', 'A required
privilege is not held by the client.')`, the terminal isn't elevated —
re-open it as Administrator.

If logon auditing isn't enabled on your machine, you may see `Parsed 0
events`. Enable it with:
```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

### Linux

No special privileges needed to read a log you have access to.

```bash
# Default source: /var/log/auth.log
python3 main.py

# Or point it at any file in the same format, e.g. the bundled sample:
python3 main.py data/sudo_events.txt
```

## Detection logic

The brute-force check (`log_pipeline/detector.py`) is a straightforward
sliding-window test, ported from an earlier C++ prototype of this
project:

- Collect every `AUTH_FAILURE` event for a given user, sorted by time.
- Slide a window of `threshold` consecutive failures (default 5) across
  that list.
- If any such window spans `window_seconds` or less (default 600 = 10
  minutes), that user is flagged as a brute-force suspect.

Both values are parameters to `detect_brute_force()` / `is_brute_force()`
if you want to tune sensitivity.

## Known limitations

- **Windows username extraction** (`windows.py`, `_TARGET_USER_INDEX`)
  pulls the account name from a fixed index into the event's
  `StringInserts` array. This layout isn't officially guaranteed stable
  across Windows versions — if usernames come back wrong, print
  `event.StringInserts` for a real captured event and adjust the index.
- This is a read-only reporting tool, not a monitoring daemon — it takes
  a single snapshot of the log each time you run it rather than
  watching continuously.
