"""Cross-platform security log pipeline.

Normalizes Windows Security-log logon events and Linux sudo/PAM auth
events into a common LogEvent shape so the same brute-force detector
runs unmodified on either OS. See collectors/ for the platform-specific
readers and detector.py for the shared analysis logic.
"""
