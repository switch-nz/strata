"""Short descriptions for well-known Windows event IDs.

An event ID means something only together with the provider that wrote it:
ID 1 from Sysmon is a process being created, from Kernel-General it is the
system time changing. So the table is keyed by (provider, event ID), and an
event whose provider is not listed gets no description rather than a guess.

These are Strata's own one-line summaries of the documented meanings, not
the provider's message text (which lives in DLLs on the source machine and
is not read here). A missing description says nothing about the event.
"""

SECURITY = "Microsoft-Windows-Security-Auditing"
SCM = "Service Control Manager"
EVENTLOG = "Microsoft-Windows-Eventlog"

TABLE = {
    SECURITY: {
        4608: "Windows is starting up",
        4616: "The system time was changed",
        4624: "An account logged on",
        4625: "An account failed to log on",
        4634: "An account logged off",
        4647: "A user initiated logoff",
        4648: "A logon was attempted with explicit credentials",
        4657: "A registry value was modified",
        4663: "An attempt was made to access an object",
        4672: "Special privileges were assigned to a new logon",
        4688: "A new process was created",
        4689: "A process exited",
        4697: "A service was installed",
        4698: "A scheduled task was created",
        4699: "A scheduled task was deleted",
        4700: "A scheduled task was enabled",
        4701: "A scheduled task was disabled",
        4702: "A scheduled task was updated",
        4719: "The system audit policy was changed",
        4720: "A user account was created",
        4722: "A user account was enabled",
        4723: "An attempt was made to change an account's password",
        4724: "An attempt was made to reset an account's password",
        4725: "A user account was disabled",
        4726: "A user account was deleted",
        4728: "A member was added to a security-enabled global group",
        4732: "A member was added to a security-enabled local group",
        4738: "A user account was changed",
        4740: "A user account was locked out",
        4756: "A member was added to a security-enabled universal group",
        4767: "A user account was unlocked",
        4768: "A Kerberos authentication ticket (TGT) was requested",
        4769: "A Kerberos service ticket was requested",
        4771: "Kerberos pre-authentication failed",
        4776: "The computer attempted to validate an account's credentials",
        4778: "A session was reconnected to a window station",
        4779: "A session was disconnected from a window station",
        5140: "A network share object was accessed",
        5145: "A network share object was checked for access",
        5156: "The Windows Filtering Platform permitted a connection",
    },
    EVENTLOG: {
        104: "An event log was cleared",
        1100: "The event logging service shut down",
        1102: "The audit log was cleared",
    },
    "EventLog": {
        6005: "The event log service was started",
        6006: "The event log service was stopped",
        6008: "The previous system shutdown was unexpected",
        6009: "Operating system version recorded at boot",
        6013: "System uptime",
    },
    SCM: {
        7034: "A service terminated unexpectedly",
        7035: "A control request was sent to a service",
        7036: "A service entered a new state",
        7040: "A service's start type was changed",
        7045: "A service was installed",
    },
    "Microsoft-Windows-Kernel-General": {
        1: "The system time was changed",
        12: "The operating system started",
        13: "The operating system is shutting down",
    },
    "Microsoft-Windows-Kernel-Power": {
        41: "The system rebooted without cleanly shutting down first",
        42: "The system is entering sleep",
        107: "The system resumed from sleep",
    },
    "User32": {
        1074: "A process initiated a shutdown or restart",
    },
    "Microsoft-Windows-Winlogon": {
        7001: "User logon notification",
        7002: "User logoff notification",
    },
    "Microsoft-Windows-TaskScheduler": {
        106: "A scheduled task was registered",
        140: "A scheduled task was updated",
        141: "A scheduled task was deleted",
        200: "A scheduled task action started",
        201: "A scheduled task action completed",
    },
    "Microsoft-Windows-TerminalServices-LocalSessionManager": {
        21: "Remote Desktop: session logon succeeded",
        22: "Remote Desktop: shell start notification received",
        23: "Remote Desktop: session logoff succeeded",
        24: "Remote Desktop: session disconnected",
        25: "Remote Desktop: session reconnected",
    },
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager": {
        1149: "Remote Desktop: user authentication succeeded",
    },
    "Microsoft-Windows-PowerShell": {
        4103: "PowerShell module logging: a pipeline was executed",
        4104: "PowerShell script block logging: a script block was run",
    },
    "PowerShell": {
        400: "The PowerShell engine started",
        403: "The PowerShell engine stopped",
        600: "A PowerShell provider was started",
    },
    "Microsoft-Windows-Windows Defender": {
        1116: "Microsoft Defender detected malware or unwanted software",
        1117: "Microsoft Defender took action against malware",
        5001: "Microsoft Defender real-time protection was disabled",
    },
    "Microsoft-Windows-Sysmon": {
        1: "Sysmon: process created",
        3: "Sysmon: network connection",
        11: "Sysmon: file created",
        13: "Sysmon: registry value set",
        22: "Sysmon: DNS query",
    },
    "Microsoft-Windows-WLAN-AutoConfig": {
        8001: "Connected to a wireless network",
        8003: "Disconnected from a wireless network",
    },
    "Microsoft-Windows-Bits-Client": {
        59: "A BITS transfer job started",
        60: "A BITS transfer job stopped",
    },
}

LOGON_TYPES = {
    2: "interactive", 3: "network", 4: "batch", 5: "service",
    7: "unlock", 8: "network, clear text", 9: "new credentials",
    10: "remote interactive (Remote Desktop)", 11: "cached interactive",
}

_WITH_LOGON_TYPE = {(SECURITY, 4624), (SECURITY, 4625), (SECURITY, 4634)}

NOTE = ("Descriptions are Strata's own summaries of well-known event IDs, "
        "keyed by provider. They are not the message text the source "
        "machine would show, and an event without one is simply not in the "
        "table.")


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _field(fields, name):
    for k, v in (fields or {}).items():
        if k == name or k.endswith("/" + name):
            return v
    return None


def describe(provider, event_id, fields=None):
    """A one-line description, or None when (provider, ID) is not known."""
    eid = _int(event_id)
    text = TABLE.get(provider or "", {}).get(eid)
    if text is None:
        return None
    if (provider, eid) in _WITH_LOGON_TYPE:
        lt = _int(_field(fields, "LogonType"))
        if lt is not None:
            text += " (logon type %d: %s)" % (
                lt, LOGON_TYPES.get(lt, "unrecognised"))
    return text
