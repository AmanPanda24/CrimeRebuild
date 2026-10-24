# Created by: Aman Kumar Panda
"""Shared vocabulary used by every stage of the pipeline.

Every parser converts raw evidence into events that use these action names, so
the timeline engine and the detection rules never have to care which log a
record came from. That is the "common event schema" from the design.
"""

# --- evidence kinds -> human readable source label ---------------------------
SOURCES = {
    "eventlog": "Event Log",
    "browser": "Browser",
    "usb": "USB",
    "file": "File Log",
    "login": "Login Log",
}
KIND_CHOICES = [
    ("auto", "Auto-detect"),
    ("eventlog", "Windows Event Log (CSV/JSON)"),
    ("browser", "Browser history (Chrome/Edge/Firefox DB or CSV)"),
    ("usb", "USB activity log"),
    ("file", "File access log"),
    ("login", "Login log"),
]
SOURCE_ICONS = {
    "Event Log": "journal-text",
    "Browser": "globe2",
    "USB": "usb-drive",
    "File Log": "files",
    "Login Log": "person-badge",
}

# --- action vocabulary: action -> (category, bootstrap icon, tone) ------------
ACTIONS = {
    "Login Success": ("login", "box-arrow-in-right", "success"),
    "Login Failed": ("login", "shield-exclamation", "danger"),
    "Logoff": ("login", "box-arrow-left", "muted"),
    "USB Connected": ("usb", "usb-drive", "info"),
    "USB Disconnected": ("usb", "eject", "muted"),
    "USB Activity": ("usb", "usb-plug", "info"),
    "File Accessed": ("file", "file-earmark-text", "primary"),
    "File Copied": ("file", "copy", "warning"),
    "File Deleted": ("file", "trash3", "danger"),
    "File Modified": ("file", "pencil-square", "warning"),
    "File Created": ("file", "file-earmark-plus", "primary"),
    "File Renamed": ("file", "input-cursor-text", "warning"),
    "File Downloaded": ("web", "cloud-download", "info"),
    "URL Visited": ("web", "globe2", "muted"),
    "Webmail Opened": ("web", "envelope-open", "warning"),
    "Cloud Storage Visited": ("web", "cloud-arrow-up", "warning"),
    "Process Started": ("system", "terminal", "primary"),
    "Audit Log Cleared": ("system", "eraser", "danger"),
    "Account Created": ("system", "person-plus", "warning"),
    "Account Deleted": ("system", "person-dash", "warning"),
    "Group Membership Changed": ("system", "people", "warning"),
    "Service Installed": ("system", "gear-wide-connected", "warning"),
    "Scheduled Task Created": ("system", "calendar-event", "warning"),
    "System Boot": ("system", "power", "muted"),
    "System Shutdown": ("system", "power", "muted"),
}
DEFAULT_META = ("system", "circle", "muted")


def action_meta(action):
    return ACTIONS.get(action, DEFAULT_META)


def category_of(action):
    return action_meta(action)[0]


FILE_ACTIONS = {a for a, m in ACTIONS.items() if m[0] == "file"}

# --- Windows Security / System event ids -> action ---------------------------
EVENT_ID_ACTIONS = {
    4624: "Login Success",
    4625: "Login Failed",
    4634: "Logoff",
    4647: "Logoff",
    4648: "Login Success",          # logon with explicit credentials
    4688: "Process Started",
    4698: "Scheduled Task Created",
    4720: "Account Created",
    4726: "Account Deleted",
    4732: "Group Membership Changed",
    7045: "Service Installed",
    1102: "Audit Log Cleared",
    104: "Audit Log Cleared",
    6005: "System Boot",
    6006: "System Shutdown",
}

# --- host classification for browser history ---------------------------------
WEBMAIL_HOSTS = (
    "mail.google.com", "outlook.live.com", "outlook.office.com", "outlook.office365.com",
    "mail.yahoo.com", "mail.proton.me", "protonmail.com",
)
CLOUD_HOSTS = (
    "drive.google.com", "dropbox.com", "mega.nz", "mega.io", "wetransfer.com",
    "onedrive.live.com", "box.com", "pastebin.com", "transfer.sh", "anonfiles.com",
)

# --- severities and risk scoring ---------------------------------------------
SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_POINTS = {"low": 10, "medium": 20, "high": 35, "critical": 50}


def risk_level(score):
    """Map a 0-100 risk score to a label."""
    if score <= 0:
        return "None"
    if score < 25:
        return "Low"
    if score < 50:
        return "Medium"
    if score < 75:
        return "High"
    return "Critical"


# --- rule catalogue (title, MITRE ATT&CK reference) ---------------------------
RULE_INFO = {
    "mass_deletion": ("Mass file deletion", "T1485 Data Destruction"),
    "usb_exfiltration": ("USB data exfiltration", "T1052.001 Exfiltration over USB"),
    "off_hours_login": ("Midnight / off-hours login", "T1078 Valid Accounts"),
    "brute_force": ("Repeated failed logins", "T1110 Brute Force"),
    "file_tampering": ("File tampering", "T1070 Indicator Removal"),
}
