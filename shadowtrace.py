#!/usr/bin/env python3
"""ShadowTrace - a read-only Windows keylogger / suspicious-software auditing tool.

ShadowTrace inspects a Windows computer for *indicators* that may be associated
with keyloggers or other unwanted software and writes an evidence-based report.
It is a defensive auditing tool: it never records keystrokes, installs hooks,
injects into processes, terminates processes, deletes files, edits the registry
or uploads anything. Everything it reports is an investigation lead, not a
malware verdict.

Usage (Windows PowerShell or CMD)::

    python shadowtrace.py scan
    python shadowtrace.py scan --output reports --format all
    python shadowtrace.py scan --quick
    python shadowtrace.py info
    python shadowtrace.py rules

The whole implementation lives in this one file. Optional supporting files are
``requirements.txt``, ``README.md`` and ``test_shadowtrace.py``.
"""

import copy
import getpass
import hashlib
import html
import json
import logging
import ntpath
import os
import platform
import re
import stat
import struct
# subprocess is used only by CommandRunner, to start three fixed, read-only Windows tools by absolute path.
import subprocess  # nosec B404
import sys
import time
import uuid
import webbrowser
# XML input is local (Task Scheduler files, wevtutil output) and DTD/entity declarations are rejected before parsing.
import xml.etree.ElementTree as ET  # nosec B405
from collections import Counter
from dataclasses import dataclass, field, fields, is_dataclass
from dataclasses import replace as dc_replace
from datetime import datetime, timezone
from enum import Enum, IntEnum
from pathlib import Path
from typing import Annotated, Any, Callable, Optional, Protocol

__version__ = "2.0.0"
TOOL_NAME = "ShadowTrace"
TAGLINE = "Read-only Windows threat assessment: keyloggers, malware, persistence and rootkit indicators"
MIN_PYTHON = (3, 11)

# --------------------------------------------------------------------------- #
# Optional third-party / platform imports (all guarded so we can explain
# what is missing instead of crashing with an unclear traceback).
# --------------------------------------------------------------------------- #
try:
    import psutil
except ImportError:  # reported by main() / the checks themselves
    psutil = None  # type: ignore[assignment]

try:
    import winreg  # type: ignore[import-not-found]  # Windows only
except ImportError:
    winreg = None  # type: ignore[assignment]

try:
    import typer
except ImportError:
    typer = None  # type: ignore[assignment]

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:
    Console = None  # type: ignore[assignment,misc]

IS_WINDOWS = sys.platform == "win32"

log = logging.getLogger("shadowtrace")
log.addHandler(logging.NullHandler())

# Check status values used in reports.
COMPLETED = "completed"
PARTIAL = "partial"
SKIPPED = "skipped"
FAILED = "failed"
NOT_IN_MODE = "not_in_mode"  # check deliberately omitted by the chosen scan mode


# --------------------------------------------------------------------------- #
# Basic enums and helpers
# --------------------------------------------------------------------------- #
class Severity(IntEnum):
    """Finding severity. Higher values are more significant."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        """Parse a severity name such as ``"high"``."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown severity: {value!r}") from exc


class Confidence(IntEnum):
    """How much the observed evidence supports the finding's interpretation."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def safe_str(value: Any) -> str:
    """Return a printable, UTF-8-safe string for arbitrary system metadata.

    Handles ``None``, lone surrogates from undecodable file names, and control
    characters that would break reports or terminals.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = text.encode("utf-8", "replace").decode("utf-8", "replace")
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return _CONTROL_RE.sub("?", text)


def utc_now() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(timezone.utc)


def iso_from_ts(ts: Optional[float]) -> Optional[str]:
    """Convert an epoch timestamp to an ISO-8601 UTC string (or ``None``)."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


# Secret redaction ----------------------------------------------------------- #
# Words whose following argument is redacted. This is a keyword list, not a credential.
_REDACTION_KEYWORDS = (
    r"password|passwd|pwd|pass|pw|token|secret|api[-_]?key|access[-_]?key|key|auth|authorization|credential|cred"
)
_SECRET_FLAG_RE = re.compile(
    r"(?i)(?P<prefix>(?:^|[\s,;])[-/]{1,2}(?:" + _REDACTION_KEYWORDS + r")s?(?:[=:]|\s+))"
    r"(?P<value>\"[^\"]*\"|'[^']*'|\S+)"
)
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(?P<prefix>(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|authorization)\s*[=:]\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s;&]+)"
)
_URL_CREDS_RE = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@")
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{40,}")


def _redact_long_token(match: "re.Match[str]") -> str:
    token = match.group(0)
    has_letter = any(c.isalpha() for c in token)
    has_digit = any(c.isdigit() for c in token)
    if has_letter and has_digit:
        return f"<redacted:{len(token)} chars>"
    return token


def sanitize_text(text: Any, max_len: int = 300) -> str:
    """Make arbitrary command-line style text safe to store in a report.

    Redacts likely secrets (password/token style arguments, credentials inside
    URLs, bearer tokens and long opaque tokens), strips control characters and
    truncates to ``max_len`` characters.
    """
    cleaned = safe_str(text)
    cleaned = _BEARER_RE.sub(lambda m: m.group(1) + " <redacted>", cleaned)
    cleaned = _SECRET_FLAG_RE.sub(lambda m: m.group("prefix") + "<redacted>", cleaned)
    cleaned = _SECRET_ASSIGN_RE.sub(lambda m: m.group("prefix") + "<redacted>", cleaned)
    cleaned = _URL_CREDS_RE.sub(r"\1\2:<redacted>@", cleaned)
    cleaned = _LONG_TOKEN_RE.sub(_redact_long_token, cleaned)
    if len(cleaned) > max_len:
        extra = len(cleaned) - max_len
        cleaned = f"{cleaned[:max_len]}...[truncated {extra} chars]"
    return cleaned


def sha256_file(
    path: str, max_bytes: Optional[int] = None, chunk_size: int = 1024 * 1024,
    deadline: Optional["Deadline"] = None,
) -> tuple[Optional[str], Optional[str]]:
    """Compute a file's SHA-256 digest by streaming it (read-only).

    Returns ``(hexdigest, None)`` on success or ``(None, reason)`` on failure.
    """
    try:
        st = os.stat(path)
        if stat.S_ISDIR(st.st_mode):
            return None, "path is a directory"
        if max_bytes is not None and st.st_size > max_bytes:
            return None, f"skipped: file is larger than the {max_bytes}-byte hashing limit"
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                if deadline is not None and deadline.expired():
                    return None, "skipped: scan time limit reached"
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest(), None
    except FileNotFoundError:
        return None, "file not found"
    except PermissionError:
        return None, "access denied"
    except (OSError, ValueError) as exc:
        return None, f"could not read file: {safe_str(exc)}"


class Deadline:
    """A simple monotonic time budget used to bound scan duration."""

    def __init__(self, seconds: Optional[float], clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._end = None if seconds is None else clock() + seconds

    def expired(self) -> bool:
        """True once the time budget has been used up."""
        return self._end is not None and self._clock() >= self._end

    def remaining(self) -> Optional[float]:
        """Seconds left in the budget (None when the budget is unlimited)."""
        if self._end is None:
            return None
        return max(0.0, self._end - self._clock())


def is_elevated() -> Optional[bool]:
    """Return True/False if administrator rights can be determined, else None."""
    try:
        if IS_WINDOWS:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
    except (AttributeError, OSError):
        return None
    return None


def describe_os() -> str:
    """Short OS description from direct API calls (the platform module's summary helpers can start helper processes)."""
    try:
        if IS_WINDOWS:
            version = sys.getwindowsversion()  # type: ignore[attr-defined]
            name = "Windows 11" if version.build >= 22000 else "Windows 10" if version.major >= 10 else "Windows"
            return f"{name} (version {version.major}.{version.minor}, build {version.build}, {platform.machine() or 'unknown arch'})"
        uname = os.uname()
        return f"{uname.sysname} {uname.release} ({uname.machine})"
    except (AttributeError, OSError):
        return safe_str(sys.platform)


def windows_directory_from_api() -> Optional[str]:
    """The Windows directory as reported by Windows itself, or ``None`` if it cannot be determined.

    Environment variables are never consulted (whoever starts the program can change them), and there is no
    guessed default: the result decides which programs ShadowTrace is willing to launch, so when it is unknown
    no external program is started at all and the affected checks are reported as skipped.
    """
    if not IS_WINDOWS:
        return None
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buffer, 260):  # type: ignore[attr-defined]
            return buffer.value
    except (AttributeError, OSError):
        pass  # unknown: callers must treat None as "do not launch anything"
    return None


def default_system_root() -> str:
    """Windows directory used for path *comparisons* only (rules, expected folders); never used to launch programs."""
    return windows_directory_from_api() or "C:\\Windows"


def is_wow64_python() -> bool:
    """True when a 32-bit Python runs on 64-bit Windows (file-system redirection)."""
    return (
        IS_WINDOWS
        and struct.calcsize("P") * 8 == 32
        and bool(os.environ.get("PROCESSOR_ARCHITEW6432"))
    )


# --------------------------------------------------------------------------- #
# Path helpers and transparent location rules
# --------------------------------------------------------------------------- #
def norm_path(path: str) -> str:
    """Normalise a Windows-style path for case-insensitive comparison."""
    text = safe_str(path).replace("/", "\\")
    if text.startswith("\\\\?\\"):
        text = text[4:]
    return ntpath.normpath(text).lower()


@dataclass(frozen=True)
class LocationRule:
    """A transparent rule describing a directory that deserves a second look."""

    key: str
    pattern: "re.Pattern[str]"
    process_severity: Severity
    persistence_severity: Severity
    label: str
    why: str


# Order matters: the first matching rule wins, so the most significant come first.
LOCATION_RULES: tuple[LocationRule, ...] = (
    LocationRule(
        "temp",
        re.compile(r"\\(?:temp|tmp)\\"),
        Severity.MEDIUM,
        Severity.HIGH,
        "temporary directory",
        "Temporary folders are writable by any user-level program and are a common staging area.",
    ),
    LocationRule(
        "recycle",
        re.compile(r"\\\$recycle\.bin\\"),
        Severity.MEDIUM,
        Severity.HIGH,
        "Recycle Bin",
        "Legitimate software does not normally run from the Recycle Bin.",
    ),
    LocationRule(
        "public",
        re.compile(r"\\users\\public\\"),
        Severity.LOW,
        Severity.MEDIUM,
        "Public user folder",
        "The Public profile is writable by all users and rarely hosts installed software.",
    ),
    LocationRule(
        "downloads",
        re.compile(r"\\downloads\\"),
        Severity.LOW,
        Severity.MEDIUM,
        "Downloads folder",
        "Files here were usually just downloaded and may never have been reviewed.",
    ),
    LocationRule(
        "roaming",
        re.compile(r"\\appdata\\roaming\\"),
        Severity.LOW,
        Severity.LOW,
        "AppData\\Roaming",
        "A per-user folder that both legitimate apps and malware can write to.",
    ),
    LocationRule(
        "programdata",
        re.compile(r"\\programdata\\(?!microsoft\\)"),
        Severity.LOW,
        Severity.LOW,
        "ProgramData",
        "A machine-wide writable data folder that is not normally used for executables.",
    ),
)

TRUSTED_INSTALL_RE = re.compile(r"^[a-z]:\\(?:program files(?: \(x86\))?|windows)\\")


def match_location(path: str) -> Optional[LocationRule]:
    """Return the first location rule matching ``path`` (or ``None``)."""
    normalised = norm_path(path)
    for rule in LOCATION_RULES:
        if rule.pattern.search(normalised):
            return rule
    return None


EXECUTABLE_EXTENSIONS = frozenset(
    {".exe", ".dll", ".scr", ".com", ".sys", ".cpl", ".msi", ".bat", ".cmd", ".ps1",
     ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".pif", ".lnk"}
)
RUNNABLE_EXTENSIONS = frozenset(
    {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".pif", ".cpl", ".msi", ".dll"}
)
DECEPTIVE_EXTENSIONS = frozenset(
    {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg",
     ".png", ".gif", ".bmp", ".zip", ".rar", ".7z", ".mp3", ".mp4"}
)
DOUBLE_EXT_RE = re.compile(
    r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|bmp|zip|rar|7z|mp3|mp4)\s*\.(?:exe|scr|com|bat|cmd|pif|js|vbs|hta)$"
)

# Names attackers like to imitate, with the sub-folders of %SystemRoot% in which
# the genuine binary lives ("" means %SystemRoot% itself).
SYSTEM_PROCESS_EXPECTED: dict[str, tuple[str, ...]] = {
    "svchost.exe": ("system32", "syswow64"),
    "lsass.exe": ("system32",),
    "csrss.exe": ("system32",),
    "winlogon.exe": ("system32",),
    "wininit.exe": ("system32",),
    "services.exe": ("system32",),
    "smss.exe": ("system32",),
    "spoolsv.exe": ("system32",),
    "taskhostw.exe": ("system32",),
    "dwm.exe": ("system32",),
    "conhost.exe": ("system32",),
    "sihost.exe": ("system32",),
    "ctfmon.exe": ("system32", "syswow64"),
    "fontdrvhost.exe": ("system32",),
    "runtimebroker.exe": ("system32",),
    "searchindexer.exe": ("system32",),
    "explorer.exe": ("",),
}
EXPECTED_PARENTS: dict[str, frozenset[str]] = {
    "svchost.exe": frozenset({"services.exe"}),
    "lsass.exe": frozenset({"wininit.exe"}),
    "services.exe": frozenset({"wininit.exe"}),
}
OFFICE_APPS = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"})
SCRIPT_HOSTS = frozenset({"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"})
LOLBINS = frozenset(
    {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
)
MULTI_INSTANCE_OK = frozenset(
    {"svchost.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "conhost.exe",
     "runtimebroker.exe", "code.exe", "teams.exe", "slack.exe", "discord.exe", "node.exe", "python.exe",
     "dllhost.exe", "backgroundtaskhost.exe", "msedgewebview2.exe", "electron.exe", "java.exe", "cmd.exe"}
)
ENCODED_CMD_RE = re.compile(r"(?i)(?:^|\s)[-/](?:e|ec|enc|encodedcommand)\s+\S")
HIDDEN_WINDOW_RE = re.compile(r"(?i)(?:^|\s)[-/](?:w|win|windowstyle)\s+(?:hidden|h)\b")


def looks_randomized(stem: str) -> Optional[str]:
    """Describe why a process-name stem looks machine-generated, or return ``None``."""
    text = stem.lower()
    if re.fullmatch(r"[a-f0-9]{16,}", text):
        return "long hexadecimal-only name"
    if len(text) >= 10 and re.fullmatch(r"[a-z]+", text):
        vowels = sum(1 for ch in text if ch in "aeiou")
        if vowels / len(text) < 0.2:
            return "long name containing almost no vowels"
    if len(text) == 1:
        return "single-character name"
    return None


# --------------------------------------------------------------------------- #
# Command-line parsing for startup entries
# --------------------------------------------------------------------------- #
_PROGRAM_EXTENSIONS = "exe|bat|cmd|com|scr|vbs|vbe|js|jse|wsf|hta|ps1|dll|lnk|msi|cpl|sys"
_PROGRAM_RE = re.compile(r"^(.*?\.(?:" + _PROGRAM_EXTENSIONS + r"))(?=$|[\s,\"])", re.IGNORECASE)


def expand_env_vars(text: str, env: dict[str, str]) -> str:
    """Expand ``%NAME%`` references using ``env`` (case-insensitive, unknown names kept)."""
    lookup = {key.lower(): value for key, value in env.items()}

    def replace(match: "re.Match[str]") -> str:
        value = lookup.get(match.group(1).lower())
        return value if value is not None else match.group(0)

    return re.sub(r"%([^%\s]+)%", replace, text)


def parse_command(command: str, env: Optional[dict[str, str]] = None, system_root: str = "") -> tuple[str, str]:
    """Split a startup command into ``(program, arguments)``.

    Handles quoted paths, unquoted paths that contain spaces, ``%VAR%``
    expansion and the ``\\SystemRoot\\`` prefix used by some service entries.
    """
    text = expand_env_vars(command.strip(), env or {})
    if system_root and text.lower().startswith("\\systemroot\\"):
        text = system_root.rstrip("\\") + text[len("\\SystemRoot"):]
    if not text:
        return "", ""
    if text.startswith('"'):
        end = text.find('"', 1)
        if end == -1:
            return text[1:], ""
        return text[1:end], text[end + 1:].strip()
    if re.match(r"^(?:[A-Za-z]:[\\/]|\\\\)", text):
        # Absolute unquoted path: it may contain spaces, so match up to the first program extension.
        match = _PROGRAM_RE.match(text)
        if match:
            return match.group(1), text[match.end():].strip()
    parts = text.split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def resolve_target(program: str) -> Optional[str]:
    """Return ``program`` if it is an absolute, fully expanded path, else ``None``."""
    candidate = program.strip().strip('"')
    if not candidate or "%" in candidate:
        return None
    if re.match(r"^[A-Za-z]:[\\/]", candidate) or candidate.startswith("\\\\"):
        return candidate
    return None


def program_basename(program: str) -> str:
    """Lower-case file name of a program, adding ``.exe`` to extension-less names."""
    base = ntpath.basename(program.strip().strip('"').replace("/", "\\")).lower()
    if base and "." not in base:
        base += ".exe"
    return base


# --------------------------------------------------------------------------- #
# Script / command-line pattern analysis (static text matching only - nothing is ever executed)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CommandPattern:
    """A documented heuristic for obfuscated, downloading or evasive commands."""

    pid: str
    regex: "re.Pattern[str]"
    label: str
    family: str      # encoding | download | execution | evasion | obfuscation
    weight: int      # 1 (weak) .. 3 (strong)
    scope: str       # cmd | script | both


def _pattern(pid: str, regex: str, label: str, family: str, weight: int, scope: str = "both") -> CommandPattern:
    return CommandPattern(pid, re.compile(regex, re.IGNORECASE), label, family, weight, scope)


COMMAND_PATTERNS: tuple[CommandPattern, ...] = (
    _pattern("encoded_command", r"(?:^|\s)[-/](?:e|ec|enc|encodedcommand)\s+\S", "Encoded command argument",
             "encoding", 2, "cmd"),
    _pattern("hidden_window", r"(?:^|\s)[-/](?:w|win|windowstyle)\s+(?:hidden|h)\b", "Hidden window style",
             "evasion", 1, "cmd"),
    _pattern("policy_bypass", r"[-/](?:executionpolicy|ep)\s+(?:bypass|unrestricted)",
             "Execution-policy bypass", "evasion", 1, "cmd"),
    _pattern("base64_decode", r"FromBase64String|certutil(?:\.exe)?[^\r\n]{0,120}\s-decode",
             "Base64 decoding", "encoding", 2),
    _pattern("download", r"DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Start-BitsTransfer"
                         r"|bitsadmin(?:\.exe)?[^\r\n]{0,100}/transfer|certutil(?:\.exe)?[^\r\n]{0,120}-urlcache"
                         r"|Net\.WebClient|\bcurl(?:\.exe)?\s[^\r\n]{0,100}https?://|\bwget\s",
             "Download from the network", "download", 2),
    _pattern("invoke_expression", r"\b(?:Invoke-Expression|iex)\b", "Dynamic code execution (Invoke-Expression)",
             "execution", 2),
    _pattern("in_memory_load", r"Reflection\.Assembly\]?::Load|Assembly\]::Load|VirtualAlloc|WriteProcessMemory"
                               r"|CreateRemoteThread", "In-memory code loading / injection APIs", "execution", 3),
    _pattern("amsi_tamper", r"AmsiUtils|amsiInitFailed|AmsiScanBuffer", "AMSI tampering strings", "evasion", 3),
    _pattern("defender_tamper", r"Set-MpPreference[^\r\n]{0,120}-Disable|Add-MpPreference[^\r\n]{0,120}-Exclusion",
             "Microsoft Defender tampering", "evasion", 3),
    _pattern("remote_script_host", r"mshta(?:\.exe)?\s+(?:https?:|vbscript:|javascript:)"
                                   r"|regsvr32(?:\.exe)?[^\r\n]{0,60}(?:/i:https?|scrobj\.dll)"
                                   r"|rundll32(?:\.exe)?[^\r\n]{0,60}(?:javascript:|url\.dll,\s*FileProtocolHandler)",
             "Script host fetching or running remote content", "execution", 3),
    _pattern("wscript_shell", r"WScript\.Shell|Shell\.Application|ActiveXObject", "Windows scripting host objects",
             "execution", 1, "script"),
    _pattern("char_code_obfuscation", r"(?:\[char\]\s*\d{2,3}\s*[,+]?\s*){8,}|(?:\bchr\(\s*\d+\s*\)\s*&\s*){8,}",
             "Character-code string building", "obfuscation", 2, "script"),
    _pattern("concat_obfuscation", r"(?:'[^'\r\n]{0,3}'\s*\+\s*){10,}", "Heavy string concatenation",
             "obfuscation", 1, "script"),
    _pattern("long_base64", r"[A-Za-z0-9+/]{300,}={0,2}", "Very long Base64-like blob", "encoding", 2, "script"),
)
MAX_PATTERN_TEXT = 512 * 1024
SCRIPT_EXTENSIONS = frozenset({".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd"})


def scan_patterns(text: str, scope: str = "cmd") -> list[CommandPattern]:
    """Return the documented patterns found in ``text`` (``scope`` is ``cmd`` or ``script``)."""
    if not text:
        return []
    sample = text[:MAX_PATTERN_TEXT]
    return [p for p in COMMAND_PATTERNS if p.scope in (scope, "both") and p.regex.search(sample)]


def classify_pattern_hits(hits: list[CommandPattern]) -> Optional[tuple[Severity, Confidence]]:
    """Map pattern hits to a severity/confidence. A single weak hit stays LOW; nothing is ever 'confirmed'."""
    if not hits:
        return None
    total = sum(h.weight for h in hits)
    families = {h.family for h in hits}
    if ("download" in families and "execution" in families) or total >= 6:
        return Severity.HIGH, Confidence.MEDIUM
    if total >= 3 or len(families) >= 2:
        return Severity.MEDIUM, Confidence.MEDIUM
    return Severity.LOW, Confidence.LOW


def describe_hits(hits: list[CommandPattern]) -> str:
    """Human-readable list of pattern labels."""
    return "; ".join(f"{h.label} [{h.family}]" for h in hits)


# Keyboard-capture API *names* (a capability indicator, not proof of keylogging) -------------------- #
KEYBOARD_API_RE = re.compile(
    rb"SetWindowsHookEx[AW]?|GetAsyncKeyState|GetKeyboardState|RegisterRawInputDevices|GetRawInputData"
    rb"|GetForegroundWindow|GetWindowText[AW]?"
)
KEYBOARD_CAPTURE_APIS = frozenset({"SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState",
                                   "RegisterRawInputDevices", "GetRawInputData"})
KEYBOARD_CONTEXT_APIS = frozenset({"GetForegroundWindow", "GetWindowText"})


def normalise_api_name(raw: bytes) -> str:
    """Strip the ANSI/Unicode suffix from an API name found in a binary."""
    name = raw.decode("ascii", "replace")
    if name.endswith(("A", "W")) and name[:-1] in ("SetWindowsHookEx", "GetWindowText"):
        name = name[:-1]
    return name


def classify_keyboard_apis(names: set[str]) -> Optional[list[str]]:
    """Return the API names if they suggest keyboard capture (capture API plus another capture/context API)."""
    capture = names & KEYBOARD_CAPTURE_APIS
    context = names & KEYBOARD_CONTEXT_APIS
    if capture and (len(capture) >= 2 or context):
        return sorted(capture | context)
    return None


def parse_pe_signature_flag(header: bytes) -> Optional[bool]:
    """Whether a PE header declares an embedded certificate table (presence only - NOT a validity check).

    Returns None when ``header`` is not a parsable PE header. Catalog-signed Windows files carry no embedded
    certificate, so ``False`` does not mean "unsigned".
    """
    try:
        if header[:2] != b"MZ" or len(header) < 0x40:
            return None
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        if header[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None
        optional = pe_offset + 24
        magic = struct.unpack_from("<H", header, optional)[0]
        if magic == 0x10B:
            directories = optional + 96
        elif magic == 0x20B:
            directories = optional + 112
        else:
            return None
        _address, size = struct.unpack_from("<II", header, directories + 4 * 8)
        return size > 0
    except (struct.error, IndexError):
        return None


# Known-hash intelligence (local only - ShadowTrace ships no malware signatures and does no lookups) ---- #
KNOWN_TEST_HASHES: dict[str, str] = {
    # SHA-256 of the industry-standard, harmless EICAR antivirus test file (stored as a hash so that this
    # source file does not itself contain the test string and trigger antivirus products).
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR standard antivirus test file",
}
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class IntelEntry:
    """One entry of a user-supplied known-hash list."""

    sha256: str
    label: str
    source: str


class ThreatIntel:
    """Known-hash lists the user supplied with --hash-list (plain text, one SHA-256 per line, optional label)."""

    MAX_FILE_BYTES = 64 * 1024 * 1024
    MAX_ENTRIES = 2_000_000

    def __init__(self) -> None:
        self.entries: dict[str, IntelEntry] = {}
        self.sources: list[str] = []
        self.rejected_lines = 0
        self.errors: list[str] = []

    @classmethod
    def load(cls, paths: list[str]) -> "ThreatIntel":
        """Read the lists; unreadable or malformed content is reported, never fatal."""
        intel = cls()
        for raw in paths:
            name = safe_str(os.path.basename(raw)) or safe_str(raw)
            try:
                if os.stat(raw).st_size > cls.MAX_FILE_BYTES:
                    intel.errors.append(f"{name}: larger than {cls.MAX_FILE_BYTES} bytes, not loaded")
                    continue
                with open(raw, "r", encoding="utf-8", errors="replace") as handle:
                    count = 0
                    for line in handle:
                        text = line.strip()
                        if not text or text.startswith("#"):
                            continue
                        parts = [p.strip() for p in re.split(r"[,\t;]", text, maxsplit=2)]
                        if not _HEX64_RE.match(parts[0]):
                            intel.rejected_lines += 1
                            continue
                        if len(intel.entries) >= cls.MAX_ENTRIES:
                            intel.errors.append(f"{name}: entry limit reached")
                            break
                        label = safe_str(parts[1])[:80] if len(parts) > 1 and parts[1] else "unlabelled"
                        intel.entries.setdefault(parts[0].lower(), IntelEntry(parts[0].lower(), label, name))
                        count += 1
                intel.sources.append(f"{name} ({count} hashes)")
            except (OSError, ValueError) as exc:
                intel.errors.append(f"{name}: could not be read ({safe_str(exc)})")
        return intel

    def lookup(self, sha256: Optional[str]) -> Optional[IntelEntry]:
        """Return the entry for ``sha256`` (case-insensitive), if any."""
        return self.entries.get(sha256.lower()) if sha256 else None

    def describe(self) -> str:
        """Short description for reports."""
        if not self.sources and not self.errors:
            return "No user-supplied known-hash list was loaded."
        text = f"{len(self.entries)} known-hash entries from: {', '.join(self.sources) or 'none'}"
        if self.rejected_lines:
            text += f"; {self.rejected_lines} unparsable lines ignored"
        if self.errors:
            text += "; problems: " + "; ".join(self.errors)
        return text


# --------------------------------------------------------------------------- #
# Scan modes
# --------------------------------------------------------------------------- #
CHECK_LABELS: dict[str, str] = {
    "process_inventory": "Running-process inventory",
    "registry_autoruns": "Registry startup keys",
    "registry_config": "Registry execution-hijack settings",
    "startup_folders": "Startup folders",
    "services": "Auto-start Windows services",
    "scheduled_tasks": "Scheduled tasks",
    "wmi_persistence": "WMI event subscriptions",
    "drivers": "Kernel drivers",
    "security_settings": "Security settings",
    "file_sweep": "Suspicious-file sweep",
    "file_analysis": "Selected file analysis",
    "telemetry_defender": "Microsoft Defender status",
    "defender_detections": "Microsoft Defender detection history",
    "event_logs": "PowerShell event-log evidence",
    "detection_rules": "Detection rules",
    "risk_scoring": "Risk scoring",
}
# Checks that run in every mode (file analysis is skipped when no --path is given).
ALWAYS_RUN_CHECKS = frozenset({"file_analysis", "detection_rules", "risk_scoring"})


@dataclass(frozen=True)
class ModeProfile:
    """What one scan mode checks (and, just as important, what it leaves out)."""

    name: str
    summary: str
    checks: frozenset[str]
    hash_files: bool
    inspect_content: bool
    time_limit: float
    hash_limit: int
    sweep_limit: int
    omits: str


MODE_PROFILES: dict[str, ModeProfile] = {
    "quick": ModeProfile(
        "quick",
        "Common keylogger indicators: running processes plus the highest-value persistence locations.",
        frozenset({"process_inventory", "registry_autoruns", "startup_folders"}),
        hash_files=False, inspect_content=False, time_limit=45.0, hash_limit=0, sweep_limit=0,
        omits="No hashing or file-content inspection, services, scheduled tasks, WMI, drivers, security settings, "
              "Defender or event logs.",
    ),
    "full": ModeProfile(
        "full",
        "The broadest practical inspection: processes, files, every supported persistence location, services, "
        "scheduled tasks, WMI, drivers, security settings, Defender and PowerShell event-log evidence.",
        frozenset({"process_inventory", "registry_autoruns", "registry_config", "startup_folders", "services",
                   "scheduled_tasks", "wmi_persistence", "drivers", "security_settings", "file_sweep",
                   "telemetry_defender", "defender_detections", "event_logs"}),
        hash_files=True, inspect_content=True, time_limit=300.0, hash_limit=1500, sweep_limit=800,
        omits="Still bounded: no whole-drive scans, no memory or network inspection, no signature trust validation.",
    ),
    "malware": ModeProfile(
        "malware",
        "Suspicious-file analysis: hashes, script and executable heuristics, known-hash lists you supply, "
        "plus available Microsoft Defender findings.",
        frozenset({"process_inventory", "registry_autoruns", "startup_folders", "services", "scheduled_tasks",
                   "file_sweep", "telemetry_defender", "defender_detections"}),
        hash_files=True, inspect_content=True, time_limit=300.0, hash_limit=2500, sweep_limit=3000,
        omits="No drivers, security-setting review, WMI, registry hijack settings or event logs.",
    ),
    "rootkit": ModeProfile(
        "rootkit",
        "Driver, kernel-related service and security-configuration indicators, plus a service cross-view check.",
        frozenset({"services", "drivers", "security_settings", "telemetry_defender"}),
        hash_files=True, inspect_content=True, time_limit=180.0, hash_limit=1200, sweep_limit=0,
        omits="No process, startup-folder, scheduled-task or WMI inspection. A rootkit that hides itself from "
              "software running inside Windows cannot be ruled out.",
    ),
    "dormant": ModeProfile(
        "dormant",
        "Threats that are not running now: autoruns, services, scheduled tasks, WMI subscriptions, "
        "execution-hijack settings and available PowerShell history.",
        frozenset({"registry_autoruns", "registry_config", "startup_folders", "services", "scheduled_tasks",
                   "wmi_persistence", "event_logs"}),
        hash_files=True, inspect_content=True, time_limit=240.0, hash_limit=1200, sweep_limit=0,
        omits="No running-process inventory, drivers, security settings or Defender. Event-log history depends on "
              "Windows logging being enabled.",
    ),
}
MODE_ORDER = ("quick", "full", "malware", "rootkit", "dormant")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class ShadowTraceConfig:
    """All tunable settings for a scan. Every threshold is documented here."""

    quick: bool = False
    mode: str = ""                       # quick | full | malware | rootkit | dormant ("" -> full, or quick if quick=True)
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    report_format: str = "both"          # html | json | markdown | both (html+json) | all
    extra_paths: list[str] = field(default_factory=list)
    hash_list_paths: list[str] = field(default_factory=list)   # local known-hash lists supplied by the user
    telemetry: bool = False              # legacy flag: force the Defender status check in any mode
    no_defender: bool = False            # never run any Defender query
    redact: bool = False                 # best-effort redaction of user / computer names in reports
    time_limit_seconds: Optional[float] = None  # None -> the mode's default
    allow_non_windows: bool = False
    system_root: str = field(default_factory=default_system_root)
    max_processes: int = 4000            # upper bound on processes inspected
    max_files_hashed: Optional[int] = None  # None -> the mode's default
    max_sweep_files: Optional[int] = None   # None -> the mode's default
    max_hash_bytes: int = 256 * 1024 * 1024  # files larger than this are not hashed
    max_inspect_bytes: int = 32 * 1024 * 1024  # bytes of one executable searched for keyboard-API names
    max_script_bytes: int = 512 * 1024   # bytes of one script file searched for suspicious patterns
    max_dir_entries: int = 200           # files analysed per user-supplied directory
    max_dir_depth: int = 2               # directory depth for user-supplied directories
    max_services: int = 1500             # services inspected
    max_tasks: int = 3000                # scheduled-task files parsed
    max_driver_keys: int = 4000          # service/driver registry keys examined
    max_startup_folder_entries: int = 200
    max_cmdline_chars: int = 300         # command lines are truncated to this length
    max_report_rows: int = 400           # rows shown in appendix tables
    instance_threshold: int = 8          # ST-P009: instances of one executable
    severity_points: dict[Severity, float] = field(
        default_factory=lambda: {
            Severity.INFO: 0.0,
            Severity.LOW: 4.0,
            Severity.MEDIUM: 15.0,
            Severity.HIGH: 35.0,
            Severity.CRITICAL: 60.0,
        }
    )
    confidence_multiplier: dict[Confidence, float] = field(
        default_factory=lambda: {Confidence.LOW: 0.5, Confidence.MEDIUM: 0.8, Confidence.HIGH: 1.0}
    )
    diminishing_factor: float = 0.75     # each additional independent indicator counts less
    band_moderate: int = 15
    band_elevated: int = 35
    band_high: int = 60

    def __post_init__(self) -> None:
        if not self.mode:
            self.mode = "quick" if self.quick else "full"
        self.mode = self.mode.lower()
        if self.mode not in MODE_PROFILES:
            raise ValueError(f"Unknown scan mode {self.mode!r}; choose one of: {', '.join(MODE_ORDER)}")
        self.quick = self.mode == "quick"

    @property
    def profile(self) -> ModeProfile:
        """The :class:`ModeProfile` for the selected mode."""
        return MODE_PROFILES[self.mode]

    @property
    def hash_files(self) -> bool:
        """Whether process / startup / driver executables are hashed (off in quick mode)."""
        return self.profile.hash_files

    @property
    def inspect_content(self) -> bool:
        """Whether file contents are inspected (script patterns, keyboard-API names, signature presence)."""
        return self.profile.inspect_content

    @property
    def scan_services(self) -> bool:
        """Whether services are inspected in this mode."""
        return "services" in self.profile.checks

    @property
    def hash_limit(self) -> int:
        """Maximum number of unique files hashed in this scan."""
        return self.max_files_hashed if self.max_files_hashed is not None else (self.profile.hash_limit or 400)

    @property
    def sweep_limit(self) -> int:
        """Maximum number of candidate files examined by the file sweep."""
        return self.max_sweep_files if self.max_sweep_files is not None else self.profile.sweep_limit

    @property
    def time_limit(self) -> float:
        """Effective wall-clock budget for the scan, in seconds."""
        if self.time_limit_seconds is not None:
            return self.time_limit_seconds
        return self.profile.time_limit

    @property
    def defender_enabled(self) -> bool:
        """Whether Microsoft Defender queries run (mode default, or forced by --telemetry; never with --no-defender)."""
        if self.no_defender:
            return False
        return self.telemetry or "telemetry_defender" in self.profile.checks

    def check_enabled(self, check_id: str) -> bool:
        """Whether a check belongs to the selected mode."""
        if check_id in ALWAYS_RUN_CHECKS:
            return True
        if check_id in ("telemetry_defender", "defender_detections"):
            if self.no_defender:
                return False
            if self.telemetry and check_id == "telemetry_defender":
                return True
        return check_id in self.profile.checks


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class CheckStatus:
    """Outcome of one check - distinguishes 'nothing found' from 'could not run'."""

    name: str
    label: str
    status: str
    detail: str = ""
    items: int = 0


@dataclass
class ProcessInfo:
    """Metadata about one running process (no memory or keystroke data)."""

    pid: int
    ppid: Optional[int]
    name: str
    exe: Optional[str] = None
    cmdline: str = ""
    started_at: Optional[str] = None
    start_ts: Optional[float] = None
    username: Optional[str] = None
    exe_exists: Optional[bool] = None
    sha256: Optional[str] = None
    errors: list[str] = field(default_factory=list)


@dataclass
class FileInfo:
    """Read-only facts about a file selected for analysis."""

    path: str
    name: str
    source: str = "user-path"
    size: Optional[int] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    accessed: Optional[str] = None
    extension: str = ""
    sha256: Optional[str] = None
    is_pe: Optional[bool] = None
    error: Optional[str] = None
    hash_note: Optional[str] = None
    sources: list[str] = field(default_factory=list)
    inspected: bool = False
    embedded_signature: Optional[bool] = None   # certificate table present in the PE header (NOT validated)
    keyboard_apis: list[str] = field(default_factory=list)
    script_patterns: list[str] = field(default_factory=list)


@dataclass
class StartupEntry:
    """One persistence location entry (autorun value, startup-folder item, service)."""

    kind: str          # autorun | winlogon | startup_folder | service | scheduled_task | wmi | registry_config
    source: str        # human-readable source description
    location: str      # registry key / folder / "Windows services"
    name: str
    command: str
    program_name: str = ""
    target_path: Optional[str] = None
    target_exists: Optional[bool] = None
    sha256: Optional[str] = None
    view: Optional[str] = None
    notes: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class TelemetryResult:
    """Result of one optional telemetry source."""

    source: str
    available: bool
    checked: bool
    details: dict[str, Any] = field(default_factory=dict)
    note: str = ""


@dataclass
class Finding:
    """An evidence-based investigation lead."""

    rule_id: str
    category: str
    title: str
    severity: Severity
    confidence: Confidence
    confidence_note: str
    subject: str
    evidence: list[str]
    explanation: str
    recommendation: str
    limitations: str
    evidence_key: str
    finding_id: str = ""
    related_subjects: list[str] = field(default_factory=list)
    counted_in_score: bool = True
    shares_evidence_with: list[str] = field(default_factory=list)
    detection_method: str = "heuristic"   # heuristic | known-hash | security-product | signature
    status: str = "suspicious"            # confirmed | suspicious | informational
    artifacts: list[str] = field(default_factory=list)
    source_check: str = ""
    limiting_factors: list[str] = field(default_factory=list)


@dataclass
class ScoreGroup:
    """Findings that rest on the same underlying evidence (counted once)."""

    evidence_key: str
    points: float
    finding_ids: list[str]
    counted_finding_id: str


@dataclass
class ScoreResult:
    """Heuristic risk indicator - explicitly not a malware verdict."""

    total: int
    band: str
    interpretation: str
    groups: list[ScoreGroup]
    insufficient_evidence: bool
    coverage_notes: list[str]
    method: str
    disclaimer: str


@dataclass
class DriverInfo:
    """A kernel / file-system driver service read from the registry (never loaded or executed by ShadowTrace)."""

    name: str
    display_name: str = ""
    image_path: str = ""
    path: Optional[str] = None
    service_type: Optional[int] = None
    start: Optional[int] = None
    start_label: str = "unknown"
    state: Optional[str] = None        # from the Win32_SystemDriver view, when available
    exists: Optional[bool] = None
    sha256: Optional[str] = None
    embedded_signature: Optional[bool] = None   # certificate table present in the PE header (NOT validated)
    standard_location: Optional[bool] = None
    notes: list[str] = field(default_factory=list)


@dataclass
class SecuritySetting:
    """One read-only security configuration observation."""

    key: str
    label: str
    value: str
    state: str          # enabled | disabled | policy-disabled | not-configured | exclusion | unknown | unavailable
    detail: str = ""
    source: str = ""


@dataclass
class EventEvidence:
    """Evidence read from a Windows event log (historical; depends on logging being enabled)."""

    log: str
    event_id: int
    time: str
    patterns: list[str]
    labels: list[str]
    excerpt: str


@dataclass
class ThreatDetection:
    """A Microsoft Defender detection-history entry (history may include already-remediated items)."""

    threat_id: str
    name: str
    resources: list[str]
    process_name: str = ""
    time: str = ""
    action_success: Optional[bool] = None
    active: Optional[bool] = None


@dataclass
class ScanResult:
    """Everything produced by one scan; kept in memory even if reporting fails."""

    tool_version: str
    started_at: str
    finished_at: str = ""
    duration_seconds: float = 0.0
    mode: str = "full"
    elevated: Optional[bool] = None
    os_description: str = ""
    python_version: str = ""
    processes: list[ProcessInfo] = field(default_factory=list)
    files: list[FileInfo] = field(default_factory=list)
    startup_entries: list[StartupEntry] = field(default_factory=list)
    telemetry: list[TelemetryResult] = field(default_factory=list)
    checks: list[CheckStatus] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: Optional[ScoreResult] = None
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    conclusion: str = ""
    scan_id: str = ""
    started_local: str = ""
    drivers: list[DriverInfo] = field(default_factory=list)
    settings: list[SecuritySetting] = field(default_factory=list)
    events: list[EventEvidence] = field(default_factory=list)
    detections: list[ThreatDetection] = field(default_factory=list)
    view_mismatches: list[str] = field(default_factory=list)
    mode_summary: str = ""
    intel_summary: str = ""
    redacted: bool = False


def to_jsonable(value: Any) -> Any:
    """Recursively convert dataclasses, enums, paths and tuples to JSON-safe values."""
    if isinstance(value, Enum):
        return value.name
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, dict):
        return {safe_str(k.name if isinstance(k, Enum) else k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, Path):
        return safe_str(value)
    if isinstance(value, str):
        return safe_str(value)
    return value


# --------------------------------------------------------------------------- #
# Detection rule catalogue (single source of truth for `rules` and findings)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RuleSpec:
    """Documentation and defaults for one detection rule."""

    rule_id: str
    category: str
    title: str
    severity: Severity
    confidence: Confidence
    confidence_note: str
    checks: str
    explanation: str
    recommendation: str
    limitations: str
    method: str = "heuristic"
    status: str = "suspicious"


_VERIFY = (
    "Confirm you recognise the program and where it came from. Check its properties (publisher, "
    "signature, install location) in File Explorer and, if still unsure, look up its SHA-256 hash "
    "in a reputation service yourself. Do not delete anything until you know what it is."
)

RULE_LIST: tuple[RuleSpec, ...] = (
    RuleSpec(
        "ST-P001", "Process location", "Process running from a low-trust or user-writable location",
        Severity.MEDIUM, Confidence.MEDIUM,
        "The path is an observed fact; how suspicious it is depends on the matched location rule.",
        "Compares each running process's executable path with the documented location rules "
        "(temporary folders, Recycle Bin, Public, Downloads, AppData\\Roaming, ProgramData).",
        "Installed software normally lives in Program Files or the Windows folder. Malware often runs from "
        "folders that any user-level program can write to. This is a lead, not proof.",
        _VERIFY,
        "Portable apps, installers, updaters and developer tools legitimately run from these folders.",
    ),
    RuleSpec(
        "ST-P002", "Process integrity", "Running process whose executable file no longer exists",
        Severity.MEDIUM, Confidence.LOW,
        "A missing image can be a harmless side effect of updates or a sign the file was removed after launch.",
        "Checks whether the executable path reported for a running process still exists on disk.",
        "A process was started from a file that is no longer present. Some malware deletes its own file "
        "after launching to hide; software updates can cause the same symptom.",
        "Note the process name and PID, check whether the software was recently updated or uninstalled, "
        "and restart the computer to see whether the process returns.",
        "Application updaters, installers that clean up after themselves and ongoing uninstalls.",
    ),
    RuleSpec(
        "ST-P003", "Process masquerading", "Windows system process name running outside its expected folder",
        Severity.HIGH, Confidence.MEDIUM,
        "Name and path are observed facts; unusual but legitimate layouts are rare.",
        "For well-known Windows process names (svchost.exe, lsass.exe, explorer.exe, ...) verifies the "
        "executable lives in the expected %SystemRoot% folder.",
        "Attackers commonly name malware after core Windows processes. The genuine ones run only from "
        "specific system folders.",
        "Treat this as a priority lead. Compare the file's location, publisher and hash with a known-good "
        "copy and, if it cannot be explained, scan the computer offline with trusted security software.",
        "Custom Windows images, relocated system roots and some security-tool sandboxes.",
    ),
    RuleSpec(
        "ST-P004", "Process naming", "Executable name uses a deceptive double extension",
        Severity.MEDIUM, Confidence.MEDIUM,
        "The name pattern is observed; intent is inferred.",
        "Flags process names such as 'invoice.pdf.exe' that imitate a document or media file.",
        "A document-style name followed by an executable extension is a classic way to trick users into "
        "running a program.",
        _VERIFY,
        "Rare in legitimate software, but some build or test tools create oddly named executables.",
    ),
    RuleSpec(
        "ST-P005", "Process naming", "Process name looks randomly generated",
        Severity.LOW, Confidence.LOW,
        "Name heuristics are weak; many tools use unusual names.",
        "Flags single-character names, long hexadecimal-only names and long names with almost no vowels, "
        "unless the file lives in Program Files or the Windows folder.",
        "Randomly generated names are sometimes used to avoid easy recognition.",
        _VERIFY,
        "Many legitimate tools, game launchers and installers use short or abbreviated names.",
    ),
    RuleSpec(
        "ST-P006", "Process relationships", "System process started by an unexpected parent",
        Severity.HIGH, Confidence.MEDIUM,
        "Parent/child links are observed; the check ignores parents that started after the child (PID reuse).",
        "Verifies the parent of svchost.exe (services.exe), lsass.exe and services.exe (wininit.exe).",
        "These processes are always launched by a specific Windows component. A different parent suggests "
        "an imitation or an unusual launch method.",
        "Review the process and its parent together (Task Manager details or Process Explorer) and verify "
        "both executables' locations and publishers.",
        "Containers, sandboxes and some debugging or virtualisation setups launch system processes differently.",
    ),
    RuleSpec(
        "ST-P007", "Process relationships", "Office application started a script host or shell",
        Severity.MEDIUM, Confidence.MEDIUM,
        "The parent/child relationship is observed; macros and add-ins can have legitimate reasons.",
        "Looks for Word, Excel, PowerPoint, Outlook or OneNote parents of cmd, PowerShell, wscript, cscript or mshta.",
        "Malicious documents commonly use Office macros to launch a script host. Legitimate add-ins and "
        "automation can behave the same way.",
        "Identify the document that was open, and check whether you expected it to run macros or add-ins.",
        "Legitimate macros, add-ins and enterprise automation.",
    ),
    RuleSpec(
        "ST-P008", "Process command line", "PowerShell started with an encoded command or hidden window",
        Severity.MEDIUM, Confidence.MEDIUM,
        "The flags are observed in the command line; encoded commands are used by both admins and attackers.",
        "Looks for -EncodedCommand style arguments and hidden-window arguments on powershell.exe / pwsh.exe "
        "(raises severity when both are present).",
        "Encoded commands hide what a script does. Attackers use them often, but so do some management "
        "tools and installers.",
        "Identify what launched the process (see the parent) and whether you or your IT team expected it. "
        "Long values are redacted in this report; inspect them locally if needed.",
        "Software-deployment tools, configuration managers and some installers use encoded commands.",
    ),
    RuleSpec(
        "ST-P009", "Process relationships", "Many instances of the same executable",
        Severity.INFO, Confidence.LOW,
        "Counts are observed; their meaning is context-dependent.",
        "Reports executables with at least the configured number of simultaneous instances (default 8), "
        "excluding well-known multi-process applications.",
        "A large number of identical processes is unusual for most programs and worth a glance.",
        "Check whether the program is expected to spawn many workers.",
        "Browsers, build tools, test runners and Electron applications run many processes by design.",
    ),
    RuleSpec(
        "ST-S001", "Persistence", "Startup entry points to a file that does not exist",
        Severity.LOW, Confidence.MEDIUM,
        "File absence is an observed fact; it is usually a harmless leftover.",
        "Resolves the program referenced by each Run/RunOnce value, service and startup item and checks it exists.",
        "A start-up entry whose file is missing is a stale leftover, but attackers also remove payloads after use.",
        "Look up the entry name. If you do not recognise it, research it before removing it manually.",
        "Software that was uninstalled badly is by far the most common cause. 32-bit Python on 64-bit Windows "
        "can also report System32 files as missing.",
    ),
    RuleSpec(
        "ST-S002", "Persistence", "Startup entry runs a program from a low-trust location",
        Severity.MEDIUM, Confidence.MEDIUM,
        "The configured path is an observed fact; persistence from these folders is uncommon for legitimate software.",
        "Applies the documented location rules (severity table for persistence) to each startup entry's target.",
        "Programs that restart automatically from temporary, Public or download folders are unusual and are "
        "a common persistence pattern.",
        _VERIFY,
        "Some per-user apps (updaters, chat clients) legitimately start from AppData folders.",
    ),
    RuleSpec(
        "ST-S003", "Persistence", "Startup entry launches a script host or system utility",
        Severity.LOW, Confidence.LOW,
        "The launcher is observed; what it runs is not analysed.",
        "Flags entries whose program is powershell, pwsh, cmd, wscript, cscript, mshta, rundll32 or regsvr32 "
        "(mshta, encoded PowerShell and hidden windows raise the severity).",
        "These built-in tools are used for legitimate automation and are also abused to run hidden code at logon.",
        "Read the full command in the report and confirm which script or library it runs.",
        "Corporate login scripts and many ordinary applications use these launchers.",
    ),
    RuleSpec(
        "ST-S004", "Persistence", "Executable or script placed directly in a Startup folder",
        Severity.LOW, Confidence.MEDIUM,
        "File type and location are observed facts.",
        "Flags executables or scripts stored directly in the current-user or all-users Startup folders.",
        "Anything in these folders runs at every logon. Shortcuts are normal; raw executables and scripts are less so.",
        _VERIFY,
        "Some small utilities are deliberately copied here by their owners.",
    ),
    RuleSpec(
        "ST-S005", "Persistence", "Winlogon Shell or Userinit differs from the Windows default",
        Severity.HIGH, Confidence.MEDIUM,
        "Registry values are observed exactly; deviations from the default are uncommon.",
        "Compares HKLM/HKCU Winlogon 'Shell' (default explorer.exe) and 'Userinit' (default userinit.exe) "
        "with the standard values.",
        "Programs appended to these values run at every sign-in, which is a known persistence technique.",
        "Compare the value with the default and research any extra program. Do not edit the registry "
        "unless you are sure; ask a professional if unsure.",
        "Some corporate or OEM images add their own components here.",
    ),
    RuleSpec(
        "ST-F001", "File location", "Executable or script stored in a low-trust location",
        Severity.LOW, Confidence.MEDIUM,
        "Applies to files you asked ShadowTrace to analyse or found in Startup folders.",
        "Applies the location rules to user-selected files and Startup-folder files with executable extensions.",
        "Executables in temporary, download or public folders have usually not been reviewed.",
        _VERIFY,
        "Freshly downloaded installers and portable tools live here legitimately.",
    ),
    RuleSpec(
        "ST-F002", "File integrity", "Executable content hidden behind a document or media extension",
        Severity.MEDIUM, Confidence.MEDIUM,
        "The 'MZ' executable header is an observed fact; renamed files are rarely benign.",
        "Reads the first two bytes of analysed files and flags Windows executable headers on files named like "
        "documents, images, archives or media.",
        "A program disguised as a document or picture is a common social-engineering trick.",
        "Do not open the file. Check where it came from, and scan it with trusted security software.",
        "Some software distributes executable data in files with misleading extensions.",
    ),
    RuleSpec(
        "ST-F003", "File naming", "File name uses a deceptive double extension",
        Severity.MEDIUM, Confidence.MEDIUM,
        "The name pattern is observed; intent is inferred.",
        "Flags analysed files named like 'photo.jpg.exe'.",
        "A document-style name followed by an executable extension is a classic way to trick users into running a program.",
        _VERIFY,
        "Rare in legitimate software.",
    ),
    RuleSpec(
        "ST-T001", "Security telemetry", "Microsoft Defender real-time protection reported as off",
        Severity.INFO, Confidence.MEDIUM,
        "The value was read from Defender; it says nothing about keyloggers directly.",
        "With --telemetry, reads Defender status through the read-only Get-MpComputerStatus cmdlet.",
        "With real-time protection off, malware is less likely to be blocked automatically. A third-party "
        "antivirus may legitimately have taken over.",
        "Confirm another security product is active, or re-enable Defender through Windows Security.",
        "Third-party antivirus products normally switch Defender's real-time protection off.",
    ),
    RuleSpec(
        "ST-T002", "Security telemetry", "Microsoft Defender reported as unavailable, disabled or out of date",
        Severity.INFO, Confidence.MEDIUM,
        "The values were read from Defender; they describe protection status, not infection.",
        "Reads AMServiceEnabled, AntivirusEnabled and signature age from Get-MpComputerStatus.",
        "If Defender's service or antivirus component is off, or its signatures are old, malware is less likely "
        "to be blocked. Another security product may legitimately be in charge.",
        "Confirm that a security product is active and up to date in Windows Security.",
        "Managed or third-party antivirus setups normally turn Defender components off.",
    ),
    RuleSpec(
        "ST-P010", "Process command line", "Process command line shows obfuscation or download-and-execute patterns",
        Severity.MEDIUM, Confidence.MEDIUM,
        "Patterns are matched in the (redacted) command line text; legitimate automation can look the same.",
        "Applies the documented command-pattern table (Base64 decoding, download cradles, Invoke-Expression, "
        "in-memory loading APIs, AMSI/Defender tampering, remote script hosts) to script-host and system-utility "
        "processes. Encoded and hidden-window PowerShell is reported separately by ST-P008.",
        "Attackers use these building blocks to download and run code without leaving a normal program file "
        "on disk (fileless or script-based activity). Admin and deployment tooling uses them too.",
        "Identify what started the process (see its parent) and whether you or your IT team expected it. "
        "Never run the command yourself to 'see what it does'.",
        "Software installers, configuration management and developer tooling commonly download and run scripts.",
    ),
    RuleSpec(
        "ST-S006", "Persistence", "Startup command shows obfuscation or download-and-execute patterns",
        Severity.MEDIUM, Confidence.MEDIUM,
        "Patterns are matched in the (redacted) command text; the content of referenced scripts is not executed.",
        "Applies the documented command-pattern table to the command of every autorun, service, scheduled task, "
        "WMI consumer and execution-hijack value.",
        "Persistence that decodes or downloads code each time it starts is a common way to keep a threat dormant "
        "and mostly fileless.",
        "Review the full command in the report, find the script or program it references, and verify its origin.",
        "Legitimate updaters and corporate logon scripts sometimes download and run content.",
    ),
    RuleSpec(
        "ST-S007", "Persistence", "Execution-hijack or auto-run registry setting is configured",
        Severity.MEDIUM, Confidence.MEDIUM,
        "The registry values are read exactly; the settings themselves are uncommon but have legitimate uses.",
        "Reads Image File Execution Options 'Debugger', SilentProcessExit 'MonitorProcess', AppInit_DLLs, "
        "BootExecute, Command Processor AutoRun and Windows 'Load'.",
        "These settings make Windows start another program when a program, command prompt or session starts. "
        "They are rarely needed and are a known persistence and hijacking technique.",
        "Look up the program named in the value and confirm it belongs to software you installed on purpose.",
        "Debugging tools (for example a replacement Task Manager or a JIT debugger) legitimately use Debugger values.",
    ),
    RuleSpec(
        "ST-D001", "Persistence", "Hidden scheduled task with a suspicious action",
        Severity.MEDIUM, Confidence.MEDIUM,
        "The 'hidden' flag and the action are read from the task definition.",
        "Flags enabled, non-Microsoft scheduled tasks marked Hidden whose action is a script host or system "
        "utility, runs from a low-trust location, or points to a missing file.",
        "Hiding a task keeps it out of the default Task Scheduler view. Combined with an unusual action it is a "
        "typical way to run something later or repeatedly.",
        "Open Task Scheduler (show hidden tasks), read the task's triggers and action, and verify who created it.",
        "Some vendor update tasks are hidden on purpose.",
    ),
    RuleSpec(
        "ST-W001", "Persistence", "WMI event consumer that runs commands or scripts",
        Severity.MEDIUM, Confidence.MEDIUM,
        "Consumers are read from the root\\subscription namespace; they are rare on ordinary computers.",
        "Lists CommandLineEventConsumer and ActiveScriptEventConsumer objects (with their filters) in the "
        "WMI repository. Severity rises when the command matches suspicious patterns.",
        "WMI event subscriptions can start a program or script whenever a trigger fires (logon, a time, a process "
        "starting) without any startup entry, and are used for fileless persistence.",
        "Identify the software that created the subscription. If you cannot explain it, treat it as suspicious and "
        "use a trusted security product or specialist to inspect and remove it.",
        "Some enterprise management and hardware-monitoring software registers WMI consumers.",
    ),
    RuleSpec(
        "ST-M001", "File content", "Script file contains obfuscation or download-and-execute patterns",
        Severity.MEDIUM, Confidence.MEDIUM,
        "Patterns are matched in the script text only; the script is never run.",
        "Applies the documented command-pattern table to the text of script files (.ps1, .vbs, .js, .bat, .cmd, "
        ".hta, .wsf, ...) that ShadowTrace analyses.",
        "Scripts that decode hidden payloads, download content or load code in memory are typical of "
        "script-based malware, but administrators write such scripts too.",
        "Read the script yourself without running it, check where it came from, and scan it with trusted security software.",
        "Installers, build scripts and admin tooling often download files and use encoded data.",
    ),
    RuleSpec(
        "ST-M002", "File content", "Executable references keyboard-capture API names",
        Severity.LOW, Confidence.LOW,
        "The API names are found as text inside the file; that shows capability, not behaviour.",
        "Searches executables outside Program Files and Windows for names such as SetWindowsHookEx, "
        "GetAsyncKeyState, GetKeyboardState and RegisterRawInputDevices (plus window-title APIs). Severity rises "
        "when the file also sits in a low-trust location or runs at startup.",
        "Keyloggers need an API to see keystrokes. The same APIs are used by games, remote-control tools, "
        "accessibility software and hotkey utilities, so this is a weak lead.",
        _VERIFY,
        "Packed or obfuscated programs hide their API names; legitimate hotkey, macro and remote-access tools use them.",
    ),
    RuleSpec(
        "ST-M003", "Known malicious hash", "File hash matches your supplied known-hash list",
        Severity.CRITICAL, Confidence.HIGH,
        "The file's SHA-256 is identical to an entry in a list you provided with --hash-list.",
        "Compares SHA-256 hashes of every analysed file with the local list(s) given by --hash-list. ShadowTrace "
        "ships no malware signatures and performs no online lookups.",
        "An identical hash means the file's bytes are identical to a file your list identifies as malicious. The "
        "result is only as reliable as the list you supplied.",
        "Do not run the file. Isolate the computer from sensitive activity, and use a trusted security product or "
        "offline scan (for example Microsoft Defender Offline) to remove it.",
        "A wrong or poorly curated list produces wrong matches; a missing match proves nothing.",
        "known-hash", "confirmed",
    ),
    RuleSpec(
        "ST-M004", "Known test indicator", "Standard antivirus test file (EICAR) found",
        Severity.LOW, Confidence.HIGH,
        "The file's SHA-256 equals the published hash of the harmless EICAR antivirus test file.",
        "Compares file hashes with the built-in hash of the industry-standard EICAR test file.",
        "The EICAR file is a harmless string used to test antivirus products. It is not malware.",
        "If you did not place it there on purpose, find out who did; otherwise delete it with Windows Explorer.",
        "None expected; the match is exact.",
        "known-hash", "confirmed",
    ),
    RuleSpec(
        "ST-R001", "Drivers", "Kernel driver service points to a user-writable location",
        Severity.HIGH, Confidence.MEDIUM,
        "The driver's configured path is read from the registry and matched against the location rules.",
        "Reads kernel/file-system driver services from HKLM\\SYSTEM\\CurrentControlSet\\Services and flags image "
        "paths in temporary, Public, Downloads, Roaming, ProgramData or Recycle Bin folders.",
        "Genuine drivers are installed under the Windows folder or Program Files. A driver that loads from a "
        "folder any user can write to can be swapped by an attacker and is a known rootkit technique.",
        "Identify the software that installed the driver. Do not delete it manually: use a trusted security product "
        "or specialist, and consider an offline scan.",
        "Some installers briefly register drivers from temporary folders; vendor tools sometimes use ProgramData.",
    ),
    RuleSpec(
        "ST-R002", "Drivers", "Auto-start driver whose file is missing",
        Severity.LOW, Confidence.LOW,
        "File absence is observed; it is usually a stale leftover.",
        "Flags boot/system/auto-start driver services whose image file cannot be found.",
        "A driver entry that points to a missing file is normally a leftover from uninstalled software.",
        "Look up the driver name; if unknown, research it before taking any action.",
        "Stale entries from uninstalled hardware or software are very common; 32-bit Python on 64-bit Windows can "
        "also make System32 files look missing.",
    ),
    RuleSpec(
        "ST-R003", "Drivers", "Driver outside standard folders without an embedded signature",
        Severity.LOW, Confidence.LOW,
        "Signature presence is read from the PE header only; the signature is not validated.",
        "Flags drivers outside the Windows and Program Files folders whose PE header has no embedded certificate.",
        "A driver in an unusual folder with no embedded signature deserves a closer look. Catalog-signed drivers "
        "carry no embedded signature, so this is a weak signal.",
        "Check the driver's publisher in File Explorer (Properties > Digital Signatures) and Device Manager.",
        "Catalog-signed drivers have no embedded certificate; ShadowTrace does not validate signatures.",
    ),
    RuleSpec(
        "ST-R004", "Drivers", "Service visible in the service manager but missing from the registry",
        Severity.MEDIUM, Confidence.LOW,
        "Two independent views of the services disagree; transient states and per-user services can also cause this.",
        "Compares service names enumerated through the service manager (and driver names from Win32_SystemDriver) "
        "with the keys under HKLM\\SYSTEM\\CurrentControlSet\\Services (per-user service suffixes are accounted for).",
        "Deleting a service's registry key while it keeps running is one way to hide it from tools that read the "
        "registry. The disagreement is a lead, not proof.",
        "Re-run the scan after a reboot; if the same name appears, research it and consider an offline scan or "
        "specialist forensic tools.",
        "Services being installed or removed during the scan, and unusual per-user service naming, can cause false positives.",
    ),
    RuleSpec(
        "ST-R005", "Boot / kernel security", "Driver signature enforcement or integrity checks appear relaxed",
        Severity.MEDIUM, Confidence.MEDIUM,
        "Values are read from the boot configuration (bcdedit /enum {current}); requires administrator rights.",
        "Reports test-signing, 'nointegritychecks' and similar boot options set to Yes.",
        "These options let Windows load unsigned or test-signed drivers, which rootkits need. Developers also use them.",
        "If you are not developing drivers, restore the setting using an administrator prompt following Microsoft's "
        "documentation, or ask a professional.",
        "Driver developers and some anti-cheat or hardware tools use test signing.",
    ),
    RuleSpec(
        "ST-R006", "Boot / kernel security", "Microsoft Defender disabled by policy",
        Severity.MEDIUM, Confidence.MEDIUM,
        "Policy registry values are read exactly; third-party antivirus products also set them.",
        "Reads Defender policy values DisableAntiSpyware and DisableRealtimeMonitoring.",
        "Malware commonly turns Defender off by policy before it runs. Managed and third-party antivirus "
        "deployments do too.",
        "Confirm which security product is active. If none, re-enable protection through Windows Security or your IT team.",
        "Third-party antivirus and organisation-managed policies legitimately disable Defender.",
    ),
    RuleSpec(
        "ST-R007", "Boot / kernel security", "Defender exclusion covers a user-writable or very broad location",
        Severity.MEDIUM, Confidence.LOW,
        "Exclusions are read from the registry (usually administrator-only); intent cannot be determined.",
        "Reads Defender path and process exclusions and flags temporary, Downloads, Public, profile-wide or "
        "drive-wide exclusions.",
        "Anything stored in an excluded folder is not scanned. Attackers add exclusions to protect their files.",
        "Confirm you or your IT team added the exclusion and still need it.",
        "Developers and gamers often exclude build or game folders.",
    ),
    RuleSpec(
        "ST-R008", "Boot / kernel security", "Security hardening feature not enabled",
        Severity.INFO, Confidence.MEDIUM,
        "The value is read from the registry; absence of a feature is a configuration gap, not an infection.",
        "Reports Secure Boot, memory integrity (HVCI), LSA protection, the vulnerable-driver blocklist, "
        "Defender tamper protection and UAC when they are off or not configured.",
        "These features make kernel-level and credential attacks harder. Missing features are context, not a threat.",
        "Consider enabling them through Windows Security or Group Policy if your hardware and software support them.",
        "Older hardware or software may not support these features.",
    ),
    RuleSpec(
        "ST-E001", "Fileless evidence", "PowerShell script-block log shows suspicious patterns",
        Severity.MEDIUM, Confidence.LOW,
        "Evidence is historical, depends on script-block logging being enabled, and cannot show who ran it or why.",
        "Reads recent Microsoft-Windows-PowerShell/Operational event 4104 (read-only, bounded) and applies the "
        "documented script patterns. Only matched pattern names and a short redacted excerpt are kept.",
        "Script-block logging records the PowerShell code that actually ran, even if it was encoded or downloaded. "
        "Matching patterns suggest obfuscated or download-and-execute activity at some point.",
        "Identify the time and the user context of the event and whether you or your IT team ran it. Review the "
        "log in Event Viewer.",
        "Administrators, management tools and some installers run similar scripts. The log may be disabled or rotated.",
    ),
    RuleSpec(
        "ST-A001", "Security product result", "Microsoft Defender reports a detected threat",
        Severity.HIGH, Confidence.HIGH,
        "The detection comes from Microsoft Defender's own history; ShadowTrace did not scan anything itself.",
        "Reads Defender detection history (Get-MpThreatDetection / Get-MpThreat), read-only, newest 50 entries.",
        "Defender reported a detection. History can include threats that were already removed or quarantined, "
        "and an active entry means the threat may still be present.",
        "Open Windows Security > Protection history and follow Defender's recommended action, or run a Defender "
        "full or offline scan yourself. ShadowTrace does not start scans or remediation.",
        "History entries may be old or already remediated; reading history is not the same as running a scan.",
        "security-product", "confirmed",
    ),
)
RULES: dict[str, RuleSpec] = {spec.rule_id: spec for spec in RULE_LIST}

CAPABILITIES = (
    "Five scan modes (quick, full, malware, rootkit, dormant) sharing the same scanner components; run 'modes' to see "
    "exactly what each one checks and omits.",
    "Running-process inventory (psutil) with bounded SHA-256 hashing and content inspection of executables.",
    "Persistence: Run/RunOnce/Policies keys (64-bit and 32-bit views), Winlogon, execution-hijack settings (IFEO, "
    "AppInit_DLLs, BootExecute, AutoRun), Startup folders, services, scheduled tasks and WMI event subscriptions.",
    "Suspicious-file analysis: hashes, script obfuscation/download patterns, keyboard-API names, executable headers, "
    "known-hash lists you supply (--hash-list) and the EICAR test file.",
    "Rootkit and driver indicators: driver services, driver paths and signature presence, a service cross-view check, "
    "boot-integrity options, Defender policy and exclusions, hardening features.",
    "Fileless indicators: encoded/obfuscated command lines, WMI consumers, PowerShell script-block log evidence.",
    "Read-only Microsoft Defender status and detection-history query (fixed, documented cmdlets only).",
    f"{len(RULE_LIST)} documented detection rules (run 'rules --details'), an evidence-de-duplicating score and "
    "explicit confirmed / suspicious / informational / not-assessed separation.",
    "HTML, JSON and Markdown reports saved to reports/MM-DD-YYYY/ with collision-proof names, an optional "
    "redaction mode, a 'reports' history command and a post-scan 'view the report?' prompt.",
)
LIMITATIONS = (
    "ShadowTrace is a user-mode, point-in-time assessment. It cannot reliably detect kernel-level rootkits, "
    "firmware or hardware keyloggers, or malware that hides from software running inside Windows.",
    "Windows has no documented API for listing which processes installed keyboard hooks, so ShadowTrace does not "
    "claim to detect hooks or keystroke capture; ST-M002 only notes API names found inside files.",
    "Signature trust is not validated (no WinVerifyTrust, to avoid revocation lookups over the network); only the "
    "presence of an embedded certificate table is read. Unsigned does not mean malicious; signed does not mean safe.",
    "No malware signatures or online reputation lookups are included. Known-hash detections only happen for lists "
    "you supply with --hash-list and for the harmless EICAR test file.",
    "Defender history can include already-remediated items, and reading it is not the same as running a scan.",
    "Event-log evidence depends on logging being enabled and on the log not having rotated.",
    "Run as Administrator for fuller visibility (WMI, scheduled tasks, Defender exclusions, boot options and many "
    "processes need it). Skipped checks are listed in the report.",
    "Bounded work: time, file-size, file-count and per-check limits apply. A single blocking Windows call (for "
    "example a stalled network drive) cannot be interrupted, so the time limit is not a hard real-time guarantee.",
    "Services hosted by svchost are reported by their command line, not by the DLL they load. Browser extensions, "
    "memory contents and network traffic are not inspected.",
    "Cross-view (hidden-object) checks are limited to service/driver names; no independent user-mode view of "
    "processes exists that could reveal a hidden process reliably.",
    "A clean result is not proof the computer is clean, and a flagged item is not proof of infection.",
)
SAFETY_GUARANTEES = (
    "Manual, one-shot and read-only: no deleting, quarantining, renaming or moving files; no terminating, "
    "suspending or injecting into processes; no registry, service, task or security-setting changes; no driver "
    "loading; no persistence or background service.",
    "Nothing suspicious is ever executed. Files are only read, hashed and pattern-matched as text or bytes.",
    "No keystroke capture and no credential collection.",
    "No network access and no uploads: the program imports no networking library and never contacts a server. "
    "Reports stay on your disk; opening one in your browser only happens after you answer Yes.",
    "The only external programs started are three fixed, read-only Windows tools (PowerShell cmdlets, wevtutil, "
    "bcdedit) by absolute path, never through a shell and never with user-supplied text.",
    "Secrets in command lines are redacted and long values truncated before they reach a report; --redact also "
    "masks your user and computer names (best effort - review reports before sharing them).",
)
NOT_INSPECTED = (
    "Process memory, loaded modules and keyboard-hook tables",
    "Firmware, boot sector and kernel memory (a hidden rootkit may not be visible at all)",
    "Browser extensions and per-application plug-ins",
    "Network connections, DNS and traffic",
    "Active Setup, Shell extensions and other less common autostart locations",
    "Files outside the documented locations and any --path values",
    "Windows event logs other than PowerShell script-block (4104) events",
)
GENERAL_FALSE_POSITIVES = (
    "Portable applications, installers and updaters often run from user-writable folders.",
    "Stale start-up entries from uninstalled software are very common.",
    "Corporate management tools, login scripts and security products use script hosts and encoded commands.",
    "Developer and gaming tools often use unusual names and many processes.",
)


# --------------------------------------------------------------------------- #
# File analysis
# --------------------------------------------------------------------------- #
class FileAnalyzer:
    """Safe, read-only file analysis with hashing limits, a deadline-aware hasher and a result cache.

    ``analyze(..., inspect=True)`` hashes the file and inspects its content in a single streaming pass
    (header, embedded-signature presence, keyboard-API names, script patterns). Files are only read; they
    are never executed, opened for writing, renamed or removed.
    """

    def __init__(self, config: ShadowTraceConfig, deadline: Optional[Deadline] = None) -> None:
        self.config = config
        self.deadline = deadline or Deadline(None)
        self.files_hashed = 0
        self.files_inspected = 0
        self._cache: dict[str, tuple[Optional[str], Optional[str]]] = {}
        self._files: dict[str, FileInfo] = {}

    # -- hashing ------------------------------------------------------------ #
    @staticmethod
    def _key(path: str) -> str:
        return os.path.normcase(os.path.abspath(path))

    def hash_file(self, path: str) -> tuple[Optional[str], Optional[str]]:
        """Hash ``path`` once; returns ``(digest, reason_if_unavailable)``."""
        try:
            key = self._key(path)
        except (ValueError, OSError):
            return None, "invalid path"
        if key in self._cache:
            return self._cache[key]
        if self.deadline.expired():
            return None, "skipped: scan time limit reached"
        if self.files_hashed >= self.config.hash_limit:
            return None, "skipped: file-hashing limit reached"
        result = sha256_file(path, self.config.max_hash_bytes, deadline=self.deadline)
        if result[1] and "time limit" in result[1]:
            return result  # not cached: a later call could still succeed if the budget were larger
        self._cache[key] = result
        if result[0]:
            self.files_hashed += 1
        return result

    @staticmethod
    def _has_mz_header(path: str) -> Optional[bool]:
        try:
            with open(path, "rb") as handle:
                return handle.read(2) == b"MZ"
        except (OSError, ValueError):
            return None

    @staticmethod
    def _decode_script(data: bytes) -> str:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16", errors="replace")
        return data.decode("utf-8-sig", errors="replace")

    def _stream_inspect(self, path: str, info: FileInfo, size: int) -> None:
        """Single read pass: SHA-256 plus bounded content inspection. Fills ``info`` in place."""
        key = self._key(path)
        extension = info.extension
        if size > self.config.max_hash_bytes:
            info.hash_note = f"skipped: file is larger than the {self.config.max_hash_bytes}-byte hashing limit"
            info.is_pe = self._has_mz_header(path) if size >= 2 else None
            return
        if self.files_hashed >= self.config.hash_limit:
            info.hash_note = "skipped: file-hashing limit reached"
            info.is_pe = self._has_mz_header(path) if size >= 2 else None
            return
        hasher = hashlib.sha256()
        script = bytearray()
        api_names: set[str] = set()
        carry = b""
        scanned = 0
        complete = False
        want_script = extension in SCRIPT_EXTENSIONS
        first = True
        try:
            with open(path, "rb") as handle:
                while True:
                    if self.deadline.expired():
                        info.hash_note = "skipped: scan time limit reached"
                        break
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        complete = True
                        break
                    hasher.update(chunk)
                    if first:
                        first = False
                        info.is_pe = chunk[:2] == b"MZ"
                        if info.is_pe:
                            info.embedded_signature = parse_pe_signature_flag(chunk[:4096])
                    if want_script and len(script) < self.config.max_script_bytes:
                        script += chunk[: self.config.max_script_bytes - len(script)]
                    if info.is_pe and scanned < self.config.max_inspect_bytes:
                        window = carry + chunk
                        for match in KEYBOARD_API_RE.finditer(window):
                            api_names.add(normalise_api_name(match.group(0)))
                        carry = chunk[-40:]
                        scanned += len(chunk)
        except FileNotFoundError:
            info.error = "file not found"
            return
        except PermissionError:
            info.error = "access denied"
            return
        except (OSError, ValueError) as exc:
            info.error = f"could not read file: {safe_str(exc)}"
            return
        self.files_inspected += 1
        info.inspected = True
        if not complete:
            return
        info.sha256 = hasher.hexdigest()
        self._cache[key] = (info.sha256, None)
        self.files_hashed += 1
        names = classify_keyboard_apis(api_names)
        if names:
            info.keyboard_apis = names
        if want_script and script:
            info.script_patterns = [h.pid for h in scan_patterns(self._decode_script(bytes(script)), "script")]

    # -- analysis ----------------------------------------------------------- #
    def analyze(self, path: str, source: str = "user-path", hash_enabled: bool = True,
                inspect: bool = False) -> FileInfo:
        """Collect read-only facts about one file. Never raises for I/O problems."""
        try:
            absolute = os.path.abspath(path)
        except (ValueError, OSError):
            absolute = str(path)
        cache_key = None
        if hash_enabled:
            try:
                cache_key = self._key(absolute)
            except (ValueError, OSError):
                cache_key = None
            cached = self._files.get(cache_key) if cache_key else None
            if cached is not None and (cached.inspected or not inspect):
                if source not in cached.sources:
                    cached.sources.append(source)
                return cached
        info = FileInfo(
            path=safe_str(absolute),
            name=safe_str(os.path.basename(absolute)),
            source=source,
            sources=[source],
            extension=safe_str(os.path.splitext(absolute)[1].lower()),
        )
        try:
            st = os.stat(absolute)
        except FileNotFoundError:
            info.error = "file not found"
            return info
        except PermissionError:
            info.error = "access denied"
            return info
        except (OSError, ValueError) as exc:
            info.error = f"could not stat file: {safe_str(exc)}"
            return info
        if not stat.S_ISREG(st.st_mode):
            info.error = "not a regular file"
            return info
        info.size = st.st_size
        info.created = iso_from_ts(st.st_ctime)
        info.modified = iso_from_ts(st.st_mtime)
        info.accessed = iso_from_ts(st.st_atime)
        if hash_enabled and inspect and st.st_size >= 1:
            self._stream_inspect(absolute, info, st.st_size)
        else:
            if hash_enabled:
                info.sha256, info.hash_note = self.hash_file(absolute)
            if st.st_size >= 2:
                info.is_pe = self._has_mz_header(absolute)
        if cache_key and not info.error:
            self._files[cache_key] = info
        return info

    def files(self) -> list[FileInfo]:
        """Every file analysed with hashing enabled, in first-seen order."""
        return list(self._files.values())

    def expand_user_paths(self, paths: list[str]) -> tuple[list[str], list[str]]:
        """Expand user-supplied files/directories into a bounded file list plus notes."""
        files: list[str] = []
        notes: list[str] = []
        for raw in paths:
            path = os.path.abspath(os.path.expanduser(raw))
            if os.path.isfile(path):
                files.append(path)
            elif os.path.isdir(path):
                found, walk_notes = self._walk(path)
                files.extend(found)
                notes.extend(walk_notes)
            else:
                notes.append(f"Path not found or not accessible: {safe_str(path)}")
        return files, notes

    def _walk(self, root: str) -> tuple[list[str], list[str]]:
        """Bounded breadth-first listing of ``root`` (no symlink following)."""
        found: list[str] = []
        notes: list[str] = []
        queue: list[tuple[str, int]] = [(root, 0)]
        while queue:
            current, depth = queue.pop(0)
            try:
                with os.scandir(current) as iterator:
                    entries = sorted(iterator, key=lambda e: e.name.lower())
            except OSError as exc:
                notes.append(f"Could not list {safe_str(current)}: {safe_str(exc)}")
                continue
            for entry in entries:
                try:
                    if entry.is_file(follow_symlinks=False):
                        if len(found) >= self.config.max_dir_entries:
                            notes.append(
                                f"File limit ({self.config.max_dir_entries}) reached while reading {safe_str(root)}; "
                                "remaining files were not analysed."
                            )
                            return found, notes
                        found.append(entry.path)
                    elif entry.is_dir(follow_symlinks=False) and depth < self.config.max_dir_depth:
                        queue.append((entry.path, depth + 1))
                except OSError as exc:
                    notes.append(f"Could not inspect {safe_str(entry.path)}: {safe_str(exc)}")
        return found, notes


class FileSweeper:
    """Bounded, read-only sweep of a few documented user-writable locations for suspicious file content.

    Candidates are executables, scripts and files named like documents or media (which may hide an executable
    header). A file's location alone never produces a finding; only its content or hash can.
    """

    def __init__(self, config: ShadowTraceConfig, analyzer: FileAnalyzer, deadline: Deadline,
                 env: Optional[dict[str, str]] = None) -> None:
        self.config = config
        self.analyzer = analyzer
        self.deadline = deadline
        self.env = dict(os.environ) if env is None else env

    def roots(self) -> list[tuple[str, int]]:
        """``(directory, max_depth)`` pairs. Only well-known user-writable locations are swept."""
        env = {k.lower(): v for k, v in self.env.items()}
        roots: list[tuple[str, int]] = []

        def add(path: Optional[str], depth: int) -> None:
            if path and (path, depth) not in roots:
                roots.append((path, depth))

        temp = env.get("temp") or env.get("tmp")
        add(temp, 2)
        local = env.get("localappdata")
        if local:
            add(ntpath.join(local, "Temp"), 2)
        profile = env.get("userprofile")
        if profile:
            add(ntpath.join(profile, "Downloads"), 2)
            add(ntpath.join(profile, "Desktop"), 1)
        add(env.get("public"), 1)
        add(env.get("appdata"), 2)
        add(env.get("programdata"), 1)
        if self.config.system_root:
            add(ntpath.join(self.config.system_root, "Temp"), 1)
        return roots

    @staticmethod
    def _is_reparse_point(entry: "os.DirEntry[str]") -> bool:
        try:
            attributes = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        except OSError:
            return True
        return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT: skip junctions and symlinks

    def sweep(self) -> tuple[list[FileInfo], CheckStatus]:
        """Walk the documented roots and analyse candidate files within the configured limits."""
        label = CHECK_LABELS["file_sweep"]
        limit = self.config.sweep_limit
        candidates = EXECUTABLE_EXTENSIONS | DECEPTIVE_EXTENSIONS
        analysed: list[FileInfo] = []
        examined = 0
        unreadable = 0
        stopped = ""
        visited: set[str] = set()
        listed = 0
        for root, max_depth in self.roots():
            queue: list[tuple[str, int]] = [(root, 0)]
            while queue and not stopped:
                directory, depth = queue.pop(0)
                key = os.path.normcase(directory)
                if key in visited:
                    continue
                visited.add(key)
                native = directory.replace("\\", os.sep) if os.sep != "\\" else directory
                try:
                    with os.scandir(native) as iterator:
                        entries = sorted(iterator, key=lambda e: e.name.lower())
                except (FileNotFoundError, NotADirectoryError):
                    continue
                except OSError:
                    unreadable += 1
                    continue
                listed += 1
                for entry in entries:
                    if self.deadline.expired():
                        stopped = "scan time limit reached"
                        break
                    try:
                        if self._is_reparse_point(entry):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if depth < max_depth:
                                queue.append((entry.path, depth + 1))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        unreadable += 1
                        continue
                    ext = os.path.splitext(entry.name)[1].lower()
                    if ext not in candidates or ext == ".lnk":
                        continue
                    if examined >= limit:
                        stopped = f"file limit ({limit}) reached"
                        break
                    examined += 1
                    analysed.append(self.analyzer.analyze(entry.path, source="sweep", hash_enabled=True,
                                                          inspect=self.config.inspect_content))
            if stopped:
                break
        errors = sum(1 for info in analysed if info.error)
        detail = f"{examined} candidate files examined in {listed} directories"
        if unreadable or errors:
            detail += f"; {unreadable} directories and {errors} files could not be read"
        status = COMPLETED
        if stopped:
            status = PARTIAL
            detail += f"; stopped early: {stopped}"
        elif unreadable or errors:
            status = PARTIAL
        if not listed:
            return [], CheckStatus("file_sweep", label, SKIPPED, "No documented sweep locations exist on this system.")
        return analysed, CheckStatus("file_sweep", label, status, detail, len(analysed))


# --------------------------------------------------------------------------- #
# Process inventory
# --------------------------------------------------------------------------- #
class ProcessScanner:
    """Read-only inventory of running processes using psutil."""

    ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "create_time", "username"]

    def __init__(
        self,
        config: ShadowTraceConfig,
        analyzer: FileAnalyzer,
        deadline: Deadline,
        path_exists: Callable[[str], bool] = os.path.exists,
    ) -> None:
        self.config = config
        self.analyzer = analyzer
        self.deadline = deadline
        self.path_exists = path_exists

    def build_process(self, info: dict[str, Any]) -> ProcessInfo:
        """Turn a psutil attribute dict into a :class:`ProcessInfo`."""
        errors: list[str] = []
        pid = int(info.get("pid") or 0)
        name = safe_str(info.get("name") or "")
        raw_exe = info.get("exe")
        exe = safe_str(raw_exe) if raw_exe else None
        if exe is None:
            errors.append("executable path not available (restricted, protected or system process)")
        raw_cmd = info.get("cmdline")
        if raw_cmd:
            try:
                cmd_text = subprocess.list2cmdline([safe_str(part) for part in raw_cmd])
            except (TypeError, ValueError):
                cmd_text = " ".join(safe_str(part) for part in raw_cmd)
        else:
            cmd_text = ""
            errors.append("command line not available or empty")
        started = info.get("create_time")
        exists: Optional[bool] = None
        if exe:
            try:
                exists = bool(self.path_exists(exe))
            except (OSError, ValueError):
                exists = None
        digest: Optional[str] = None
        if exe and exists and self.config.hash_files:
            if self.config.inspect_content:
                analysed = self.analyzer.analyze(exe, source="process", hash_enabled=True, inspect=True)
                digest, hash_error = analysed.sha256, (analysed.hash_note or analysed.error)
            else:
                digest, hash_error = self.analyzer.hash_file(exe)
            if hash_error:
                errors.append(f"hash unavailable: {hash_error}")
        return ProcessInfo(
            pid=pid,
            ppid=info.get("ppid"),
            name=name,
            exe=exe,
            cmdline=sanitize_text(cmd_text, self.config.max_cmdline_chars),
            started_at=iso_from_ts(started),
            start_ts=started if isinstance(started, (int, float)) else None,
            username=safe_str(info.get("username")) or None,
            exe_exists=exists,
            sha256=digest,
            errors=errors,
        )

    def scan(self) -> tuple[list[ProcessInfo], CheckStatus]:
        """Enumerate accessible processes, tolerating per-process failures."""
        label = "Running-process inventory"
        if psutil is None:
            return [], CheckStatus("process_inventory", label, SKIPPED,
                                   "psutil is not installed. Run: pip install psutil")
        processes: list[ProcessInfo] = []
        skipped = 0
        stopped_early = ""
        try:
            for proc in psutil.process_iter(self.ATTRS, ad_value=None):
                if self.deadline.expired():
                    stopped_early = "scan time limit reached"
                    break
                if len(processes) >= self.config.max_processes:
                    stopped_early = f"process limit ({self.config.max_processes}) reached"
                    break
                try:
                    processes.append(self.build_process(proc.info))
                except (psutil.Error, OSError, ValueError, TypeError) as exc:
                    # A process can exit or become unreadable mid-scan; count it and move on.
                    skipped += 1
                    log.debug("Skipping process: %s", exc)
        except (psutil.Error, OSError) as exc:
            status = PARTIAL if processes else FAILED
            return processes, CheckStatus("process_inventory", label, status,
                                          f"Enumeration stopped: {safe_str(exc)}", len(processes))
        restricted = sum(1 for p in processes if not p.exe)
        detail = f"{len(processes)} processes examined; {restricted} had no readable executable path"
        if skipped:
            detail += f"; {skipped} vanished or could not be read"
        if not self.config.hash_files:
            detail += "; hashing disabled in quick mode"
        status = COMPLETED
        if stopped_early:
            status = PARTIAL
            detail += f"; stopped early: {stopped_early}"
        return processes, CheckStatus("process_inventory", label, status, detail, len(processes))


# --------------------------------------------------------------------------- #
# External programs: the ONLY place ShadowTrace starts a process.
# Every command is a fixed, read-only Windows operation (no user-supplied text, no shell).
# --------------------------------------------------------------------------- #
_PS_FLAGS = ("-NoProfile", "-NonInteractive", "-Command")
DEFENDER_STATUS_PS = (
    "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,"
    "RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress"
)
DEFENDER_DETECTIONS_PS = (
    "$ErrorActionPreference='Stop'; "
    "$t=@(Get-MpThreat | Select-Object ThreatID,ThreatName,IsActive); "
    "$d=@(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 50 "
    "-Property ThreatID,ProcessName,Resources,ActionSuccess,@{n='Time';e={$_.InitialDetectionTime.ToString('o')}}); "
    "@{threats=$t;detections=$d} | ConvertTo-Json -Depth 4 -Compress"
)
WMI_SUBSCRIPTIONS_PS = (
    "$ErrorActionPreference='Stop'; $ns='root/subscription'; "
    "$f=@(Get-CimInstance -Namespace $ns -ClassName __EventFilter | Select-Object Name,Query,QueryLanguage); "
    "$c=@(Get-CimInstance -Namespace $ns -ClassName __EventConsumer | ForEach-Object { [pscustomobject]@{"
    "Name=$_.Name;Type=$_.CimClass.CimClassName;CommandLineTemplate=$_.CommandLineTemplate;"
    "ExecutablePath=$_.ExecutablePath;ScriptingEngine=$_.ScriptingEngine;ScriptFileName=$_.ScriptFileName;"
    "ScriptText=$_.ScriptText} }); "
    "$b=@(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | ForEach-Object { "
    "[pscustomobject]@{Filter=[string]$_.Filter;Consumer=[string]$_.Consumer} }); "
    "@{filters=$f;consumers=$c;bindings=$b} | ConvertTo-Json -Depth 4 -Compress"
)
CIM_DRIVERS_PS = (
    "$ErrorActionPreference='Stop'; Get-CimInstance -ClassName Win32_SystemDriver | "
    "Select-Object Name,State,Started,PathName | ConvertTo-Json -Compress"
)
# key -> (tool, fixed arguments, timeout seconds)
FIXED_COMMANDS: dict[str, tuple[str, tuple[str, ...], float]] = {
    "defender_status": ("powershell", _PS_FLAGS + (DEFENDER_STATUS_PS,), 25.0),
    "defender_detections": ("powershell", _PS_FLAGS + (DEFENDER_DETECTIONS_PS,), 40.0),
    "wmi_subscriptions": ("powershell", _PS_FLAGS + (WMI_SUBSCRIPTIONS_PS,), 40.0),
    "cim_drivers": ("powershell", _PS_FLAGS + (CIM_DRIVERS_PS,), 40.0),
    "event_powershell_scriptblock": (
        "wevtutil",
        ("qe", "Microsoft-Windows-PowerShell/Operational", "/q:*[System[(EventID=4104)]]", "/c:100", "/rd:true", "/f:xml"),
        40.0,
    ),
    "bcdedit_current": ("bcdedit", ("/enum", "{current}"), 15.0),
}
TOOL_RELATIVE_PATHS: dict[str, tuple[str, ...]] = {
    "powershell": ("WindowsPowerShell", "v1.0", "powershell.exe"),
    "wevtutil": ("wevtutil.exe",),
    "bcdedit": ("bcdedit.exe",),
}


@dataclass
class CommandOutcome:
    """Result of one fixed command: ok | unsupported | not_found | timeout | error | nonzero."""

    kind: str
    stdout: str = ""
    note: str = ""
    returncode: Optional[int] = None


class CommandRunner:
    """Runs only the fixed commands in ``FIXED_COMMANDS``, by absolute path, never through a shell."""

    def __init__(self, runner: Callable[..., Any] = subprocess.run, system_root: Optional[str] = None) -> None:
        self.runner = runner
        self.system_root = system_root

    def launch_root(self) -> Optional[str]:
        """The Windows directory programs may be launched from: an explicit test value or the verified API answer."""
        return self.system_root or windows_directory_from_api()

    def tool_path(self, tool: str, root: str) -> str:
        """Absolute path of a Windows tool (avoids PATH / current-directory hijacking; Sysnative under WOW64)."""
        folder = "Sysnative" if is_wow64_python() else "System32"
        return ntpath.join(root, folder, *TOOL_RELATIVE_PATHS[tool])

    def run(self, key: str, deadline: Optional["Deadline"] = None, timeout: Optional[float] = None) -> CommandOutcome:
        """Execute one fixed command and classify the outcome. Unknown keys are a programming error."""
        tool, args, default_timeout = FIXED_COMMANDS[key]
        if not IS_WINDOWS:
            return CommandOutcome("unsupported", note="Windows only")
        root = self.launch_root()
        if root is None:
            return CommandOutcome("error", note="the Windows directory could not be determined, so no external tool was started")
        limit = timeout if timeout is not None else default_timeout
        if deadline is not None:
            remaining = deadline.remaining()
            if remaining is not None:
                if remaining <= 0:
                    return CommandOutcome("timeout", note="scan time limit reached")
                limit = min(limit, remaining)
        kwargs: dict[str, Any] = {
            "capture_output": True, "text": True, "errors": "replace", "timeout": limit,
            "check": False, "shell": False, "stdin": subprocess.DEVNULL,
        }
        if IS_WINDOWS:
            kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        try:
            completed = self.runner([self.tool_path(tool, root), *args], **kwargs)
        except FileNotFoundError:
            return CommandOutcome("not_found", note=f"{tool} was not found")
        except subprocess.TimeoutExpired:
            return CommandOutcome("timeout", note=f"timed out after {limit:.0f}s")
        except OSError as exc:
            return CommandOutcome("error", note=safe_str(exc))
        stdout = getattr(completed, "stdout", "") or ""
        code = getattr(completed, "returncode", 1)
        if code != 0:
            stderr = sanitize_text(getattr(completed, "stderr", "") or "", 200)
            return CommandOutcome("nonzero", stdout, stderr, code)
        return CommandOutcome("ok", stdout, "", code)


def outcome_problem(outcome: CommandOutcome, what: str) -> Optional[tuple[str, str]]:
    """``(status, detail)`` when a command produced no usable output, else ``None``."""
    if outcome.kind == "ok":
        return None
    if outcome.kind == "unsupported":
        return SKIPPED, f"{what} is only available on Windows."
    if outcome.kind == "not_found":
        return SKIPPED, f"The Windows tool needed for {what} was not found."
    if outcome.kind == "timeout":
        return FAILED, f"{what} timed out ({outcome.note})."
    if outcome.kind == "error":
        return FAILED, f"{what} could not be started: {outcome.note}"
    detail = f" ({outcome.note})" if outcome.note else ""
    return SKIPPED, (f"{what} was not permitted or is not available{detail}; "
                     "administrator rights are often required.")


def parse_xml_safely(raw: Any) -> "ET.Element":
    """Parse XML that came from the local system, refusing DTD/entity declarations (entity-expansion attacks)."""
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-16", errors="replace") if bytes(raw[:2]) in (b"\xff\xfe", b"\xfe\xff") \
            else bytes(raw).decode("utf-8", errors="replace")
    else:
        text = str(raw)
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValueError("XML containing DTD or entity declarations was rejected")
    # DTD and entity declarations were rejected above and the data is local, so entity-expansion attacks do not apply.
    return ET.fromstring(raw)  # nosec B314


def xml_local(tag: str) -> str:
    """Local name of an XML tag, without its namespace."""
    return tag.rsplit("}", 1)[-1]


def as_list(value: Any) -> list[Any]:
    """PowerShell's ConvertTo-Json yields a bare object for one item and a list for several."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def to_bool(value: Any) -> Optional[bool]:
    """Best-effort boolean from JSON values."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return None


# --------------------------------------------------------------------------- #
# Microsoft Defender (read-only status and history)
# --------------------------------------------------------------------------- #
class TelemetryChecker:
    """Optional, read-only Microsoft Defender queries (fixed cmdlets; never changes settings or starts scans)."""

    DEFENDER_COMMAND = DEFENDER_STATUS_PS

    def __init__(self, runner: Callable[..., Any] = subprocess.run, timeout: float = 20.0,
                 system_root: Optional[str] = None) -> None:
        self.commands = CommandRunner(runner, system_root)
        self.timeout = timeout

    def check_defender(self, deadline: Optional["Deadline"] = None) -> tuple[TelemetryResult, CheckStatus]:
        """Read Defender status through a single read-only cmdlet with a timeout."""
        label = CHECK_LABELS["telemetry_defender"]
        outcome = self.commands.run("defender_status", deadline, timeout=self.timeout)
        if outcome.kind == "unsupported":
            note = "Defender status is only available on Windows."
            return (TelemetryResult("defender", False, False, note=note),
                    CheckStatus("telemetry_defender", label, SKIPPED, note))
        if outcome.kind == "not_found":
            note = "powershell.exe was not found."
            return (TelemetryResult("defender", False, False, note=note),
                    CheckStatus("telemetry_defender", label, SKIPPED, note))
        if outcome.kind == "timeout":
            note = f"Defender query timed out ({outcome.note})."
            return (TelemetryResult("defender", True, False, note=note),
                    CheckStatus("telemetry_defender", label, FAILED, note))
        if outcome.kind == "error":
            note = f"Could not run PowerShell: {outcome.note}"
            return (TelemetryResult("defender", False, False, note=note),
                    CheckStatus("telemetry_defender", label, FAILED, note))
        output = outcome.stdout.strip()
        if outcome.kind != "ok" or not output:
            note = "Defender status is not available (Defender may be absent or managed by another product)."
            return (TelemetryResult("defender", False, False, note=note),
                    CheckStatus("telemetry_defender", label, SKIPPED, note))
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            note = "Defender returned output that could not be parsed."
            return (TelemetryResult("defender", True, False, note=note),
                    CheckStatus("telemetry_defender", label, FAILED, note))
        if not isinstance(data, dict):
            note = "Defender returned an unexpected data shape."
            return (TelemetryResult("defender", True, False, note=note),
                    CheckStatus("telemetry_defender", label, FAILED, note))
        details = {key: data.get(key) for key in
                   ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled", "AntivirusSignatureAge")}
        return (TelemetryResult("defender", True, True, details, "Read via Get-MpComputerStatus (read-only)."),
                CheckStatus("telemetry_defender", label, COMPLETED, "Defender status read (this is not a scan).", 1))

    def check_detections(self, deadline: Optional["Deadline"] = None) -> tuple[list[ThreatDetection], CheckStatus]:
        """Read recent Defender detection history (read-only; not the same as running a scan)."""
        label = CHECK_LABELS["defender_detections"]
        outcome = self.commands.run("defender_detections", deadline)
        problem = outcome_problem(outcome, "The Defender detection-history query")
        if problem:
            return [], CheckStatus("defender_detections", label, problem[0], problem[1])
        output = outcome.stdout.strip()
        if not output:
            return [], CheckStatus("defender_detections", label, COMPLETED,
                                   "Defender returned no detection history (reading history is not a scan).")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return [], CheckStatus("defender_detections", label, FAILED, "Defender output could not be parsed.")
        if not isinstance(data, dict):
            return [], CheckStatus("defender_detections", label, FAILED, "Defender returned an unexpected data shape.")
        names: dict[str, tuple[str, Optional[bool]]] = {}
        for threat in as_list(data.get("threats")):
            if isinstance(threat, dict):
                names[safe_str(threat.get("ThreatID"))] = (safe_str(threat.get("ThreatName")),
                                                           to_bool(threat.get("IsActive")))
        detections: list[ThreatDetection] = []
        for item in as_list(data.get("detections"))[:50]:
            if not isinstance(item, dict):
                continue
            threat_id = safe_str(item.get("ThreatID"))
            name, active = names.get(threat_id, ("", None))
            detections.append(ThreatDetection(
                threat_id=threat_id,
                name=name or f"Threat {threat_id}",
                resources=[sanitize_text(r, 200) for r in as_list(item.get("Resources"))[:5]],
                process_name=safe_str(item.get("ProcessName")),
                time=safe_str(item.get("Time")),
                action_success=to_bool(item.get("ActionSuccess")),
                active=active,
            ))
        detail = (f"{len(detections)} detection-history entries read (history may include remediated items; "
                  "this is not a scan).")
        return detections, CheckStatus("defender_detections", label, COMPLETED, detail, len(detections))


# --------------------------------------------------------------------------- #
# Fileless evidence from the PowerShell script-block log
# --------------------------------------------------------------------------- #
class EventLogScanner:
    """Reads recent PowerShell script-block events (4104) with wevtutil and applies the pattern table."""

    LOG = "Microsoft-Windows-PowerShell/Operational"
    MAX_OUTPUT_CHARS = 12 * 1024 * 1024
    MAX_EVIDENCE = 50

    def __init__(self, commands: CommandRunner, deadline: Deadline) -> None:
        self.commands = commands
        self.deadline = deadline

    def scan(self) -> tuple[list[EventEvidence], CheckStatus]:
        """Return pattern evidence from recent script-block events (historical; depends on logging)."""
        label = CHECK_LABELS["event_logs"]
        outcome = self.commands.run("event_powershell_scriptblock", self.deadline)
        problem = outcome_problem(outcome, "The PowerShell event-log query")
        if problem:
            return [], CheckStatus("event_logs", label, problem[0], problem[1])
        output = outcome.stdout.strip()
        if not output:
            return [], CheckStatus(
                "event_logs", label, COMPLETED,
                "No script-block events were returned. Script-block logging is often disabled, so this is not "
                "evidence that nothing ran.")
        if len(output) > self.MAX_OUTPUT_CHARS:
            return [], CheckStatus("event_logs", label, PARTIAL,
                                   "The event output was too large to parse safely and was not analysed.")
        try:
            root = parse_xml_safely(f"<Events>{output}</Events>")
        except (ET.ParseError, ValueError) as exc:
            return [], CheckStatus("event_logs", label, FAILED, f"Event XML could not be parsed: {safe_str(exc)}")
        evidence: list[EventEvidence] = []
        parsed = 0
        for event in root:
            parsed += 1
            when = ""
            text = ""
            for node in event.iter():
                name = xml_local(node.tag)
                if name == "TimeCreated":
                    when = safe_str(node.attrib.get("SystemTime", ""))
                elif name == "Data" and node.attrib.get("Name") == "ScriptBlockText":
                    text = node.text or ""
            hits = scan_patterns(text[:20000], "script")
            if not hits or len(evidence) >= self.MAX_EVIDENCE:
                continue
            match = hits[0].regex.search(text)
            start = max(0, (match.start() if match else 0) - 40)
            end = (match.end() if match else 0) + 80
            evidence.append(EventEvidence(
                log=self.LOG, event_id=4104, time=when, patterns=[h.pid for h in hits],
                labels=[h.label for h in hits], excerpt=sanitize_text(text[start:end], 200)))
        detail = (f"{parsed} recent script-block events read; {len(evidence)} matched documented patterns "
                  "(history only; depends on logging being enabled).")
        return evidence, CheckStatus("event_logs", label, COMPLETED, detail, parsed)
# --------------------------------------------------------------------------- #
# Additional persistence locations (scheduled tasks, WMI, execution-hijack settings)
# --------------------------------------------------------------------------- #
APPINIT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
SILENT_EXIT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
# (hive, subkey, value names). Values are only read; empty values are not recorded.
REGISTRY_CONFIG_VALUES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("HKLM", APPINIT_KEY, ("AppInit_DLLs", "LoadAppInit_DLLs", "Load")),
    ("HKCU", r"Software\Microsoft\Windows NT\CurrentVersion\Windows", ("Load",)),
    ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager", ("BootExecute",)),
    ("HKLM", r"SOFTWARE\Microsoft\Command Processor", ("AutoRun",)),
    ("HKCU", r"Software\Microsoft\Command Processor", ("AutoRun",)),
)
MAX_TASK_FILE_BYTES = 512 * 1024


def parse_task_xml(raw: bytes) -> dict[str, Any]:
    """Parse a Task Scheduler XML definition (read-only). Raises ValueError / ET.ParseError when malformed."""
    root = parse_xml_safely(raw)

    def child(elem: Optional["ET.Element"], name: str) -> Optional["ET.Element"]:
        if elem is None:
            return None
        for node in elem:
            if xml_local(node.tag) == name:
                return node
        return None

    def text(elem: Optional["ET.Element"], name: str, default: str = "") -> str:
        node = child(elem, name)
        return (node.text or "").strip() if node is not None and node.text else default

    settings = child(root, "Settings")
    principal = child(child(root, "Principals"), "Principal")
    triggers: list[str] = []
    triggers_node = child(root, "Triggers")
    if triggers_node is not None:
        for trig in triggers_node:
            label = xml_local(trig.tag)
            delay = text(trig, "Delay")
            if delay:
                label += f" (delay {delay})"
            if text(trig, "Enabled", "true").lower() == "false":
                label += " [disabled]"
            triggers.append(label)
    actions: list[dict[str, str]] = []
    actions_node = child(root, "Actions")
    if actions_node is not None:
        for action in actions_node:
            kind = xml_local(action.tag)
            if kind == "Exec":
                actions.append({"kind": "Exec", "command": text(action, "Command"),
                                "arguments": text(action, "Arguments"), "workdir": text(action, "WorkingDirectory")})
            elif kind == "ComHandler":
                actions.append({"kind": "ComHandler", "class_id": text(action, "ClassId")})
    return {
        "author": text(child(root, "RegistrationInfo"), "Author"),
        "enabled": text(settings, "Enabled", "true").lower() != "false",
        "hidden": text(settings, "Hidden", "false").lower() == "true",
        "run_level": text(principal, "RunLevel"),
        "user": text(principal, "UserId") or text(principal, "GroupId"),
        "triggers": triggers,
        "actions": actions,
    }


class ExtendedPersistenceMixin:
    """Scheduled-task, WMI and registry-setting inspection; mixed into :class:`PersistenceScanner`."""

    # Attributes below are provided by PersistenceScanner.__init__.
    config: ShadowTraceConfig
    deadline: Deadline
    registry: Optional[Any]
    commands: CommandRunner
    tasks_dir: Optional[str]

    # -- execution-hijack / auto-run registry settings ---------------------- #
    def scan_registry_config(self) -> tuple[list[StartupEntry], CheckStatus]:
        """Read IFEO Debugger, AppInit_DLLs, BootExecute, AutoRun and Load values (read-only)."""
        label = CHECK_LABELS["registry_config"]
        if self.registry is None:
            return [], CheckStatus("registry_config", label, SKIPPED,
                                   "The Windows registry (winreg) is not available on this platform.")
        entries: list[StartupEntry] = []
        denied: list[str] = []
        errored: list[str] = []
        time_up = False

        def record(hive: str, subkey: str, name: str, raw: Any, setting: str, view: Optional[str] = None) -> None:
            command = self._value_to_text(raw).strip()  # type: ignore[attr-defined]
            if not command and name.lower() != "loadappinit_dlls":
                return
            entry = self.make_entry("registry_config", "registry", f"{hive}\\{subkey}", name, command,  # type: ignore[attr-defined]
                                    view, {"setting": setting})
            entries.append(entry)

        for hive, subkey, names in REGISTRY_CONFIG_VALUES:
            if self.deadline.expired():
                time_up = True
                break
            try:
                values = self.registry.read_values(hive, subkey, "default")
            except FileNotFoundError:
                continue
            except PermissionError:
                denied.append(f"{hive}\\{subkey}")
                continue
            except OSError as exc:
                errored.append(f"{hive}\\{subkey}: {safe_str(exc)}")
                continue
            wanted = {n.lower() for n in names}
            for name, raw, _vtype in values:
                if name.lower() in wanted:
                    record(hive, subkey, name, raw, name)

        lister = getattr(self.registry, "list_subkeys", None)
        if lister is None:
            errored.append("subkey enumeration is not supported by this registry reader (IFEO/SilentProcessExit skipped)")
        else:
            for base, value_name, setting in ((IFEO_KEY, "Debugger", "Image File Execution Options Debugger"),
                                              (SILENT_EXIT_KEY, "MonitorProcess", "SilentProcessExit MonitorProcess")):
                for view in ("64-bit", "32-bit"):
                    if time_up or self.deadline.expired():
                        time_up = True
                        break
                    try:
                        subkeys = lister("HKLM", base, view)
                    except FileNotFoundError:
                        continue
                    except PermissionError:
                        denied.append(f"HKLM\\{base} ({view})")
                        continue
                    except OSError as exc:
                        errored.append(f"HKLM\\{base} ({view}): {safe_str(exc)}")
                        continue
                    for sub in subkeys[:3000]:
                        try:
                            values = self.registry.read_values("HKLM", f"{base}\\{sub}", view)
                        except (FileNotFoundError, PermissionError, OSError):
                            continue  # one unreadable subkey must not stop the sweep
                        for name, raw, _vtype in values:
                            if name.lower() == value_name.lower():
                                record("HKLM", f"{base}\\{sub}", sub, raw, setting, view)
        seen: set[tuple[str, str, str]] = set()
        unique: list[StartupEntry] = []
        for entry in entries:
            signature = (entry.location.lower(), entry.name.lower(), entry.command.lower())
            if signature not in seen:
                seen.add(signature)
                unique.append(entry)
        detail = f"{len(unique)} settings recorded"
        status = COMPLETED
        if denied:
            status = PARTIAL
            detail += f"; access denied: {', '.join(denied[:6])}"
        if errored:
            status = PARTIAL
            detail += f"; notes: {'; '.join(errored[:4])}"
        if time_up:
            status = PARTIAL
            detail += "; stopped early: scan time limit reached"
        return unique, CheckStatus("registry_config", label, status, detail, len(unique))

    # -- scheduled tasks ------------------------------------------------------ #
    def _tasks_root(self) -> str:
        if self.tasks_dir:
            return self.tasks_dir
        folder = "Sysnative" if is_wow64_python() else "System32"
        return ntpath.join(self.config.system_root, folder, "Tasks")

    def scan_tasks(self) -> tuple[list[StartupEntry], CheckStatus]:
        """Parse Task Scheduler definitions from the Tasks folder (read-only; tasks are never run or changed)."""
        label = CHECK_LABELS["scheduled_tasks"]
        root = self._tasks_root()
        native = root.replace("\\", os.sep) if os.sep != "\\" else root
        if not os.path.isdir(native):
            return [], CheckStatus("scheduled_tasks", label, SKIPPED,
                                   "The Task Scheduler folder was not found on this system.")
        entries: list[StartupEntry] = []
        parsed = disabled = malformed = unreadable = 0
        denied: list[str] = []
        stopped = ""

        def on_error(error: OSError) -> None:
            denied.append(safe_str(getattr(error, "filename", "")))

        for dirpath, dirnames, filenames in os.walk(native, onerror=on_error, followlinks=False):
            dirnames.sort()
            for filename in sorted(filenames):
                if self.deadline.expired():
                    stopped = "scan time limit reached"
                    break
                if parsed + malformed + unreadable >= self.config.max_tasks:
                    stopped = f"task limit ({self.config.max_tasks}) reached"
                    break
                full = os.path.join(dirpath, filename)
                try:
                    if os.path.getsize(full) > MAX_TASK_FILE_BYTES:
                        malformed += 1
                        continue
                    with open(full, "rb") as handle:
                        raw = handle.read(MAX_TASK_FILE_BYTES + 1)
                except OSError:
                    unreadable += 1
                    continue
                try:
                    task = parse_task_xml(raw)
                except (ET.ParseError, ValueError):
                    malformed += 1
                    continue
                parsed += 1
                if not task["enabled"]:
                    disabled += 1
                    continue
                task_path = "\\" + os.path.relpath(full, native).replace(os.sep, "\\")
                attributes = {"task_path": safe_str(task_path), "author": safe_str(task["author"]),
                              "triggers": task["triggers"], "hidden": task["hidden"],
                              "run_level": task["run_level"], "user": safe_str(task["user"])}
                for action in task["actions"]:
                    if action["kind"] == "Exec" and action["command"]:
                        command = action["command"]
                        if " " in command and not command.startswith('"'):
                            command = f'"{command}"'
                        if action["arguments"]:
                            command = f"{command} {action['arguments']}"
                        entries.append(self.make_entry("scheduled_task", "scheduled task", "Scheduled Tasks",  # type: ignore[attr-defined]
                                                       task_path, command, None, dict(attributes)))
                    elif action["kind"] == "ComHandler":
                        entries.append(StartupEntry(
                            kind="scheduled_task", source="scheduled task", location="Scheduled Tasks",
                            name=safe_str(task_path), command=f"COM handler {safe_str(action.get('class_id'))}",
                            attributes=dict(attributes)))
            if stopped:
                break
        detail = (f"{parsed} task definitions parsed, {len(entries)} actions in {parsed - disabled} enabled tasks "
                  f"({disabled} disabled tasks skipped)")
        status = COMPLETED
        if malformed or unreadable or denied:
            status = PARTIAL
            detail += f"; {malformed} malformed/oversized, {unreadable} unreadable, {len(denied)} folders denied"
        if stopped:
            status = PARTIAL
            detail += f"; stopped early: {stopped}"
        return entries, CheckStatus("scheduled_tasks", label, status, detail, len(entries))

    # -- WMI persistence ------------------------------------------------------- #
    def scan_wmi(self) -> tuple[list[StartupEntry], CheckStatus]:
        """List WMI permanent event subscriptions through a fixed, read-only CIM query."""
        label = CHECK_LABELS["wmi_persistence"]
        outcome = self.commands.run("wmi_subscriptions", self.deadline)
        problem = outcome_problem(outcome, "The WMI subscription query")
        if problem:
            return [], CheckStatus("wmi_persistence", label, problem[0], problem[1])
        output = outcome.stdout.strip()
        if not output:
            return [], CheckStatus("wmi_persistence", label, COMPLETED, "No WMI event subscriptions were returned.")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return [], CheckStatus("wmi_persistence", label, FAILED, "WMI output could not be parsed.")
        if not isinstance(data, dict):
            return [], CheckStatus("wmi_persistence", label, FAILED, "WMI returned an unexpected data shape.")
        queries = {safe_str(f.get("Name")): sanitize_text(f.get("Query"), 200)
                   for f in as_list(data.get("filters")) if isinstance(f, dict)}
        bound: dict[str, list[str]] = {}
        for binding in as_list(data.get("bindings")):
            if not isinstance(binding, dict):
                continue
            consumer = re.search(r'Name="([^"]*)"', safe_str(binding.get("Consumer")))
            filt = re.search(r'Name="([^"]*)"', safe_str(binding.get("Filter")))
            if consumer:
                bound.setdefault(consumer.group(1), []).append(queries.get(filt.group(1), "?") if filt else "?")
        entries: list[StartupEntry] = []
        for consumer in as_list(data.get("consumers")):
            if not isinstance(consumer, dict):
                continue
            name = safe_str(consumer.get("Name"))
            ctype = safe_str(consumer.get("Type"))
            command = safe_str(consumer.get("CommandLineTemplate")) or safe_str(consumer.get("ExecutablePath"))
            if not command and consumer.get("ScriptFileName"):
                command = f"{safe_str(consumer.get('ScriptingEngine'))} script file {safe_str(consumer.get('ScriptFileName'))}"
            if not command and consumer.get("ScriptText"):
                command = f"{safe_str(consumer.get('ScriptingEngine'))} inline script: {safe_str(consumer.get('ScriptText'))}"
            entries.append(self.make_entry("wmi", "WMI subscription", "root\\subscription", name,  # type: ignore[attr-defined]
                                           command or f"({ctype})", None,
                                           {"wmi_type": ctype, "filters": bound.get(name, []), "bound": name in bound}))
        executing = sum(1 for e in entries if e.attributes.get("wmi_type") in WMI_EXECUTING_TYPES)
        detail = f"{len(entries)} consumers read ({executing} can run commands or scripts)"
        return entries, CheckStatus("wmi_persistence", label, COMPLETED, detail, len(entries))


WMI_EXECUTING_TYPES = frozenset({"CommandLineEventConsumer", "ActiveScriptEventConsumer"})


# --------------------------------------------------------------------------- #
# Persistence inspection (strictly read-only)
# --------------------------------------------------------------------------- #
class RegistryReader(Protocol):
    """Interface for reading registry values; allows mocking in tests."""

    def read_values(self, hive: str, subkey: str, view: str) -> list[tuple[str, Any, int]]:
        """Return ``(name, value, type)`` tuples; raise FileNotFoundError / PermissionError / OSError."""

    def list_subkeys(self, hive: str, subkey: str, view: str) -> list[str]:
        """Return the names of the subkeys of a key (same exceptions as ``read_values``)."""


class WinRegistryReader:
    """Reads registry values with ``winreg`` using KEY_READ access only."""

    def read_values(self, hive: str, subkey: str, view: str) -> list[tuple[str, Any, int]]:
        if winreg is None:
            raise OSError("winreg is not available on this platform")
        hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        access = winreg.KEY_READ
        if view == "64-bit":
            access |= winreg.KEY_WOW64_64KEY
        elif view == "32-bit":
            access |= winreg.KEY_WOW64_32KEY
        results: list[tuple[str, Any, int]] = []
        with winreg.OpenKey(hives[hive], subkey, 0, access) as key:
            count = winreg.QueryInfoKey(key)[1]
            for index in range(count):
                try:
                    name, value, value_type = winreg.EnumValue(key, index)
                except OSError:
                    break
                results.append((safe_str(name), value, value_type))
        return results

    def list_subkeys(self, hive: str, subkey: str, view: str) -> list[str]:
        if winreg is None:
            raise OSError("winreg is not available on this platform")
        hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        access = winreg.KEY_READ
        if view == "64-bit":
            access |= winreg.KEY_WOW64_64KEY
        elif view == "32-bit":
            access |= winreg.KEY_WOW64_32KEY
        names: list[str] = []
        with winreg.OpenKey(hives[hive], subkey, 0, access) as key:
            for index in range(winreg.QueryInfoKey(key)[0]):
                try:
                    names.append(safe_str(winreg.EnumKey(key, index)))
                except OSError:
                    break
        return names


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUNONCE_KEY = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
POLICY_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
WINLOGON_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
# (hive, subkey, query both 64-bit and 32-bit registry views?)
REGISTRY_AUTORUN_KEYS: tuple[tuple[str, str, bool], ...] = (
    ("HKCU", RUN_KEY, False),
    ("HKCU", RUNONCE_KEY, False),
    ("HKCU", POLICY_RUN_KEY, False),
    ("HKLM", RUN_KEY, True),
    ("HKLM", RUNONCE_KEY, True),
    ("HKLM", POLICY_RUN_KEY, True),
)
WINLOGON_LOCATIONS: tuple[tuple[str, str], ...] = (("HKLM", WINLOGON_KEY), ("HKCU", WINLOGON_KEY))


class PersistenceScanner(ExtendedPersistenceMixin):
    """Inspects startup persistence locations without modifying anything."""

    def __init__(
        self,
        config: ShadowTraceConfig,
        analyzer: FileAnalyzer,
        deadline: Deadline,
        registry_reader: Optional[RegistryReader] = None,
        path_exists: Callable[[str], bool] = os.path.exists,
        env: Optional[dict[str, str]] = None,
        service_iter: Optional[Callable[[], Any]] = None,
        commands: Optional[CommandRunner] = None,
        tasks_dir: Optional[str] = None,
    ) -> None:
        self.config = config
        self.analyzer = analyzer
        self.deadline = deadline
        self.path_exists = path_exists
        self.env = dict(os.environ) if env is None else env
        self.service_iter = service_iter
        self.commands = commands or CommandRunner()
        self.tasks_dir = tasks_dir
        self.scm_service_names: set[str] = set()
        if registry_reader is None and winreg is not None:
            registry_reader = WinRegistryReader()
        self.registry = registry_reader

    # -- helpers ----------------------------------------------------------- #
    _INSPECT_SOURCE = {"autorun": "startup-target", "registry_config": "startup-target",
                       "service": "service-binary", "scheduled_task": "task-target", "wmi": "startup-target"}

    def make_entry(self, kind: str, source: str, location: str, name: str, command: str,
                   view: Optional[str] = None, attributes: Optional[dict[str, Any]] = None) -> StartupEntry:
        """Build a :class:`StartupEntry`, resolving and checking the target program."""
        program, _ = parse_command(command, self.env, self.config.system_root)
        target = resolve_target(program)
        exists: Optional[bool] = None
        if target:
            try:
                exists = bool(self.path_exists(target))
            except (OSError, ValueError):
                exists = None
        digest: Optional[str] = None
        if exists and target and self.config.hash_files:
            if self.config.inspect_content:
                digest = self.analyzer.analyze(target, source=self._INSPECT_SOURCE.get(kind, kind),
                                               hash_enabled=True, inspect=True).sha256
            else:
                digest, _ = self.analyzer.hash_file(target)
        return StartupEntry(
            kind=kind,
            source=source,
            location=safe_str(location),
            name=safe_str(name),
            command=sanitize_text(command, self.config.max_cmdline_chars),
            program_name=program_basename(program),
            target_path=safe_str(target) if target else None,
            target_exists=exists,
            sha256=digest,
            view=view,
            attributes=dict(attributes or {}),
        )

    @staticmethod
    def _value_to_text(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            return f"<binary data, {len(value)} bytes>"
        if isinstance(value, (list, tuple)):
            return " ".join(safe_str(v) for v in value)
        return safe_str(value)

    # -- registry ---------------------------------------------------------- #
    def scan_registry(self) -> tuple[list[StartupEntry], CheckStatus]:
        """Read Run/RunOnce/Policy keys and the Winlogon Shell/Userinit values."""
        label = "Registry startup keys"
        if self.registry is None:
            return [], CheckStatus("registry_autoruns", label, SKIPPED,
                                   "The Windows registry (winreg) is not available on this platform.")
        entries: list[StartupEntry] = []
        denied: list[str] = []
        errored: list[str] = []
        seen: set[tuple[str, str, str, str]] = set()
        time_up = False
        for hive, subkey, both_views in REGISTRY_AUTORUN_KEYS:
            for view in (("64-bit", "32-bit") if both_views else ("default",)):
                if self.deadline.expired():
                    time_up = True
                    break
                location = f"{hive}\\{subkey}"
                try:
                    values = self.registry.read_values(hive, subkey, view)
                except FileNotFoundError:
                    continue  # key absent: nothing configured here
                except PermissionError:
                    denied.append(f"{location} ({view})")
                    continue
                except OSError as exc:
                    errored.append(f"{location} ({view}): {safe_str(exc)}")
                    continue
                for name, raw, _vtype in values:
                    command = self._value_to_text(raw).strip()
                    if command[:1] in ("!", "*"):  # RunOnce execution flags
                        command = command[1:].strip()
                    signature = (hive, subkey.lower(), name.lower(), command.lower())
                    if signature in seen:
                        continue
                    seen.add(signature)
                    entries.append(self.make_entry("autorun", "registry", location, name, command,
                                                   None if view == "default" else view))
            if time_up:
                break
        for hive, subkey in WINLOGON_LOCATIONS:
            if self.deadline.expired():
                time_up = True
                break
            location = f"{hive}\\{subkey}"
            try:
                values = self.registry.read_values(hive, subkey, "default")
            except FileNotFoundError:
                continue
            except PermissionError:
                denied.append(location)
                continue
            except OSError as exc:
                errored.append(f"{location}: {safe_str(exc)}")
                continue
            for name, raw, _vtype in values:
                if name.lower() in ("shell", "userinit"):
                    command = self._value_to_text(raw).strip()
                    entry = self.make_entry("winlogon", "registry", location, name, command)
                    entry.target_exists = None  # existence is not what this check is about
                    entries.append(entry)
        detail = f"{len(entries)} entries read"
        status = COMPLETED
        if denied:
            status = PARTIAL
            detail += f"; access denied: {', '.join(denied)}"
        if errored:
            status = PARTIAL
            detail += f"; errors: {'; '.join(errored)}"
        if time_up:
            status = PARTIAL
            detail += "; stopped early: scan time limit reached"
        return entries, CheckStatus("registry_autoruns", label, status, detail, len(entries))

    # -- startup folders --------------------------------------------------- #
    def startup_folders(self) -> list[tuple[str, str]]:
        """Return ``(description, path)`` pairs for the Startup folders."""
        folders: list[tuple[str, str]] = []
        appdata = self.env.get("APPDATA") or self.env.get("AppData")
        programdata = self.env.get("ProgramData") or self.env.get("PROGRAMDATA")
        if appdata:
            folders.append(("current-user Startup folder",
                            ntpath.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")))
        if programdata:
            folders.append(("all-users Startup folder",
                            ntpath.join(programdata, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp")))
        return folders

    def scan_startup_folders(self) -> tuple[list[StartupEntry], list[FileInfo], CheckStatus]:
        """List (never open or run) items in the Startup folders."""
        label = "Startup folders"
        folders = self.startup_folders()
        if not folders:
            return [], [], CheckStatus("startup_folders", label, SKIPPED,
                                       "APPDATA / ProgramData are not defined (not a Windows session).")
        entries: list[StartupEntry] = []
        infos: list[FileInfo] = []
        notes: list[str] = []
        denied = False
        for description, folder in folders:
            native = folder.replace("\\", os.sep) if os.sep != "\\" else folder
            try:
                with os.scandir(native) as iterator:
                    listing = sorted(iterator, key=lambda e: e.name.lower())
            except FileNotFoundError:
                notes.append(f"{description} does not exist")
                continue
            except PermissionError:
                denied = True
                notes.append(f"{description}: access denied")
                continue
            except OSError as exc:
                denied = True
                notes.append(f"{description}: {safe_str(exc)}")
                continue
            for item in listing[: self.config.max_startup_folder_entries]:
                try:
                    if not item.is_file(follow_symlinks=False) or item.name.lower() == "desktop.ini":
                        continue
                except OSError:
                    continue
                info = self.analyzer.analyze(item.path, source="startup-folder", hash_enabled=self.config.hash_files,
                                             inspect=self.config.inspect_content)
                infos.append(info)
                entries.append(StartupEntry(
                    kind="startup_folder",
                    source=description,
                    location=safe_str(folder),
                    name=safe_str(item.name),
                    command=safe_str(item.path),
                    program_name=safe_str(item.name).lower(),
                    target_path=safe_str(item.path),
                    target_exists=True,
                    sha256=info.sha256,
                ))
        detail = f"{len(entries)} items listed"
        if notes:
            detail += "; " + "; ".join(notes)
        status = PARTIAL if denied else COMPLETED
        return entries, infos, CheckStatus("startup_folders", label, status, detail, len(entries))

    # -- services ---------------------------------------------------------- #
    def scan_services(self) -> tuple[list[StartupEntry], CheckStatus]:
        """Inspect auto-start Windows services via psutil (read-only)."""
        label = "Auto-start Windows services"
        iterator = self.service_iter
        if iterator is None and psutil is not None:
            iterator = getattr(psutil, "win_service_iter", None)
        if iterator is None:
            return [], CheckStatus("services", label, SKIPPED,
                                   "Windows service enumeration (psutil.win_service_iter) is unavailable here.")
        entries: list[StartupEntry] = []
        inspected = 0
        partial_reason = ""
        try:
            for service in iterator():
                if self.deadline.expired():
                    partial_reason = "scan time limit reached"
                    break
                if inspected >= self.config.max_services:
                    partial_reason = f"service limit ({self.config.max_services}) reached"
                    break
                try:
                    data = service.as_dict()
                except (OSError, ValueError, AttributeError) as exc:
                    log.debug("Skipping service: %s", exc)
                    continue
                inspected += 1
                self.scm_service_names.add(safe_str(data.get("name")).lower())
                if safe_str(data.get("start_type")).lower() != "automatic":
                    continue
                binpath = safe_str(data.get("binpath"))
                if not binpath:
                    continue
                entry = self.make_entry("service", "service", "Windows services",
                                        data.get("name") or "?", binpath)
                entry.notes.append(f"status: {safe_str(data.get('status'))}; "
                                   f"account: {safe_str(data.get('username'))}")
                entries.append(entry)
        except (OSError, PermissionError) as exc:
            status = PARTIAL if entries else FAILED
            return entries, CheckStatus("services", label, status,
                                        f"Service enumeration stopped: {safe_str(exc)}", len(entries))
        detail = f"{inspected} services examined, {len(entries)} auto-start entries recorded"
        status = COMPLETED
        if partial_reason:
            status = PARTIAL
            detail += f"; stopped early: {partial_reason}"
        return entries, CheckStatus("services", label, status, detail, len(entries))


# --------------------------------------------------------------------------- #
# Drivers, security settings and cross-view checks (read-only; drivers are never loaded or executed)
# --------------------------------------------------------------------------- #
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
DRIVER_SERVICE_TYPES = frozenset({1, 2, 8})   # kernel driver, file-system driver, recognizer driver
START_LABELS = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}


def to_int(value: Any) -> Optional[int]:
    """Integer from a registry/JSON value, or ``None``."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def normalize_kernel_path(image_path: str, system_root: str, env: Optional[dict[str, str]] = None) -> Optional[str]:
    """Turn a driver ``ImagePath`` (``\\SystemRoot\\...``, ``\\??\\C:\\...``, relative or absolute) into a plain path."""
    text = safe_str(image_path).strip().strip('"')
    if not text:
        return None
    text = expand_env_vars(text, {**(env or {}), "SystemRoot": system_root, "windir": system_root})
    if text.startswith("\\??\\"):
        text = text[4:]
    if text.lower().startswith("\\systemroot\\"):
        text = system_root.rstrip("\\") + text[len("\\SystemRoot"):]
    elif not (re.match(r"^[A-Za-z]:[\\/]", text) or text.startswith("\\\\")):
        text = ntpath.join(system_root, text)
    return text


class DriverScanner:
    """Enumerates driver services from the registry (and their loaded state from CIM) without loading anything."""

    def __init__(self, config: ShadowTraceConfig, analyzer: FileAnalyzer, deadline: Deadline,
                 registry: Optional[Any], commands: CommandRunner,
                 path_exists: Callable[[str], bool] = os.path.exists, env: Optional[dict[str, str]] = None) -> None:
        self.config = config
        self.analyzer = analyzer
        self.deadline = deadline
        self.registry = registry
        self.commands = commands
        self.path_exists = path_exists
        self.env = dict(os.environ) if env is None else env
        self.registry_service_names: set[str] = set()
        self.cim_driver_names: set[str] = set()

    def _loaded_states(self) -> tuple[dict[str, str], str]:
        outcome = self.commands.run("cim_drivers", self.deadline)
        problem = outcome_problem(outcome, "The loaded-driver (Win32_SystemDriver) view")
        if problem:
            return {}, problem[1]
        try:
            data = json.loads(outcome.stdout.strip() or "[]")
        except json.JSONDecodeError:
            return {}, "The loaded-driver view returned unparsable output."
        states: dict[str, str] = {}
        for item in as_list(data):
            if isinstance(item, dict) and item.get("Name"):
                name = safe_str(item.get("Name")).lower()
                states[name] = safe_str(item.get("State"))
                self.cim_driver_names.add(name)
        return states, ""

    def scan(self) -> tuple[list[DriverInfo], CheckStatus]:
        """Read driver services; hash and inspect their files within the scan limits."""
        label = CHECK_LABELS["drivers"]
        lister = getattr(self.registry, "list_subkeys", None) if self.registry is not None else None
        if self.registry is None or lister is None:
            return [], CheckStatus("drivers", label, SKIPPED,
                                   "Registry service enumeration is not available on this platform.")
        try:
            names = lister("HKLM", SERVICES_KEY, "default")
        except PermissionError:
            return [], CheckStatus("drivers", label, FAILED, "Access to the Services registry key was denied.")
        except (FileNotFoundError, OSError) as exc:
            return [], CheckStatus("drivers", label, FAILED, f"The Services registry key could not be read: {safe_str(exc)}")
        states, state_note = self._loaded_states()
        drivers: list[DriverInfo] = []
        unreadable = 0
        stopped = ""
        root_norm = norm_path(self.config.system_root)
        for name in names[: self.config.max_driver_keys]:
            self.registry_service_names.add(name.lower())
        for name in names[: self.config.max_driver_keys]:
            if self.deadline.expired():
                stopped = "scan time limit reached"
                break
            try:
                raw_values = self.registry.read_values("HKLM", f"{SERVICES_KEY}\\{name}", "default")
            except (FileNotFoundError, PermissionError, OSError):
                unreadable += 1
                continue
            values = {n.lower(): v for n, v, _t in raw_values}
            service_type = to_int(values.get("type"))
            if service_type not in DRIVER_SERVICE_TYPES:
                continue
            start = to_int(values.get("start"))
            image = safe_str(values.get("imagepath")) if isinstance(values.get("imagepath"), str) else ""
            path = normalize_kernel_path(image or f"System32\\drivers\\{name}.sys", self.config.system_root, self.env)
            driver = DriverInfo(
                name=safe_str(name),
                display_name=safe_str(values.get("displayname")) if isinstance(values.get("displayname"), str) else "",
                image_path=safe_str(image), path=safe_str(path) if path else None, service_type=service_type,
                start=start, start_label=START_LABELS.get(start, "unknown") if start is not None else "unknown",
                state=states.get(name.lower()),
            )
            if path:
                normalised = norm_path(path)
                driver.standard_location = bool(normalised.startswith(root_norm + "\\")
                                                or TRUSTED_INSTALL_RE.match(normalised))
                try:
                    driver.exists = bool(self.path_exists(path))
                except (OSError, ValueError):
                    driver.exists = None
                if driver.exists and start != 4 and self.config.hash_files:
                    info = self.analyzer.analyze(path, source="driver", hash_enabled=True,
                                                 inspect=self.config.inspect_content)
                    driver.sha256 = info.sha256
                    driver.embedded_signature = info.embedded_signature
            drivers.append(driver)
        running = sum(1 for d in drivers if (d.state or "").lower() == "running")
        detail = f"{len(drivers)} driver services examined from {len(names)} service keys; {running} reported running"
        status = COMPLETED
        if state_note:
            status = PARTIAL
            detail += f"; loaded-state view unavailable: {state_note}"
        if unreadable:
            status = PARTIAL
            detail += f"; {unreadable} keys unreadable"
        if stopped:
            status = PARTIAL
            detail += f"; stopped early: {stopped}"
        return drivers, CheckStatus("drivers", label, status, detail, len(drivers))


_PER_USER_SUFFIX_RE = re.compile(r"^(.*)_[0-9a-f]{4,8}$")


def find_service_view_mismatches(scm_names: set[str], registry_names: set[str],
                                 cim_driver_names: Optional[set[str]] = None) -> list[str]:
    """Names visible through the service manager (or Win32_SystemDriver) but absent from the registry.

    Per-user service instances (``Name_1a2b3``) are matched to their registry template. Returns [] unless
    both views are available, because a single view cannot be compared with anything.
    """
    if not scm_names or not registry_names:
        return []
    missing: list[str] = []
    for name in sorted(set(scm_names) | set(cim_driver_names or ())):
        lowered = name.lower()
        if lowered in registry_names:
            continue
        match = _PER_USER_SUFFIX_RE.match(lowered)
        if match and match.group(1) in registry_names:
            continue
        missing.append(safe_str(name))
    return missing[:50]


# (key, label, hive, subkey, value, values meaning "on", values meaning "off")
HARDENING_CHECKS: tuple[tuple[str, str, str, str, str, frozenset[int], frozenset[int]], ...] = (
    ("secure_boot", "Secure Boot", "HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
     "UEFISecureBootEnabled", frozenset({1}), frozenset({0})),
    ("hvci", "Memory integrity (HVCI)", "HKLM",
     r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
     "Enabled", frozenset({1}), frozenset({0})),
    ("lsa_ppl", "LSA protection (RunAsPPL)", "HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa",
     "RunAsPPL", frozenset({1, 2}), frozenset({0})),
    ("uac", "User Account Control (EnableLUA)", "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
     "EnableLUA", frozenset({1}), frozenset({0})),
    ("vuln_driver_blocklist", "Vulnerable driver blocklist", "HKLM", r"SYSTEM\CurrentControlSet\Control\CI\Config",
     "VulnerableDriverBlocklistEnable", frozenset({1}), frozenset({0})),
    ("defender_tamper", "Defender tamper protection", "HKLM", r"SOFTWARE\Microsoft\Windows Defender\Features",
     "TamperProtection", frozenset({5}), frozenset({4})),
)
POLICY_CHECKS: tuple[tuple[str, str, str, str, str], ...] = (
    ("defender_policy_antispyware", "Defender disabled by policy (DisableAntiSpyware)", "HKLM",
     r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
    ("defender_policy_realtime", "Defender real-time monitoring disabled by policy", "HKLM",
     r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
)
EXCLUSION_KEYS = (("Paths", "path"), ("Processes", "process"))
BOOT_OPTIONS = {"testsigning": "Test signing", "nointegritychecks": "Driver integrity checks disabled",
                "debug": "Kernel debugging"}


class SecuritySettingsScanner:
    """Reads security-relevant configuration (registry values and the boot configuration) without changing it."""

    def __init__(self, config: ShadowTraceConfig, registry: Optional[Any], commands: CommandRunner,
                 deadline: Deadline) -> None:
        self.config = config
        self.registry = registry
        self.commands = commands
        self.deadline = deadline

    def _read(self, hive: str, subkey: str, cache: dict[tuple[str, str], Any]) -> Any:
        key = (hive, subkey)
        if key not in cache:
            try:
                cache[key] = {n.lower(): v for n, v, _t in self.registry.read_values(hive, subkey, "default")}
            except FileNotFoundError:
                cache[key] = None
            except PermissionError:
                cache[key] = PermissionError
            except OSError:
                cache[key] = OSError
        return cache[key]

    def scan(self) -> tuple[list[SecuritySetting], CheckStatus]:
        """Collect hardening state, Defender policy/exclusions and boot-integrity options."""
        label = CHECK_LABELS["security_settings"]
        if self.registry is None:
            return [], CheckStatus("security_settings", label, SKIPPED,
                                   "The Windows registry (winreg) is not available on this platform.")
        settings: list[SecuritySetting] = []
        cache: dict[tuple[str, str], Any] = {}
        denied: list[str] = []
        for key, name, hive, subkey, value_name, good, bad in HARDENING_CHECKS:
            values = self._read(hive, subkey, cache)
            if values is PermissionError or values is OSError:
                denied.append(name)
                settings.append(SecuritySetting(key, name, "", "unavailable", "registry value could not be read",
                                                f"{hive}\\{subkey}"))
                continue
            if values is None:
                state, shown = "unknown", ""
            else:
                raw = values.get(value_name.lower())
                number = to_int(raw)
                shown = "" if raw is None else safe_str(raw)
                if raw is None:
                    state = "not-configured"
                elif number in good:
                    state = "enabled"
                elif number in bad:
                    state = "disabled"
                else:
                    state = "unknown"
            settings.append(SecuritySetting(key, name, shown, state, source=f"{hive}\\{subkey}\\{value_name}"))
        for key, name, hive, subkey, value_name in POLICY_CHECKS:
            values = self._read(hive, subkey, cache)
            if values is PermissionError or values is OSError or values is None:
                continue
            raw = values.get(value_name.lower())
            if raw is not None:
                settings.append(SecuritySetting(
                    key, name, safe_str(raw), "policy-disabled" if to_int(raw) == 1 else "not-configured",
                    source=f"{hive}\\{subkey}\\{value_name}"))
        for leaf, kind in EXCLUSION_KEYS:
            subkey = rf"SOFTWARE\Microsoft\Windows Defender\Exclusions\{leaf}"
            try:
                rows = self.registry.read_values("HKLM", subkey, "default")
            except FileNotFoundError:
                continue
            except (PermissionError, OSError):
                denied.append(f"Defender {kind} exclusions")
                continue
            for entry_name, _value, _t in rows[:200]:
                settings.append(SecuritySetting(f"defender_exclusion_{kind}", f"Defender {kind} exclusion",
                                                safe_str(entry_name), "exclusion", source=f"HKLM\\{subkey}"))
        boot_note = ""
        outcome = self.commands.run("bcdedit_current", self.deadline)
        problem = outcome_problem(outcome, "The boot-configuration query")
        if problem:
            boot_note = problem[1]
        else:
            for line in outcome.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0].lower() in BOOT_OPTIONS:
                    option = parts[0].lower()
                    settings.append(SecuritySetting(
                        option, BOOT_OPTIONS[option], safe_str(parts[1]),
                        "enabled" if parts[1].strip().lower() == "yes" else "disabled",
                        source="bcdedit /enum {current}"))
        detail = f"{len(settings)} observations recorded"
        status = COMPLETED
        if denied:
            status = PARTIAL
            detail += f"; not readable without more rights: {', '.join(sorted(set(denied)))}"
        if boot_note:
            status = PARTIAL
            detail += f"; boot options unavailable: {boot_note}"
        return settings, CheckStatus("security_settings", label, status, detail, len(settings))


# --------------------------------------------------------------------------- #
# Detection engine
# --------------------------------------------------------------------------- #
class DetectionEngine:
    """Applies the documented rules to collected data and de-duplicates findings."""

    def __init__(self, config: ShadowTraceConfig) -> None:
        self.config = config
        self.intel: Optional[ThreatIntel] = None
        self._findings: dict[tuple[str, str], Finding] = {}

    # -- public API -------------------------------------------------------- #
    def run(
        self,
        processes: list[ProcessInfo],
        startup_entries: list[StartupEntry],
        files: list[FileInfo],
        telemetry: Optional[list[TelemetryResult]] = None,
        *,
        drivers: Optional[list[DriverInfo]] = None,
        settings: Optional[list[SecuritySetting]] = None,
        events: Optional[list[EventEvidence]] = None,
        detections: Optional[list[ThreatDetection]] = None,
        view_mismatches: Optional[list[str]] = None,
        intel: Optional[ThreatIntel] = None,
    ) -> list[Finding]:
        """Evaluate every rule and return findings sorted by severity with IDs assigned."""
        self._findings = {}
        self.intel = intel
        self._process_rules(processes)
        self._persistence_rules(startup_entries)
        self._file_rules(files)
        self._hash_rules(processes, startup_entries, files, drivers or [])
        self._driver_rules(drivers or [])
        self._settings_rules(settings or [])
        self._view_rules(view_mismatches or [])
        self._event_rules(events or [])
        self._detection_rules(detections or [])
        self._telemetry_rules(telemetry or [])
        ordered = sorted(
            self._findings.values(),
            key=lambda f: (-int(f.severity), -int(f.confidence), f.rule_id, f.subject),
        )
        for index, finding in enumerate(ordered, start=1):
            finding.finding_id = f"SHT-{index:04d}"
        return ordered

    # -- helpers ------------------------------------------------------------ #
    _DEFAULT_CHECK = {"P": "process_inventory", "F": "file_analysis", "M": "file_analysis", "T": "telemetry_defender",
                      "A": "defender_detections", "E": "event_logs", "R": "security_settings"}
    _ARTIFACT_PREFIXES = ("Executable: ", "File: ", "Location: ", "Driver file: ", "Target: ", "Resource: ")

    def _emit(
        self,
        rule_id: str,
        subject: str,
        evidence: list[str],
        key: str,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        check: str = "",
        artifacts: Optional[list[str]] = None,
    ) -> None:
        spec = RULES[rule_id]
        subject = safe_str(subject)
        dedupe_key = (rule_id, key)
        existing = self._findings.get(dedupe_key)
        if existing is not None:
            if subject != existing.subject and subject not in existing.related_subjects:
                existing.related_subjects.append(subject)
            return
        level = severity if severity is not None else spec.severity
        lines = [safe_str(line)[:600] for line in evidence]
        if artifacts is None:
            artifacts = [line[len(prefix):] for line in lines for prefix in self._ARTIFACT_PREFIXES
                         if line.startswith(prefix)]
        # Evidence is built from fields that were already redacted at collection time (command lines) or
        # are not secret (paths, hashes), so only normalise and bound it here.
        self._findings[dedupe_key] = Finding(
            rule_id=rule_id,
            category=spec.category,
            title=spec.title,
            severity=level,
            confidence=confidence if confidence is not None else spec.confidence,
            confidence_note=spec.confidence_note,
            subject=subject,
            evidence=lines,
            explanation=spec.explanation,
            recommendation=spec.recommendation,
            limitations=spec.limitations,
            evidence_key=key,
            detection_method=spec.method,
            status="informational" if level == Severity.INFO else spec.status,
            artifacts=[safe_str(a) for a in artifacts][:6],
            source_check=check or self._DEFAULT_CHECK.get(rule_id[3], ""),
        )

    def _expected_dirs(self, name: str) -> set[str]:
        root = self.config.system_root
        return {norm_path(ntpath.join(root, sub)) for sub in SYSTEM_PROCESS_EXPECTED.get(name, ())}

    @staticmethod
    def _proc_label(proc: ProcessInfo) -> str:
        return f"{proc.name or '?'} (PID {proc.pid})"

    @staticmethod
    def _proc_evidence(proc: ProcessInfo) -> list[str]:
        lines = [f"Process: {proc.name} (PID {proc.pid}, parent PID {proc.ppid})"]
        if proc.exe:
            lines.append(f"Executable: {proc.exe}")
        if proc.cmdline:
            lines.append(f"Command line: {proc.cmdline}")
        if proc.sha256:
            lines.append(f"SHA-256: {proc.sha256}")
        return lines

    # -- process rules ------------------------------------------------------ #
    def _process_rules(self, processes: list[ProcessInfo]) -> None:
        by_pid = {p.pid: p for p in processes}
        instances: Counter[str] = Counter()
        instance_samples: dict[str, ProcessInfo] = {}

        for proc in processes:
            name = proc.name.lower()
            exe = proc.exe
            normalised = norm_path(exe) if exe else ""
            label = self._proc_label(proc)
            evidence = self._proc_evidence(proc)

            if exe:
                rule = match_location(exe)
                if rule:
                    self._emit("ST-P001", label,
                               evidence + [f"Matched location rule: {rule.label} - {rule.why}"],
                               f"loc::{normalised}", rule.process_severity)
                if proc.exe_exists is False:
                    self._emit("ST-P002", label,
                               evidence + ["The executable path no longer exists on disk."],
                               f"missing::{normalised}")
                if name in SYSTEM_PROCESS_EXPECTED:
                    folder = norm_path(ntpath.dirname(exe.replace("/", "\\")))
                    expected = self._expected_dirs(name)
                    if folder not in expected:
                        self._emit(
                            "ST-P003", label,
                            evidence + ["Expected folder(s): " + ", ".join(sorted(expected))],
                            f"masq::{normalised}",
                        )
                if name not in MULTI_INSTANCE_OK:
                    instances[normalised] += 1
                    instance_samples.setdefault(normalised, proc)
                if not TRUSTED_INSTALL_RE.match(normalised):
                    reason = looks_randomized(ntpath.splitext(proc.name)[0])
                    if reason:
                        self._emit("ST-P005", label, evidence + [f"Name heuristic: {reason}"],
                                   f"randname::{normalised}")
            elif proc.name and looks_randomized(ntpath.splitext(proc.name)[0]) == "long hexadecimal-only name":
                self._emit("ST-P005", label, evidence + ["Name heuristic: long hexadecimal-only name"],
                           f"randname::{name}")

            if proc.name and DOUBLE_EXT_RE.search(proc.name):
                self._emit("ST-P004", label, evidence + ["Name imitates a document/media file."],
                           f"dblext::{normalised or name}")

            parent = by_pid.get(proc.ppid) if proc.ppid is not None else None
            parent_valid = (
                parent is not None and parent.start_ts is not None and proc.start_ts is not None
                and parent.start_ts <= proc.start_ts + 1.0
            )
            expected_parents = EXPECTED_PARENTS.get(name)
            if expected_parents and parent_valid and parent is not None and parent.name.lower() not in expected_parents:
                self._emit(
                    "ST-P006", label,
                    evidence + [f"Actual parent: {parent.name} (PID {parent.pid})",
                                "Expected parent: " + ", ".join(sorted(expected_parents))],
                    f"parent::{normalised or name}::{parent.name.lower()}",
                )
            if name in SCRIPT_HOSTS and parent_valid and parent is not None and parent.name.lower() in OFFICE_APPS:
                self._emit(
                    "ST-P007", label,
                    evidence + [f"Parent: {parent.name} (PID {parent.pid})"],
                    f"officespawn::{parent.name.lower()}::{name}",
                )
            if name in ("powershell.exe", "pwsh.exe") and proc.cmdline:
                encoded = bool(ENCODED_CMD_RE.search(proc.cmdline))
                hidden = bool(HIDDEN_WINDOW_RE.search(proc.cmdline))
                if encoded or hidden:
                    details = []
                    if encoded:
                        details.append("encoded-command argument present")
                    if hidden:
                        details.append("hidden-window argument present")
                    severity = Severity.HIGH if (encoded and hidden) else (
                        Severity.MEDIUM if encoded else Severity.LOW)
                    self._emit("ST-P008", label, evidence + ["Flags: " + "; ".join(details)],
                               f"psflags::{normalised or name}::{int(encoded)}{int(hidden)}", severity)
            if name in LOLBINS and proc.cmdline:
                pattern_hits = [h for h in scan_patterns(proc.cmdline, "cmd")
                                if h.pid not in ("encoded_command", "hidden_window")]
                classified = classify_pattern_hits(pattern_hits)
                if classified:
                    self._emit("ST-P010", label, evidence + ["Patterns: " + describe_hits(pattern_hits)],
                               f"cmdpat::{normalised or name}::{','.join(h.pid for h in pattern_hits)}",
                               classified[0], classified[1])

        for key, count in instances.items():
            if key and count >= self.config.instance_threshold:
                sample = instance_samples[key]
                self._emit(
                    "ST-P009", self._proc_label(sample),
                    [f"Executable: {sample.exe}", f"Simultaneous instances: {count} "
                     f"(threshold {self.config.instance_threshold})"],
                    f"instances::{key}",
                )

    # -- persistence rules -------------------------------------------------- #
    _CHECK_FOR_KIND = {"autorun": "registry_autoruns", "winlogon": "registry_autoruns",
                       "startup_folder": "startup_folders", "service": "services",
                       "scheduled_task": "scheduled_tasks", "wmi": "wmi_persistence",
                       "registry_config": "registry_config"}

    def _winlogon_deviates(self, entry: StartupEntry) -> bool:
        value = entry.command.strip()
        if entry.name.lower() == "shell":
            return value.lower() != "explorer.exe"
        parts = [p.strip().strip('"') for p in value.split(",") if p.strip()]
        expected = norm_path(ntpath.join(self.config.system_root, "system32", "userinit.exe"))
        return not (len(parts) == 1 and norm_path(parts[0]) == expected)

    def _is_system_task(self, entry: StartupEntry) -> bool:
        """Microsoft-provided tasks whose action lives under the Windows folder (not flagged for launcher use)."""
        if entry.kind != "scheduled_task":
            return False
        task_path = safe_str(entry.attributes.get("task_path")).lower()
        target = entry.target_path or ""
        return task_path.startswith("\\microsoft\\") and (
            not target or norm_path(target).startswith(norm_path(self.config.system_root) + "\\"))

    @staticmethod
    def _command_hits(entry: StartupEntry) -> list[CommandPattern]:
        hits = scan_patterns(entry.command, "cmd")
        if entry.kind == "wmi" and "script" in entry.command.lower():
            known = {h.pid for h in hits}
            hits += [h for h in scan_patterns(entry.command, "script") if h.pid not in known]
        return hits

    def _registry_config_finding(self, entry: StartupEntry, siblings: dict[tuple[str, str], StartupEntry],
                                 label: str, evidence: list[str]) -> None:
        name = entry.name.lower()
        severity = Severity.MEDIUM
        note = ""
        if name == "loadappinit_dlls":
            return
        if name == "appinit_dlls":
            load = siblings.get((entry.location.lower(), "loadappinit_dlls"))
            enabled = load is not None and to_int(load.command.strip()) == 1
            severity = Severity.HIGH if enabled else Severity.LOW
            note = ("LoadAppInit_DLLs is 1: the listed DLLs are loaded into processes" if enabled
                    else "LoadAppInit_DLLs is not 1, so the listed DLLs are not loaded")
        elif name == "bootexecute":
            if " ".join(entry.command.lower().split()) == "autocheck autochk *":
                return
            severity = Severity.HIGH
            note = "BootExecute differs from the Windows default 'autocheck autochk *'"
        self._emit("ST-S007", label, evidence + ([note] if note else []),
                   f"regconfig::{entry.location.lower()}::{name}", severity,
                   check="registry_config")

    def _persistence_rules(self, entries: list[StartupEntry]) -> None:
        siblings = {(e.location.lower(), e.name.lower()): e for e in entries if e.kind == "registry_config"}
        for entry in entries:
            check = self._CHECK_FOR_KIND.get(entry.kind, "registry_autoruns")
            label = f"{entry.name} ({entry.source}: {entry.location})"
            evidence = [f"Name: {entry.name}", f"Location: {entry.location}", f"Command: {entry.command}"]
            if entry.view:
                evidence.append(f"Registry view: {entry.view}")
            if entry.sha256:
                evidence.append(f"SHA-256 of target: {entry.sha256}")
            attrs = entry.attributes
            if attrs.get("triggers"):
                evidence.append("Triggers: " + "; ".join(safe_str(t) for t in attrs["triggers"]))
            if attrs.get("hidden"):
                evidence.append("Task is marked Hidden")
            if attrs.get("run_level"):
                evidence.append(f"Run level: {attrs['run_level']}")

            if entry.kind == "winlogon":
                if self._winlogon_deviates(entry):
                    default = "explorer.exe" if entry.name.lower() == "shell" else "<SystemRoot>\\system32\\userinit.exe,"
                    self._emit("ST-S005", label, evidence + [f"Windows default: {default}"],
                               f"winlogon::{entry.location.lower()}::{entry.name.lower()}", check=check)
                continue
            if entry.kind == "registry_config":
                self._registry_config_finding(entry, siblings, label, evidence)

            system_task = self._is_system_task(entry)
            target = entry.target_path
            low_trust = None
            if target:
                normalised = norm_path(target)
                if entry.target_exists is False:
                    self._emit("ST-S001", label, evidence + [f"Target does not exist: {target}"],
                               f"missing::{normalised}", check=check)
                low_trust = match_location(target)
                if low_trust and not (entry.kind == "startup_folder" and low_trust.key == "roaming"):
                    self._emit("ST-S002", label,
                               evidence + [f"Matched location rule: {low_trust.label} - {low_trust.why}"],
                               f"loc::{normalised}", low_trust.persistence_severity, check=check)
            lolbin = entry.kind != "startup_folder" and entry.program_name in LOLBINS and not system_task
            hits = [] if entry.kind == "startup_folder" else self._command_hits(entry)
            if lolbin:
                encoded = bool(ENCODED_CMD_RE.search(entry.command))
                hidden = bool(HIDDEN_WINDOW_RE.search(entry.command))
                severity = Severity.MEDIUM if (entry.program_name == "mshta.exe" or encoded or hidden) else Severity.LOW
                notes = [f"Launcher: {entry.program_name}"]
                if encoded:
                    notes.append("encoded-command argument present")
                if hidden:
                    notes.append("hidden-window argument present")
                self._emit("ST-S003", label, evidence + ["; ".join(notes)],
                           f"lolbin::{entry.kind}::{entry.location.lower()}::{entry.name.lower()}", severity, check=check)
            classified = classify_pattern_hits(hits) if not system_task else None
            if classified:
                self._emit("ST-S006", label, evidence + ["Patterns: " + describe_hits(hits)],
                           f"cmdpat::{entry.kind}::{entry.location.lower()}::{entry.name.lower()}",
                           classified[0], classified[1], check=check)
            if entry.kind == "startup_folder":
                ext = os.path.splitext(entry.name.lower())[1]
                if ext in RUNNABLE_EXTENSIONS:
                    self._emit("ST-S004", label,
                               evidence + [f"File type {ext} runs at every logon when placed here."],
                               f"startupfile::{norm_path(entry.command)}", check=check)
            if (entry.kind == "scheduled_task" and attrs.get("hidden") and not system_task
                    and (lolbin or low_trust or entry.target_exists is False or classified)):
                self._emit("ST-D001", label, evidence + ["Hidden task with an unusual action (see rule description)."],
                           f"hiddentask::{safe_str(attrs.get('task_path')).lower()}", check=check)
            if entry.kind == "wmi" and attrs.get("wmi_type") in WMI_EXECUTING_TYPES:
                escalated = bool(classified and classified[0] >= Severity.MEDIUM) or lolbin or bool(low_trust)
                filters = [safe_str(f) for f in attrs.get("filters", [])]
                self._emit("ST-W001", label,
                           evidence + [f"Consumer type: {attrs.get('wmi_type')}",
                                       "Bound filters: " + ("; ".join(filters) if filters else "none (unbound)")],
                           f"wmi::{entry.name.lower()}", Severity.HIGH if escalated else Severity.MEDIUM,
                           check=check)

    # -- file rules --------------------------------------------------------- #
    def _file_rules(self, files: list[FileInfo]) -> None:
        for info in files:
            if info.error:
                continue
            sources = info.sources or [info.source]
            normalised = norm_path(info.path)
            evidence = [f"File: {info.path}", f"Size: {info.size} bytes"]
            if info.sha256:
                evidence.append(f"SHA-256: {info.sha256}")
            if info.modified:
                evidence.append(f"Modified: {info.modified}")
            check = "file_sweep" if sources == ["sweep"] else "file_analysis"
            # A file's location alone is only reported for files the user selected or that sit in Startup folders.
            if any(s in ("user-path", "startup-folder") for s in sources):
                if info.extension in EXECUTABLE_EXTENSIONS and info.extension != ".lnk":
                    rule = match_location(info.path)
                    if rule and not ("startup-folder" in sources and rule.key == "roaming"):
                        self._emit("ST-F001", info.path,
                                   evidence + [f"Matched location rule: {rule.label} - {rule.why}"],
                                   f"loc::{normalised}", rule.process_severity, check=check)
            if info.is_pe and info.extension in DECEPTIVE_EXTENSIONS:
                self._emit("ST-F002", info.path,
                           evidence + [f"Starts with an executable header (MZ) but is named *{info.extension}"],
                           f"mzmismatch::{normalised}", check=check)
            if DOUBLE_EXT_RE.search(info.name):
                self._emit("ST-F003", info.path, evidence + ["Name imitates a document/media file."],
                           f"dblext::{normalised}", check=check)
            if info.script_patterns:
                hits = [p for p in COMMAND_PATTERNS if p.pid in info.script_patterns]
                classified = classify_pattern_hits(hits)
                if classified:
                    self._emit("ST-M001", info.path, evidence + ["Patterns: " + describe_hits(hits)],
                               f"scriptpat::{normalised}", classified[0], classified[1], check=check)
            if info.keyboard_apis and not TRUSTED_INSTALL_RE.match(normalised):
                persistent = any(s in ("startup-target", "service-binary", "task-target", "driver") for s in sources)
                severity = Severity.MEDIUM if (match_location(info.path) or persistent) else Severity.LOW
                self._emit("ST-M002", info.path,
                           evidence + ["API names found in the file: " + ", ".join(info.keyboard_apis),
                                       "Sources: " + ", ".join(sources)],
                           f"kbdapi::{normalised}", severity, check=check)

    # -- known-hash rules --------------------------------------------------- #
    def _hash_rules(self, processes: list[ProcessInfo], entries: list[StartupEntry], files: list[FileInfo],
                    drivers: list[DriverInfo]) -> None:
        seen: dict[str, list[str]] = {}

        def add(sha: Optional[str], where: Optional[str]) -> None:
            if sha and where:
                locations = seen.setdefault(sha.lower(), [])
                if where not in locations:
                    locations.append(where)

        for proc in processes:
            add(proc.sha256, proc.exe)
        for entry in entries:
            add(entry.sha256, entry.target_path)
        for info in files:
            add(info.sha256, info.path)
        for driver in drivers:
            add(driver.sha256, driver.path)
        for sha, locations in seen.items():
            test_label = KNOWN_TEST_HASHES.get(sha)
            if test_label:
                self._emit("ST-M004", locations[0], [f"File: {loc}" for loc in locations[:5]] + [
                    f"SHA-256: {sha}", f"Matches the built-in test indicator: {test_label}"],
                    f"testhash::{sha}", check="file_analysis")
            entry_match = self.intel.lookup(sha) if self.intel else None
            if entry_match:
                self._emit("ST-M003", locations[0], [f"File: {loc}" for loc in locations[:5]] + [
                    f"SHA-256: {sha}",
                    f"Matched your list '{entry_match.source}': {entry_match.label}"],
                    f"hashmatch::{sha}", check="file_analysis")

    # -- driver / rootkit rules ---------------------------------------------- #
    def _driver_rules(self, drivers: list[DriverInfo]) -> None:
        for driver in drivers:
            label = f"{driver.name} (driver)"
            evidence = [f"Driver: {driver.name} (start: {driver.start_label}, state: {driver.state or 'unknown'})",
                        f"Service key: HKLM\\{SERVICES_KEY}\\{driver.name}"]
            if driver.path:
                evidence.append(f"Driver file: {driver.path}")
            if driver.sha256:
                evidence.append(f"SHA-256: {driver.sha256}")
            if not driver.path:
                continue
            normalised = norm_path(driver.path)
            rule = match_location(driver.path)
            if rule:
                severity = Severity.MEDIUM if rule.key == "programdata" else Severity.HIGH
                self._emit("ST-R001", label, evidence + [f"Matched location rule: {rule.label} - {rule.why}"],
                           f"driverloc::{normalised}", severity, check="drivers")
            if driver.exists is False and driver.start in (0, 1, 2):
                self._emit("ST-R002", label, evidence + [f"File missing: {driver.path}"],
                           f"drivermissing::{normalised}", check="drivers")
            if driver.exists and driver.standard_location is False and driver.embedded_signature is False:
                self._emit("ST-R003", label, evidence + ["PE header declares no embedded certificate table"],
                           f"driversig::{normalised}", check="drivers")

    def _view_rules(self, mismatches: list[str]) -> None:
        if mismatches:
            self._emit("ST-R004", "Service/driver view mismatch",
                       [f"Visible to the service manager but absent from the registry: {name}" for name in mismatches[:20]]
                       + ([f"... and {len(mismatches) - 20} more"] if len(mismatches) > 20 else []),
                       "viewmismatch::" + ",".join(sorted(n.lower() for n in mismatches[:50])), check="drivers")

    # -- security-setting rules ----------------------------------------------- #
    @staticmethod
    def _is_broad_exclusion(value: str) -> bool:
        normalised = norm_path(value).rstrip("\\")
        return (len(normalised) <= 2 or normalised.endswith("\\users")
                or bool(re.fullmatch(r"[a-z]:\\users\\[^\\]+", normalised)))

    def _settings_rules(self, settings: list[SecuritySetting]) -> None:
        for item in settings:
            evidence = [f"Setting: {item.label}", f"Value: {item.value or '(none)'}", f"State: {item.state}",
                        f"Location: {item.source}"]
            if item.key in ("testsigning", "nointegritychecks") and item.state == "enabled":
                self._emit("ST-R005", item.label, evidence, f"boot::{item.key}", check="security_settings")
            elif item.state == "policy-disabled":
                self._emit("ST-R006", item.label, evidence, f"policy::{item.key}", check="security_settings")
            elif item.state == "exclusion":
                value = item.value
                is_process = item.key.endswith("process")
                risky = (norm_path(value).split("\\")[-1] in SCRIPT_HOSTS if is_process
                         else bool(match_location(value + "\\x") or self._is_broad_exclusion(value)))  # trailing name: rules match files
                if risky:
                    self._emit("ST-R007", item.label, evidence, f"exclusion::{item.key}::{norm_path(value)}",
                               check="security_settings")
            elif item.key in ("secure_boot", "hvci", "lsa_ppl", "vuln_driver_blocklist", "defender_tamper", "uac") \
                    and item.state in ("disabled", "not-configured"):
                self._emit("ST-R008", item.label, evidence, f"hardening::{item.key}", check="security_settings")

    # -- event-log and Defender rules ------------------------------------------ #
    def _event_rules(self, events: list[EventEvidence]) -> None:
        grouped: dict[tuple[str, ...], list[EventEvidence]] = {}
        for event in events:
            grouped.setdefault(tuple(sorted(event.patterns)), []).append(event)
        for patterns, items in grouped.items():
            hits = [p for p in COMMAND_PATTERNS if p.pid in patterns]
            classified = classify_pattern_hits(hits)
            if not classified:
                continue
            severity = min(classified[0], Severity.MEDIUM)  # historical evidence is never rated above MEDIUM
            newest = max(items, key=lambda e: e.time)
            self._emit("ST-E001", f"{len(items)} PowerShell script-block event(s)",
                       [f"Log: {newest.log} (event {newest.event_id})", f"Most recent: {newest.time}",
                        f"Events matching: {len(items)}", "Patterns: " + describe_hits(hits),
                        f"Excerpt (redacted): {newest.excerpt}"],
                       "event::" + ",".join(patterns), severity, Confidence.LOW, check="event_logs")

    def _detection_rules(self, detections: list[ThreatDetection]) -> None:
        for det in detections[:25]:
            severity = Severity.CRITICAL if det.active else Severity.HIGH
            evidence = [f"Threat: {det.name} (ID {det.threat_id})", f"Detected: {det.time or 'unknown'}",
                        f"Defender reported the action as successful: {det.action_success}"]
            evidence += [f"Resource: {r}" for r in det.resources]
            if det.process_name:
                evidence.append(f"Process: {det.process_name}")
            self._emit("ST-A001", det.name, evidence, f"defender::{det.threat_id}::{'|'.join(det.resources)}",
                       severity, check="defender_detections")

    # -- telemetry rules ---------------------------------------------------- #
    def _telemetry_rules(self, telemetry: list[TelemetryResult]) -> None:
        for item in telemetry:
            if item.source == "defender" and item.checked:
                if item.details.get("RealTimeProtectionEnabled") is False:
                    self._emit("ST-T001", "Microsoft Defender",
                               [f"{k}: {v}" for k, v in item.details.items()], "defender::realtime-off")
                age = item.details.get("AntivirusSignatureAge")
                if (item.details.get("AMServiceEnabled") is False or item.details.get("AntivirusEnabled") is False
                        or (isinstance(age, int) and age > 14)):
                    self._emit("ST-T002", "Microsoft Defender",
                               [f"{k}: {v}" for k, v in item.details.items()], "defender::status")


# --------------------------------------------------------------------------- #
# Risk scoring
# --------------------------------------------------------------------------- #
SCORE_DISCLAIMER = (
    "This is a heuristic indicator of how many and how strong the observed leads are. It is not the probability "
    "that the computer is infected and not a verified malware verdict."
)


class RiskScorer:
    """Documented, evidence-de-duplicating heuristic risk score.

    Method: each finding is worth ``severity points x confidence multiplier``.
    Findings that rest on the *same underlying evidence* (same evidence key, for
    example the same file path flagged by a process rule and a persistence rule)
    form one group and only the strongest counts. Groups are then sorted from
    strongest to weakest and summed with a diminishing factor so that many weak
    indicators cannot outweigh one strong indicator. The total is capped at 100.
    """

    def __init__(self, config: ShadowTraceConfig) -> None:
        self.config = config

    def finding_points(self, finding: Finding) -> float:
        """Points contributed by a single finding before de-duplication."""
        return (self.config.severity_points[finding.severity]
                * self.config.confidence_multiplier[finding.confidence])

    def band_for(self, total: int) -> str:
        """Map a numeric score to a named band."""
        if total <= 0:
            return "NONE"
        if total < self.config.band_moderate:
            return "LOW"
        if total < self.config.band_elevated:
            return "MODERATE"
        if total < self.config.band_high:
            return "ELEVATED"
        return "HIGH"

    def coverage_notes(self, checks: list[CheckStatus], processes: list[ProcessInfo],
                       elevated: Optional[bool], quick: bool) -> tuple[list[str], bool]:
        """Describe coverage gaps; returns ``(notes, insufficient_evidence)``."""
        notes: list[str] = []
        insufficient = False
        for check in checks:
            if check.status in (SKIPPED, FAILED, PARTIAL):
                notes.append(f"{check.label}: {check.status} - {check.detail}")
            if check.name in ("process_inventory", "registry_autoruns") and check.status in (SKIPPED, FAILED):
                insufficient = True
        if elevated is False:
            notes.append("Not run as administrator: some processes, services and registry keys could not be read.")
        elif elevated is None:
            notes.append("Administrator status could not be determined.")
        if processes:
            unreadable = sum(1 for p in processes if not p.exe)
            if unreadable / len(processes) > 0.5:
                insufficient = True
                notes.append(f"{unreadable} of {len(processes)} processes had no readable executable path.")
        if quick:
            notes.append("Quick mode: hashing, service inspection and optional telemetry were skipped.")
        if is_wow64_python():
            notes.append("32-bit Python on 64-bit Windows: file-system redirection can make System32 files "
                         "appear missing. Use 64-bit Python for reliable results.")
        return notes, insufficient

    def score(self, findings: list[Finding], checks: list[CheckStatus], processes: list[ProcessInfo],
              elevated: Optional[bool]) -> ScoreResult:
        """Compute the overall score and mark which findings count towards it."""
        grouped: dict[str, list[Finding]] = {}
        for finding in findings:
            grouped.setdefault(finding.evidence_key or finding.finding_id, []).append(finding)
        groups: list[ScoreGroup] = []
        for key, members in grouped.items():
            members_sorted = sorted(members, key=lambda f: -self.finding_points(f))
            counted = members_sorted[0]
            for other in members_sorted[1:]:
                other.counted_in_score = False
                other.shares_evidence_with = [counted.finding_id]
            groups.append(ScoreGroup(key, self.finding_points(counted),
                                     [f.finding_id for f in members_sorted], counted.finding_id))
        groups.sort(key=lambda g: -g.points)
        raw = sum(g.points * (self.config.diminishing_factor ** i) for i, g in enumerate(groups))
        total = int(min(100, round(raw)))
        band = self.band_for(total)
        notes, insufficient = self.coverage_notes(checks, processes, elevated, self.config.quick)
        interpretation = {
            "NONE": "No heuristic indicators were produced by the checks that completed.",
            "LOW": "A few weak indicators were found. These are most often benign; review them when convenient.",
            "MODERATE": "Some indicators deserve a manual review. They are leads, not conclusions.",
            "ELEVATED": "Several or stronger indicators were found. Review the findings promptly and verify each item.",
            "HIGH": "Strong or numerous indicators were found. Investigate carefully, and consider an offline scan "
                    "with trusted security software.",
        }[band]
        if insufficient:
            interpretation += " Evidence is insufficient: key checks could not run or most processes were unreadable."
        method = (
            "Points = severity (INFO 0, LOW 4, MEDIUM 15, HIGH 35, CRITICAL 60) x confidence multiplier "
            "(LOW 0.5, MEDIUM 0.8, HIGH 1.0). Findings sharing the same evidence count once (strongest wins). "
            f"Groups are summed strongest-first with each additional group weighted x{self.config.diminishing_factor}. "
            "Capped at 100. Bands: 0 none, 1-14 low, 15-34 moderate, 35-59 elevated, 60+ high."
        )
        return ScoreResult(total, band, interpretation, groups, insufficient, notes, method, SCORE_DISCLAIMER)

    @staticmethod
    def conclusion(score: ScoreResult, findings: list[Finding]) -> str:
        """Plain-language conclusion that never overstates the evidence."""
        counts = Counter(f.severity.name for f in findings)
        listed = ", ".join(f"{counts[s.name]} {s.name}" for s in sorted(Severity, reverse=True) if counts[s.name])
        if not findings:
            text = ("The checks that completed produced no heuristic findings. This does not prove the computer is "
                    "free of keyloggers or other malware: user-mode inspection cannot see kernel-level, fileless "
                    "or hardware threats.")
        else:
            confirmed = sum(1 for f in findings if f.status == "confirmed")
            text = (f"ShadowTrace produced {len(findings)} finding(s) ({listed}). Each is an investigation lead "
                    "based on observed evidence, not a confirmed infection. Verify each item before taking any "
                    "action, and prefer trusted security software for remediation.")
            if confirmed:
                text = (f"{confirmed} finding(s) are confirmed by a reliable source (a known-hash list you supplied or a "
                        "security product's own result) - treat those first. " + text)
        if score.insufficient_evidence:
            text += " Coverage was limited, so the result carries less weight; see the coverage notes."
        return text


# --------------------------------------------------------------------------- #
# Report generation
# --------------------------------------------------------------------------- #
class ReportError(Exception):
    """Raised when a report cannot be written; carries any files already written."""

    def __init__(self, message: str, written: Optional[list[Path]] = None) -> None:
        super().__init__(message)
        self.written = written or []


REPORT_SCHEMA_VERSION = "2.0"
REPORT_FORMATS: dict[str, tuple[str, ...]] = {
    "html": ("html",), "json": ("json",), "markdown": ("markdown",),
    "both": ("html", "json"), "all": ("html", "json", "markdown"),
}
REPORT_EXTENSIONS = {"html": ".html", "json": ".json", "markdown": ".md"}
REPORT_STEM_RE = re.compile(r"^ShadowTrace_Report_(\d{6})(?:_(\d+))?\.(html|json|md)$")
DATE_DIR_RE = re.compile(r"^(\d{2})-(\d{2})-(\d{4})$")
VIEW_PROMPT = "Scan complete. Would you like to view the report now? [Y/N]"


def resolve_reports_root(output: Path) -> Path:
    """The ``reports`` directory for an output location (an output that is already named 'reports' is used as is)."""
    text = str(output)
    if "\x00" in text:
        raise ReportError("The output path contains an invalid character.")
    out = Path(output).expanduser()
    if out.exists() and not out.is_dir():
        raise ReportError(f"The output location is a file, not a directory: {safe_str(out)}")
    return out if out.name.lower() == "reports" else out / "reports"


def scan_datetime(result: ScanResult) -> datetime:
    """Local date/time of the scan start (used for folder names and the MM/DD/YYYY display)."""
    if result.started_local:
        try:
            return datetime.fromisoformat(result.started_local)  # already local time, with its own UTC offset
        except ValueError:
            pass  # fall through to the UTC timestamp
    if result.started_at:
        try:
            parsed = datetime.fromisoformat(result.started_at)
            return parsed.astimezone() if parsed.tzinfo else parsed
        except ValueError:
            pass  # fall back to the current time below
    return datetime.now().astimezone()


def summarize_findings(findings: list[Finding]) -> dict[str, dict[str, int]]:
    """Counts by severity, status and category (every severity is listed, even at zero)."""
    return {
        "by_severity": {s.name: sum(1 for f in findings if f.severity == s) for s in sorted(Severity, reverse=True)},
        "by_status": {k: sum(1 for f in findings if f.status == k) for k in ("confirmed", "suspicious", "informational")},
        "by_category": dict(Counter(f.category for f in findings)),
    }


def merge_files(*groups: list[FileInfo]) -> list[FileInfo]:
    """Combine FileInfo lists, keeping the first record for each path and merging their sources."""
    merged: dict[str, FileInfo] = {}
    for group in groups:
        for info in group:
            key = os.path.normcase(info.path)
            existing = merged.get(key)
            if existing is None:
                merged[key] = info
            else:
                for source in (info.sources or [info.source]):
                    if source not in existing.sources:
                        existing.sources.append(source)
    return list(merged.values())


# --------------------------------------------------------------------------- #
# Redaction (best effort) and generic string transforms
# --------------------------------------------------------------------------- #
_GENERIC_NAMES = frozenset({"user", "users", "public", "default", "system", "administrator", "root", "local",
                            "windows", "owner", "admin", "guest"})
_PROFILE_RE = re.compile(r"(?i)(\\users\\)(?!(?:public|default|default user|all users)(?:\\|$))([^\\/\s\"'<>|]+)")


class Redactor:
    """Masks the current user's and computer's names and Windows profile folder names (best effort only)."""

    def __init__(self, extra_names: tuple[str, ...] = ()) -> None:
        users: set[str] = set()
        machines: set[str] = set()
        try:
            users.add(getpass.getuser())
        except (OSError, KeyError, ImportError):
            pass  # no resolvable user name on this system
        for var in ("USERNAME", "USER"):
            users.add(os.environ.get(var, ""))
        users.add(os.path.basename(os.path.expanduser("~")))
        users.update(extra_names)
        machines.update({os.environ.get("COMPUTERNAME", ""), os.environ.get("HOSTNAME", ""), os.environ.get("USERDOMAIN", "")})
        if hasattr(os, "uname"):
            machines.add(os.uname().nodename)
        self._patterns: list[tuple["re.Pattern[str]", str]] = []
        for names, token in ((users, "[redacted-user]"), (machines, "[redacted-computer]")):
            for name in sorted({n for n in names if n and len(n) >= 3 and n.lower() not in _GENERIC_NAMES},
                               key=len, reverse=True):
                self._patterns.append((re.compile(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])",
                                                  re.IGNORECASE), token))

    def __call__(self, text: str) -> str:
        text = _PROFILE_RE.sub(lambda m: m.group(1) + "[redacted-user]", text)
        for pattern, token in self._patterns:
            text = pattern.sub(token, text)
        return text


def transform_strings(value: Any, func: Callable[[str], str]) -> Any:
    """Return a copy of ``value`` with ``func`` applied to every string (dataclasses, lists, dicts, tuples)."""
    if isinstance(value, str):
        return func(value)
    if is_dataclass(value) and not isinstance(value, type):
        return dc_replace(value, **{f.name: transform_strings(getattr(value, f.name), func)
                                    for f in fields(value) if f.init})
    if isinstance(value, list):
        return [transform_strings(v, func) for v in value]
    if isinstance(value, tuple):
        return tuple(transform_strings(v, func) for v in value)
    if isinstance(value, dict):
        return {k: transform_strings(v, func) for k, v in value.items()}
    return value


# --------------------------------------------------------------------------- #
# Report history, post-scan prompt and browser opening (opening only ever happens on an explicit Yes / command)
# --------------------------------------------------------------------------- #
@dataclass
class ReportEntry:
    """One saved scan (all formats that share a file stem)."""

    day: datetime
    time_text: str
    mode: str
    paths: dict[str, Path]

    @property
    def html(self) -> Optional[Path]:
        """The HTML report of this scan, if one was saved."""
        return self.paths.get("html")

    @property
    def date_text(self) -> str:
        """Date as MM/DD/YYYY."""
        return self.day.strftime("%m/%d/%Y")


def list_report_history(output: Path, limit: Optional[int] = None) -> list[ReportEntry]:
    """Saved reports grouped by scan, newest first. Unreadable folders and unknown files are ignored."""
    try:
        root = resolve_reports_root(output)
    except ReportError:
        return []
    groups: dict[tuple[datetime, str, int], dict[str, Path]] = {}
    try:
        day_dirs = [e for e in os.scandir(root) if e.is_dir(follow_symlinks=False)]
    except OSError:
        return []
    for day_dir in day_dirs:
        match = DATE_DIR_RE.match(day_dir.name)
        if not match:
            continue
        try:
            day = datetime.strptime(day_dir.name, "%m-%d-%Y")
            files = list(os.scandir(day_dir.path))
        except (ValueError, OSError):
            continue
        for item in files:
            found = REPORT_STEM_RE.match(item.name)
            if not found or not item.is_file(follow_symlinks=False):
                continue
            hhmmss, suffix, ext = found.group(1), int(found.group(2) or 1), found.group(3)
            groups.setdefault((day, hhmmss, suffix), {})["markdown" if ext == "md" else ext] = Path(item.path)
    entries: list[ReportEntry] = []
    for (day, hhmmss, _suffix), paths in sorted(groups.items(), reverse=True):
        mode = "unknown"
        json_path = paths.get("json")
        if json_path is not None:
            try:
                if json_path.stat().st_size <= 30 * 1024 * 1024:
                    with open(json_path, "r", encoding="utf-8") as handle:
                        mode = safe_str(json.load(handle).get("scan", {}).get("mode", "unknown"))
            except (OSError, ValueError, AttributeError):
                mode = "unknown"
        entries.append(ReportEntry(day, f"{hhmmss[:2]}:{hhmmss[2:4]}:{hhmmss[4:6]}", mode, paths))
        if limit is not None and len(entries) >= limit:
            break
    return entries


def open_report_in_browser(path: Path, opener: Optional[Callable[[str], bool]] = None) -> tuple[bool, str]:
    """Open a saved HTML report in the default browser. Returns ``(ok, reason_if_not)``. Sends no data anywhere."""
    opener = opener or webbrowser.open  # looked up at call time so tests can substitute it
    try:
        resolved = Path(path).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        return False, safe_str(exc)
    if resolved.suffix.lower() not in (".html", ".htm"):
        return False, "only .html reports can be opened"
    if not resolved.is_file():
        return False, "the report file was not found"
    try:
        launched = opener(resolved.as_uri())
    except (webbrowser.Error, OSError) as exc:
        return False, safe_str(exc)
    return (True, "") if launched else (False, "no web browser could be launched")


def is_interactive() -> bool:
    """True when both stdin and stdout are terminals (so a question can be asked without hanging)."""
    try:
        return bool(sys.stdin is not None and sys.stdin.isatty() and sys.stdout.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def ask_yes_no(question: str, input_fn: Callable[[str], str] = input, print_fn: Callable[[str], Any] = print,
               attempts: int = 5) -> Optional[bool]:
    """Ask a Y/N question. Returns True/False, or None on EOF, Ctrl+C or too many invalid answers."""
    for _ in range(attempts):
        try:
            answer = input_fn(question + " ")
        except EOFError:
            return None
        except KeyboardInterrupt:
            print_fn("")
            return None
        value = answer.strip().lower()
        if value in ("y", "yes"):
            return True
        if value in ("n", "no"):
            return False
        print_fn("Please answer Y or N (yes or no).")
    return None


def offer_to_view_report(html_path: Optional[Path], *, no_prompt: bool = False, interactive: Optional[bool] = None,
                         input_fn: Callable[[str], str] = input, print_fn: Callable[[str], Any] = print,
                         opener: Optional[Callable[[str], bool]] = None) -> str:
    """Ask whether to open the (already saved) HTML report, and open it only after a Yes.

    Returns an outcome code: no-html, no-prompt, non-interactive, opened, open-failed, declined or no-answer.
    """
    if html_path is None:
        print_fn("No HTML report was generated in this run (use --format both or --format html to get one).")
        return "no-html"
    if no_prompt:
        print_fn("Report saved (prompt skipped). Open it later with: python shadowtrace.py reports --open 1")
        return "no-prompt"
    if not (is_interactive() if interactive is None else interactive):
        print_fn("Non-interactive session: not asking to open the report. It is saved at the path above; "
                 "open that .html file in your browser, or run: python shadowtrace.py reports --open 1")
        return "non-interactive"
    answer = ask_yes_no(VIEW_PROMPT, input_fn, print_fn)
    if answer is None:
        print_fn("No answer received; the report stays saved at the path above.")
        return "no-answer"
    if not answer:
        print_fn("OK. The report stays saved; open it any time from the path above.")
        return "declined"
    ok, reason = open_report_in_browser(html_path, opener)
    if ok:
        print_fn("Opening the report in your default browser (nothing is sent anywhere).")
        return "opened"
    print_fn(f"Could not open the report automatically ({reason}).")
    print_fn(f"Open it manually: {html_path}")
    print_fn("Paste that path into your browser's address bar, or double-click the file in File Explorer.")
    return "open-failed"


_HTML_CSS = """
:root{--bg:#f6f7f9;--fg:#1d2330;--muted:#5b6475;--card:#fff;--line:#d9dde5;--accent:#1f5fbf;
--crit:#8b0000;--high:#c62828;--med:#b26a00;--low:#1565c0;--info:#5b6475;--ok:#1b7f3b}
@media (prefers-color-scheme:dark){:root{--bg:#12151c;--fg:#e6e9f0;--muted:#9aa4b8;--card:#1a1f2b;--line:#2b3244;
--accent:#6aa3ff;--crit:#ff6b6b;--high:#ff8a80;--med:#ffb74d;--low:#64b5f6;--info:#9aa4b8;--ok:#66d17f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 18px 60px}h1{margin:.2em 0}h2{margin-top:2em;border-bottom:2px solid var(--line);padding-bottom:.2em}
.meta{color:var(--muted)}.notice{border:1px solid var(--line);border-left:5px solid var(--accent);background:var(--card);padding:10px 14px;margin:14px 0;border-radius:6px}
.warn{border-left-color:var(--med)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.card b{font-size:1.7em;display:block}
table{width:100%;border-collapse:collapse;background:var(--card);margin:8px 0}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:rgba(127,127,127,.12)}code{font:12.5px/1.4 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:700;border:1px solid currentColor;margin-right:6px}
.sev-CRITICAL{color:var(--crit)}.sev-HIGH{color:var(--high)}.sev-MEDIUM{color:var(--med)}.sev-LOW{color:var(--low)}.sev-INFO{color:var(--info)}
.st-completed{color:var(--ok)}.st-partial,.st-skipped{color:var(--med)}.st-failed{color:var(--high)}.st-not_in_mode{color:var(--info)}
.finding{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:10px 0;padding:4px 12px}
.finding summary{cursor:pointer;font-weight:600;padding:8px 0}dl{display:grid;grid-template-columns:170px 1fr;gap:4px 12px}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}ul.ev{margin:0;padding-left:18px}nav a{margin-right:12px}
footer{margin-top:40px;color:var(--muted);font-size:13px}@media print{body{background:#fff}details{display:block}}
@media (max-width:640px){dl{grid-template-columns:1fr}}
"""


def md_cell(text: Any, limit: int = 120) -> str:
    """Escape text for a Markdown table cell and shorten it."""
    value = safe_str(text).replace("|", "\\|").replace("`", "'")
    if len(value) > limit:
        value = value[: limit - 3] + "..."
    return value


def md_code(text: Any) -> str:
    """Inline-code a value, neutralising backticks."""
    return "`" + safe_str(text).replace("`", "'") + "`"


class ReportGenerator:
    """Builds Markdown and JSON reports and writes them without overwriting files."""

    def __init__(self, config: ShadowTraceConfig) -> None:
        self.config = config

    # -- JSON --------------------------------------------------------------- #
    def to_dict(self, result: ScanResult) -> dict[str, Any]:
        """Structured representation of a scan. Field names are stable and documented in the README (schema 2.0)."""
        when = scan_datetime(result)
        profile = MODE_PROFILES.get(result.mode)
        by_status: dict[str, list[str]] = {}
        for check in result.checks:
            by_status.setdefault(check.status, []).append(check.name)
        summary: dict[str, Any] = dict(to_jsonable(result.counts))
        summary.update(summarize_findings(result.findings))
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "tool": TOOL_NAME,
            "version": result.tool_version,
            "report": {
                "scan_id": result.scan_id,
                "date": when.strftime("%m/%d/%Y"),
                "folder_date": when.strftime("%m-%d-%Y"),
                "redacted": result.redacted,
                "generated_locally": True,
                "network_used": False,
            },
            "scan": {
                "started_at": result.started_at,
                "started_local": result.started_local,
                "finished_at": result.finished_at,
                "duration_seconds": round(result.duration_seconds, 2),
                "mode": result.mode,
                "mode_summary": profile.summary if profile else result.mode_summary,
                "mode_omits": profile.omits if profile else "",
                "elevated": result.elevated,
                "operating_system": result.os_description,
                "python_version": result.python_version,
            },
            "summary": summary,
            "coverage": by_status,
            "checks": to_jsonable(result.checks),
            "score": to_jsonable(result.score),
            "findings": to_jsonable(result.findings),
            "processes": to_jsonable(result.processes),
            "startup_entries": to_jsonable(result.startup_entries),
            "drivers": to_jsonable(result.drivers),
            "security_settings": to_jsonable(result.settings),
            "event_evidence": to_jsonable(result.events),
            "defender_detections": to_jsonable(result.detections),
            "service_view_mismatches": to_jsonable(result.view_mismatches),
            "files": to_jsonable(result.files),
            "telemetry": to_jsonable(result.telemetry),
            "known_hash_list": result.intel_summary,
            "notes": to_jsonable(result.notes),
            "limitations": list(LIMITATIONS),
            "not_inspected": list(NOT_INSPECTED),
            "conclusion": result.conclusion,
        }

    def to_json(self, result: ScanResult) -> str:
        """Serialise the scan to a valid JSON document."""
        return json.dumps(self.to_dict(result), indent=2, ensure_ascii=False)

    # -- Markdown ----------------------------------------------------------- #
    def to_markdown(self, result: ScanResult) -> str:
        """Render the full Markdown report."""
        score = result.score
        lines: list[str] = []
        add = lines.append
        add(f"# {TOOL_NAME} Report")
        add("")
        add(f"**{TOOL_NAME} v{result.tool_version}** - {TAGLINE}")
        add("")
        add("> ShadowTrace is a defensive, read-only auditing tool. Findings are investigation leads based on "
            "observed evidence. They are not proof of malware, and a clean result is not proof of safety.")
        add("")
        if result.redacted:
            add("> Best-effort redaction of user and computer names was applied; review before sharing.")
            add("")
        add("## 1. Scan overview")
        add("")
        elevated = {True: "yes (administrator)", False: "no (standard user)", None: "unknown"}[result.elevated]
        add(f"- **Scan started (UTC):** {result.started_at}")
        add(f"- **Scan finished (UTC):** {result.finished_at}")
        add(f"- **Duration:** {result.duration_seconds:.1f} s")
        add(f"- **Scan date:** {scan_datetime(result).strftime('%m/%d/%Y')} (local)")
        add(f"- **Scan mode:** {result.mode} - {md_cell(result.mode_summary, 300)}")
        add(f"- **Operating system:** {md_cell(result.os_description, 200)}")
        add(f"- **Python:** {md_cell(result.python_version, 200)}")
        add(f"- **Elevated:** {elevated}")
        add("")
        add("## 2. What was scanned")
        add("")
        c = result.counts
        add(f"- Processes examined: **{c.get('processes_examined', 0)}**")
        add(f"- Files hashed: **{c.get('files_hashed', 0)}**")
        add(f"- Startup entries examined: **{c.get('startup_entries_examined', 0)}** "
            "(registry values, Startup-folder items, auto-start services)")
        add(f"- User-selected / Startup-folder files analysed: **{c.get('files_analyzed', 0)}**")
        add(f"- Findings: **{c.get('findings', 0)}**")
        add("")
        add("### Check status")
        add("")
        add("| Check | Status | Detail |")
        add("|---|---|---|")
        for check in result.checks:
            add(f"| {md_cell(check.label)} | {check.status} | {md_cell(check.detail, 300)} |")
        add("")
        if result.notes:
            add("**Notes:**")
            for note in result.notes:
                add(f"- {md_cell(note, 400)}")
            add("")
        add("## 3. Overall risk indicator")
        add("")
        if score is not None:
            add(f"- **Heuristic score:** {score.total} / 100 - **{score.band}**")
            add(f"- **Interpretation:** {score.interpretation}")
            add(f"- **Important:** {score.disclaimer}")
            add(f"- **Method:** {score.method}")
            add("")
            counted = [g for g in score.groups if g.points > 0]
            if counted:
                add("| Evidence group | Points counted | Findings |")
                add("|---|---|---|")
                for group in counted:
                    add(f"| {md_cell(group.evidence_key, 100)} | {group.points:.1f} | {', '.join(group.finding_ids)} |")
                add("")
            if score.coverage_notes:
                add("**Coverage notes:**")
                for note in score.coverage_notes:
                    add(f"- {md_cell(note, 500)}")
                add("")
        add("## 4. Findings")
        add("")
        if not result.findings:
            add("No findings were produced by the checks that completed. This is not proof that the system is safe.")
            add("")
        for severity in sorted(Severity, reverse=True):
            group = [f for f in result.findings if f.severity == severity]
            if not group:
                continue
            add(f"### {severity.name} ({len(group)})")
            add("")
            for finding in group:
                add(f"#### {finding.finding_id} - {md_cell(finding.title, 200)}")
                add("")
                add(f"- **Rule:** {finding.rule_id} | **Category:** {finding.category}")
                add(f"- **Severity:** {finding.severity.name} | **Confidence:** {finding.confidence.name} "
                    f"({md_cell(finding.confidence_note, 300)})")
                add(f"- **Status:** {finding.status} | **Detection method:** {finding.detection_method}")
                add(f"- **Affected:** {md_code(finding.subject)}")
                if finding.artifacts:
                    add(f"- **Location(s):** {', '.join(md_code(a) for a in finding.artifacts)}")
                if finding.related_subjects:
                    shown = finding.related_subjects[:10]
                    more = len(finding.related_subjects) - len(shown)
                    extra = f" (+{more} more)" if more > 0 else ""
                    add(f"- **Also affects:** {', '.join(md_code(s) for s in shown)}{extra}")
                if not finding.counted_in_score:
                    add(f"- **Score:** not counted again - shares evidence with {', '.join(finding.shares_evidence_with)}")
                add("- **Evidence:**")
                for line in finding.evidence:
                    add(f"  - {md_code(line)}")
                add(f"- **Why it was flagged:** {finding.explanation}")
                add(f"- **Recommended next step:** {finding.recommendation}")
                add(f"- **Possible false positives / limitations:** {finding.limitations}")
                for factor in finding.limiting_factors:
                    add(f"- **Limit on this result:** {md_cell(factor, 300)}")
                add("")
        add("## 5. False-positive considerations")
        add("")
        for item in GENERAL_FALSE_POSITIVES:
            add(f"- {item}")
        fired = sorted({f.rule_id for f in result.findings})
        for rule_id in fired:
            add(f"- **{rule_id}:** {RULES[rule_id].limitations}")
        add("")
        add("## 6. Limitations and areas not inspected")
        add("")
        for item in LIMITATIONS:
            add(f"- {item}")
        add("")
        add("**Not inspected:**")
        for item in NOT_INSPECTED:
            add(f"- {item}")
        add("")
        add("## 7. Conclusion")
        add("")
        add(result.conclusion)
        add("")
        add("## Appendix A - Startup entries")
        add("")
        if result.startup_entries:
            add("| Source | Location | Name | Command | Target exists |")
            add("|---|---|---|---|---|")
            for entry in result.startup_entries[: self.config.max_report_rows]:
                exists = {True: "yes", False: "NO", None: "unknown"}[entry.target_exists]
                add(f"| {md_cell(entry.source, 30)} | {md_cell(entry.location, 70)} | {md_cell(entry.name, 40)} "
                    f"| {md_cell(entry.command, 140)} | {exists} |")
            if len(result.startup_entries) > self.config.max_report_rows:
                add("")
                add(f"_Showing {self.config.max_report_rows} of {len(result.startup_entries)} entries; see JSON for all._")
        else:
            add("No startup entries were collected.")
        add("")
        add("## Appendix B - Process inventory")
        add("")
        if result.processes:
            add("| PID | PPID | Name | Executable | SHA-256 (first 16) |")
            add("|---|---|---|---|---|")
            for proc in result.processes[: self.config.max_report_rows]:
                digest = proc.sha256[:16] if proc.sha256 else "-"
                add(f"| {proc.pid} | {proc.ppid} | {md_cell(proc.name, 40)} | {md_cell(proc.exe or '(unavailable)', 110)} "
                    f"| {digest} |")
            if len(result.processes) > self.config.max_report_rows:
                add("")
                add(f"_Showing {self.config.max_report_rows} of {len(result.processes)} processes; see JSON for all._")
        else:
            add("No processes were collected.")
        add("")
        if result.files:
            add("## Appendix C - Analysed files")
            add("")
            add("| File | Size | SHA-256 | Note |")
            add("|---|---|---|---|")
            for info in result.files[: self.config.max_report_rows]:
                add(f"| {md_cell(info.path, 110)} | {info.size if info.size is not None else '-'} | "
                    f"{(info.sha256 or '-')[:16]} | {md_cell(info.error or info.hash_note or '', 60)} |")
            add("")
        if result.telemetry:
            add("## Appendix D - Telemetry")
            add("")
            for item in result.telemetry:
                add(f"- **{item.source}:** available={item.available}, checked={item.checked}. {md_cell(item.note, 200)}")
                for key, value in item.details.items():
                    add(f"  - {md_cell(key, 40)}: {md_cell(value, 60)}")
            add("")
        return "\n".join(lines) + "\n"

    # -- HTML --------------------------------------------------------------- #
    def to_html(self, result: ScanResult) -> str:
        """Render the self-contained HTML report (no scripts, no external resources)."""
        esc = html.escape
        when = scan_datetime(result)
        score = result.score
        profile = MODE_PROFILES.get(result.mode)
        summary = summarize_findings(result.findings)
        out: list[str] = []
        add = out.append

        def badge(text: str, css: str) -> str:
            return f'<span class="badge {esc(css)}">{esc(text)}</span>'

        def table(headers: list[str], rows: list[list[str]]) -> str:
            head = "".join(f"<th>{esc(h)}</th>" for h in headers)
            body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
            return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

        def code(text: Any) -> str:
            return f"<code>{esc(safe_str(text))}</code>"

        def finding_html(f: Finding) -> str:
            opened = " open" if (f.severity >= Severity.HIGH or f.status == "confirmed") else ""
            rows = [
                ("Rule", f"{esc(f.rule_id)} &middot; {esc(f.category)}"),
                ("Status", esc(f.status)),
                ("Detection method", esc(f.detection_method)),
                ("Confidence", f"{esc(f.confidence.name)} &mdash; {esc(f.confidence_note)}"),
                ("Affected", code(f.subject)),
            ]
            if f.related_subjects:
                shown = f.related_subjects[:10]
                more = f" (+{len(f.related_subjects) - len(shown)} more)" if len(f.related_subjects) > len(shown) else ""
                rows.append(("Also affects", ", ".join(code(s) for s in shown) + esc(more)))
            if f.artifacts:
                rows.append(("Artifact location(s)", "<br>".join(code(a) for a in f.artifacts)))
            rows.append(("Evidence", '<ul class="ev">' + "".join(f"<li>{code(line)}</li>" for line in f.evidence) + "</ul>"))
            rows.append(("Why it was flagged", esc(f.explanation)))
            rows.append(("Recommended next step", esc(f.recommendation)))
            rows.append(("Possible false positives", esc(f.limitations)))
            if f.limiting_factors:
                rows.append(("Limits on this result", "<br>".join(esc(x) for x in f.limiting_factors)))
            if not f.counted_in_score:
                rows.append(("Score", "Not counted again &mdash; shares evidence with " + esc(", ".join(f.shares_evidence_with))))
            dl = "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in rows)
            return (f'<details class="finding" id="{esc(f.finding_id)}"{opened}><summary>'
                    f'{badge(f.severity.name, "sev-" + f.severity.name)}{badge(f.status, "st-partial" if f.status == "suspicious" else "sev-INFO")}'
                    f'{esc(f.finding_id)} &ndash; {esc(f.title)}</summary><dl>{dl}</dl></details>')

        add("<!DOCTYPE html>")
        add('<html lang="en"><head><meta charset="utf-8">')
        add("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">")
        add('<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer">')
        add(f"<title>ShadowTrace Report - {when.strftime('%m/%d/%Y')}</title><style>{_HTML_CSS}</style></head><body><main>")
        add(f"<h1>ShadowTrace Report</h1>")
        add(f'<p class="meta">Scan date <b>{when.strftime("%m/%d/%Y")}</b> at {when.strftime("%H:%M:%S")} (local) &middot; '
            f'mode <b>{esc(result.mode)}</b> &middot; duration {result.duration_seconds:.1f}s &middot; '
            f'ShadowTrace v{esc(result.tool_version)} &middot; scan ID {esc(result.scan_id or "n/a")}</p>')
        add('<div class="notice warn"><b>No findings do not guarantee a clean system.</b> ShadowTrace is a read-only, '
            "user-mode assessment with known blind spots (see Limitations). It changed nothing on this computer: "
            "nothing was removed, stopped, quarantined or uploaded.</div>")
        if result.redacted:
            add('<div class="notice">Best-effort redaction of user and computer names was applied. It does not '
                "guarantee that all sensitive data was removed; review before sharing.</div>")
        add('<nav><a href="#summary">Summary</a><a href="#coverage">Coverage</a><a href="#unassessed">Not assessed</a>'
            '<a href="#findings">Findings</a><a href="#next">Next steps</a><a href="#limits">Limitations</a>'
            '<a href="#appendix">Appendix</a></nav>')

        add('<h2 id="summary">Summary</h2>')
        confirmed = summary["by_status"]["confirmed"]
        suspicious = summary["by_status"]["suspicious"]
        informational = summary["by_status"]["informational"]
        gaps = sum(1 for c in result.checks if c.status in (SKIPPED, FAILED, PARTIAL))
        add('<div class="cards">'
            f'<div class="card">Confirmed detections<b>{confirmed}</b></div>'
            f'<div class="card">Suspicious indicators<b>{suspicious}</b></div>'
            f'<div class="card">Informational<b>{informational}</b></div>'
            f'<div class="card">Checks not fully completed<b>{gaps}</b></div>')
        if score is not None:
            add(f'<div class="card">Heuristic score<b>{score.total}/100</b>{esc(score.band)}</div>')
        add("</div>")
        if score is not None:
            add(f"<p><b>{esc(score.interpretation)}</b></p><p class=\"meta\">{esc(score.disclaimer)}</p>")
        add(f"<p>{esc(result.conclusion)}</p>")
        add("<h3>Severity scheme</h3>")
        add(table(["Severity", "Meaning", "Findings"], [
            [badge("CRITICAL", "sev-CRITICAL"), "Confirmed by reliable evidence (a known-hash match from your list, or an active Defender threat).", str(summary["by_severity"]["CRITICAL"])],
            [badge("HIGH", "sev-HIGH"), "Strong, uncommon indicator that needs prompt review (not proof).", str(summary["by_severity"]["HIGH"])],
            [badge("MEDIUM", "sev-MEDIUM"), "Notable indicator worth reviewing.", str(summary["by_severity"]["MEDIUM"])],
            [badge("LOW", "sev-LOW"), "Weak or contextual signal; often benign.", str(summary["by_severity"]["LOW"])],
            [badge("INFO", "sev-INFO"), "Context or hardening information; not scored.", str(summary["by_severity"]["INFO"])],
        ]))
        if summary["by_category"]:
            add("<h3>Findings by type</h3>")
            add(table(["Type", "Count"], [[esc(k), str(v)] for k, v in sorted(summary["by_category"].items())]))
        if result.intel_summary:
            add(f'<p class="meta">Known-hash list: {esc(result.intel_summary)}</p>')

        add('<h2 id="coverage">Coverage</h2>')
        if profile is not None:
            add(f"<p><b>{esc(profile.name)} mode:</b> {esc(profile.summary)}</p><p class=\"meta\">Omitted by this mode: {esc(profile.omits)}</p>")
        add(table(["Check", "Status", "Detail"], [
            [esc(c.label), badge(c.status.replace("_", " "), "st-" + c.status), esc(c.detail)] for c in result.checks]))
        c = result.counts
        add(f"<p class=\"meta\">Processes examined: {c.get('processes_examined', 0)} &middot; files hashed: "
            f"{c.get('files_hashed', 0)} &middot; startup entries: {c.get('startup_entries_examined', 0)} &middot; "
            f"drivers: {c.get('drivers_examined', 0)} &middot; security observations: {c.get('settings_observed', 0)}</p>")

        add('<h2 id="unassessed">Could not be assessed</h2>')
        problems = [x for x in result.checks if x.status in (SKIPPED, FAILED, PARTIAL)]
        omitted = [x for x in result.checks if x.status == NOT_IN_MODE]
        if problems:
            add(table(["Check", "Status", "Why"], [[esc(x.label), badge(x.status, "st-" + x.status), esc(x.detail)] for x in problems]))
        else:
            add("<p>Every check in this mode completed.</p>")
        if score is not None and score.coverage_notes:
            add("<ul>" + "".join(f"<li>{esc(n)}</li>" for n in score.coverage_notes) + "</ul>")
        if omitted:
            add("<p class=\"meta\">Not part of this mode (not a failure): " + esc(", ".join(x.label for x in omitted)) + "</p>")

        add('<h2 id="findings">Findings</h2>')
        if not result.findings:
            add("<p>No findings were produced by the checks that completed. This is not proof that the system is safe.</p>")
        sections = [("Confirmed detections", [f for f in result.findings if f.status == "confirmed"]),
                    ("Suspicious indicators", [f for f in result.findings if f.status == "suspicious"]),
                    ("Informational findings", [f for f in result.findings if f.status == "informational"])]
        for title, items in sections:
            if not items:
                continue
            add(f"<h3>{esc(title)} ({len(items)})</h3>")
            if title == "Confirmed detections":
                add("<p class=\"meta\">Confirmed means a reliable source matched (a known-hash list you supplied or a security "
                    "product's own result). It does not mean ShadowTrace scanned or removed anything.</p>")
            for finding in items:
                add(finding_html(finding))

        add('<h2 id="next">Recommended next steps</h2><ul>')
        for line in (
            "ShadowTrace never changes your system. Nothing has been deleted, stopped, quarantined or disabled.",
            "Review each finding and its false-positive notes. Do not delete files you do not understand.",
            "To scan with Microsoft Defender yourself: Windows Security > Virus & threat protection > Scan options, "
            "choose Full scan or Microsoft Defender Antivirus (offline scan). ShadowTrace does not start scans.",
            "If you suspect a rootkit or an active compromise, use trusted offline or specialist forensic tools: software "
            "running inside a compromised Windows can be hidden from. Consider disconnecting from the network first.",
            "Reports contain local paths, command lines and possibly user or computer names. Review before sharing "
            "(the --redact option masks names on a best-effort basis).",
        ):
            add(f"<li>{esc(line)}</li>")
        add("</ul>")

        add('<h2 id="limits">Limitations</h2><ul>')
        add("".join(f"<li>{esc(x)}</li>" for x in LIMITATIONS))
        add("</ul><p class=\"meta\">Not inspected: " + esc("; ".join(NOT_INSPECTED)) + "</p>")
        fired = sorted({f.rule_id for f in result.findings})
        if fired:
            add("<h3>False-positive considerations for the rules that fired</h3><ul>")
            add("".join(f"<li><b>{esc(r)}:</b> {esc(RULES[r].limitations)}</li>" for r in fired))
            add("</ul>")

        add('<h2 id="appendix">Appendix</h2>')
        cap = self.config.max_report_rows

        def appendix(title: str, headers: list[str], rows: list[list[str]], total: int) -> None:
            if not rows:
                return
            note = f"<p class=\"meta\">Showing {len(rows)} of {total}; the JSON report has everything.</p>" if total > len(rows) else ""
            add(f"<details><summary>{esc(title)} ({total})</summary>{table(headers, rows)}{note}</details>")

        appendix("Startup entries", ["Source", "Location", "Name", "Command", "Target exists"],
                 [[esc(e.source), esc(e.location), esc(e.name), code(e.command),
                   {True: "yes", False: "NO", None: "unknown"}[e.target_exists]] for e in result.startup_entries[:cap]],
                 len(result.startup_entries))
        appendix("Drivers", ["Name", "Start", "State", "Path", "Embedded signature"],
                 [[esc(d.name), esc(d.start_label), esc(d.state or "-"), code(d.path or ""),
                   {True: "present", False: "absent", None: "n/a"}[d.embedded_signature]] for d in result.drivers[:cap]],
                 len(result.drivers))
        appendix("Security settings", ["Setting", "Value", "State", "Source"],
                 [[esc(s.label), esc(s.value), esc(s.state), code(s.source)] for s in result.settings[:cap]],
                 len(result.settings))
        appendix("PowerShell event evidence", ["Time", "Patterns", "Excerpt (redacted)"],
                 [[esc(e.time), esc(", ".join(e.labels)), code(e.excerpt)] for e in result.events[:cap]], len(result.events))
        appendix("Defender detection history", ["Threat", "Time", "Resources"],
                 [[esc(d.name), esc(d.time), "<br>".join(code(r) for r in d.resources)] for d in result.detections[:cap]],
                 len(result.detections))
        appendix("Processes", ["PID", "PPID", "Name", "Executable", "SHA-256 (first 16)"],
                 [[str(p.pid), str(p.ppid), esc(p.name), code(p.exe or "(unavailable)"), esc((p.sha256 or "-")[:16])]
                  for p in result.processes[:cap]], len(result.processes))
        appendix("Analysed files", ["File", "Size", "SHA-256 (first 16)", "Sources", "Note"],
                 [[code(i.path), str(i.size if i.size is not None else "-"), esc((i.sha256 or "-")[:16]),
                   esc(", ".join(i.sources or [i.source])), esc(i.error or i.hash_note or "")] for i in result.files[:cap]],
                 len(result.files))
        add(f"<footer>Generated locally by ShadowTrace v{esc(result.tool_version)}. No data was transmitted. "
            "Report schema "
            f"{REPORT_SCHEMA_VERSION}.</footer></main></body></html>")
        return "\n".join(out) + "\n"

    # -- rendering and writing --------------------------------------------------- #
    def _prepared(self, result: ScanResult) -> ScanResult:
        """A redacted copy of the result when redaction is enabled, otherwise the result itself."""
        if not self.config.redact or result.redacted:
            return result
        redacted = transform_strings(result, Redactor())
        redacted.redacted = True
        return redacted

    def render(self, kind: str, result: ScanResult) -> str:
        """Render one report format (``html``, ``json`` or ``markdown``), applying redaction if configured."""
        prepared = self._prepared(result)
        if kind == "html":
            return self.to_html(prepared)
        if kind == "json":
            return self.to_json(prepared)
        if kind == "markdown":
            return self.to_markdown(prepared)
        raise ValueError(f"Unknown report format: {kind}")

    def write(self, result: ScanResult, report_format: str, directory: Path) -> list[Path]:
        """Save the report(s) to ``<output>/reports/MM-DD-YYYY/`` without overwriting anything.

        Raises :class:`ReportError` on failure (any files already written are listed on the exception).
        """
        kinds = REPORT_FORMATS.get(report_format)
        if kinds is None:
            raise ReportError(f"Unknown report format: {safe_str(report_format)}")
        when = scan_datetime(result)
        written_total: list[Path] = []
        try:
            day_dir = resolve_reports_root(directory) / when.strftime("%m-%d-%Y")
            rendered = {kind: self.render(kind, result) for kind in kinds}  # render first: a bug must not leave partial files
            day_dir.mkdir(parents=True, exist_ok=True)
            base = f"ShadowTrace_Report_{when.strftime('%H%M%S')}"
            for attempt in range(1, 1000):
                stem = base if attempt == 1 else f"{base}_{attempt}"
                targets = [day_dir / f"{stem}{REPORT_EXTENSIONS[k]}" for k in kinds]
                if any(p.exists() or p.is_symlink() for p in targets):
                    continue
                written: list[Path] = []
                try:
                    for kind, path in zip(kinds, targets):
                        with open(path, "x", encoding="utf-8", newline="\n") as handle:  # 'x': never overwrite
                            handle.write(rendered[kind])
                        written.append(path)
                except FileExistsError:
                    written_total.extend(written)  # lost a race for this name; earlier files are kept, retry
                    continue
                return written
            raise OSError("could not find an unused report file name")
        except ReportError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise ReportError(f"Could not write report: {safe_str(exc)}", written_total) from exc


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def attach_limiting_factors(findings: list[Finding], checks: list[CheckStatus], elevated: Optional[bool]) -> None:
    """Record, on each finding, the coverage limits of the check that produced its evidence."""
    by_id = {c.name: c for c in checks}
    needs_admin = {"process_inventory", "services", "scheduled_tasks", "wmi_persistence", "drivers",
                   "security_settings", "registry_config", "defender_detections"}
    for finding in findings:
        check = by_id.get(finding.source_check)
        if check is not None and check.status in (SKIPPED, FAILED, PARTIAL):
            finding.limiting_factors.append(f"{check.label} was {check.status}: {check.detail}")
        if elevated is False and finding.source_check in needs_admin:
            finding.limiting_factors.append("Not run as administrator: this source may be incomplete.")


class ShadowTraceApp:
    """Runs every check enabled by the scan mode, isolating failures so one problem never aborts the scan."""

    STEPS = (
        ("process_inventory", "Inventorying processes"),
        ("registry_autoruns", "Reading startup registry keys"),
        ("registry_config", "Reading execution-hijack settings"),
        ("startup_folders", "Listing Startup folders"),
        ("services", "Inspecting services"),
        ("scheduled_tasks", "Parsing scheduled tasks"),
        ("wmi_persistence", "Reading WMI subscriptions"),
        ("drivers", "Reading driver services"),
        ("security_settings", "Reading security settings"),
        ("file_sweep", "Sweeping user-writable folders"),
        ("file_analysis", "Analysing selected files"),
        ("telemetry_defender", "Reading Defender status"),
        ("defender_detections", "Reading Defender history"),
        ("event_logs", "Reading PowerShell event evidence"),
        ("detection_rules", "Applying detection rules"),
        ("risk_scoring", "Scoring results"),
    )
    STEP_NAMES = tuple(name for _check_id, name in STEPS)

    def __init__(self, config: ShadowTraceConfig, registry_reader: Optional[RegistryReader] = None,
                 service_iter: Optional[Callable[[], Any]] = None,
                 telemetry_checker: Optional[TelemetryChecker] = None,
                 command_runner: Callable[..., Any] = subprocess.run,
                 tasks_dir: Optional[str] = None, env: Optional[dict[str, str]] = None,
                 path_exists: Callable[[str], bool] = os.path.exists) -> None:
        self.config = config
        self.registry_reader = registry_reader
        self.service_iter = service_iter
        self.command_runner = command_runner
        self.telemetry_checker = telemetry_checker or TelemetryChecker(command_runner)
        self.tasks_dir = tasks_dir
        self.env = env
        self.path_exists = path_exists

    def run(self, on_step: Optional[Callable[[int, int, str], None]] = None) -> ScanResult:
        """Execute the scan and return a :class:`ScanResult` (never raises for check failures)."""
        cfg = self.config
        started = utc_now()
        clock = time.monotonic()
        deadline = Deadline(cfg.time_limit)
        analyzer = FileAnalyzer(cfg, deadline)
        intel = ThreatIntel.load(cfg.hash_list_paths) if cfg.hash_list_paths else None
        commands = CommandRunner(self.command_runner)
        total_steps = len(self.STEPS)
        result = ScanResult(
            tool_version=__version__,
            started_at=started.isoformat(timespec="seconds"),
            started_local=started.astimezone().isoformat(timespec="seconds"),
            scan_id=uuid.uuid4().hex[:12],
            mode=cfg.mode,
            mode_summary=cfg.profile.summary,
            intel_summary=intel.describe() if intel else "",
            elevated=is_elevated(),
            os_description=safe_str(describe_os()),
            python_version=safe_str(f"{platform.python_version()} ({platform.python_implementation()}, "
                                    f"{struct.calcsize('P') * 8}-bit)"),
        )
        persistence = PersistenceScanner(cfg, analyzer, deadline, self.registry_reader, path_exists=self.path_exists,
                                         env=self.env, service_iter=self.service_iter, commands=commands,
                                         tasks_dir=self.tasks_dir)
        driver_scanner = DriverScanner(cfg, analyzer, deadline, persistence.registry, commands, self.path_exists, self.env)
        settings_scanner = SecuritySettingsScanner(cfg, persistence.registry, commands, deadline)
        ids = [check_id for check_id, _name in self.STEPS]

        def do(check_id: str, func: Callable[[], Any], default: Any, three_part: bool = False,
               skip_reason: Optional[str] = None) -> Any:
            if on_step:
                on_step(ids.index(check_id), total_steps, self.STEP_NAMES[ids.index(check_id)])
            label = CHECK_LABELS[check_id]
            if not cfg.check_enabled(check_id):
                result.checks.append(CheckStatus(check_id, label, NOT_IN_MODE, f"Not part of {cfg.mode} mode."))
                return default
            if skip_reason:
                result.checks.append(CheckStatus(check_id, label, SKIPPED, skip_reason))
                return default
            value, status = self._run_check(check_id, label, func, default, three_part)
            result.checks.append(status)
            return value

        processes = do("process_inventory", lambda: ProcessScanner(cfg, analyzer, deadline, self.path_exists).scan(), [])
        result.processes = processes
        entries: list[StartupEntry] = []
        entries += do("registry_autoruns", persistence.scan_registry, [])
        entries += do("registry_config", persistence.scan_registry_config, [])
        folder_entries, folder_files = do("startup_folders", persistence.scan_startup_folders, ([], []), three_part=True)
        entries += folder_entries
        entries += do("services", persistence.scan_services, [])
        entries += do("scheduled_tasks", persistence.scan_tasks, [])
        entries += do("wmi_persistence", persistence.scan_wmi, [])
        result.startup_entries = entries
        result.drivers = do("drivers", driver_scanner.scan, [])
        result.settings = do("security_settings", settings_scanner.scan, [])
        sweep_files = do("file_sweep", lambda: FileSweeper(cfg, analyzer, deadline, self.env).sweep(), [])
        user_files = do("file_analysis", lambda: self._analyze_user_paths(analyzer), [],
                        skip_reason=None if cfg.extra_paths else "No --path values were supplied.")
        telemetry = do("telemetry_defender", lambda: self.telemetry_checker.check_defender(deadline), None)
        if telemetry is not None:
            result.telemetry.append(telemetry)
        result.detections = do("defender_detections", lambda: self.telemetry_checker.check_detections(deadline), [])
        result.events = do("event_logs", lambda: EventLogScanner(commands, deadline).scan(), [])
        result.files = merge_files(analyzer.files(), folder_files, sweep_files, user_files)
        result.view_mismatches = find_service_view_mismatches(
            persistence.scm_service_names, driver_scanner.registry_service_names, driver_scanner.cim_driver_names)

        result.findings = do("detection_rules", lambda: self._detect(result, intel), [])
        attach_limiting_factors(result.findings, result.checks, result.elevated)

        scorer = RiskScorer(cfg)
        score = do("risk_scoring", lambda: self._score(scorer, result), None)
        if score is None:
            score = ScoreResult(0, "NONE", "Scoring failed; no score is available.", [], True,
                                ["Risk scoring failed; see the check status."], "n/a", SCORE_DISCLAIMER)
        result.score = score
        result.conclusion = RiskScorer.conclusion(score, result.findings)

        if on_step:
            on_step(total_steps, total_steps, "Finished")
        result.finished_at = utc_now().isoformat(timespec="seconds")
        result.duration_seconds = time.monotonic() - clock
        result.counts = {
            "processes_examined": len(result.processes),
            "files_hashed": analyzer.files_hashed,
            "files_inspected": analyzer.files_inspected,
            "startup_entries_examined": len(result.startup_entries),
            "files_analyzed": len(result.files),
            "drivers_examined": len(result.drivers),
            "settings_observed": len(result.settings),
            "findings": len(result.findings),
        }
        return result

    # -- internal helpers ---------------------------------------------------- #
    def _run_check(self, check_id: str, label: str, func: Callable[[], Any], default: Any,
                   three_part: bool = False) -> tuple[Any, CheckStatus]:
        """Run a check returning ``(data, status)`` tuples with failure isolation.

        Catching ``Exception`` here is deliberate: checks are independent, and a bug or unsupported Windows API
        in one must never abort the rest of the scan.
        """
        try:
            outcome = func()
        except Exception as exc:  # noqa: BLE001 - documented isolation boundary
            log.debug("Check %s failed", check_id, exc_info=True)
            return default, CheckStatus(check_id, label, FAILED,
                                        f"Unexpected error: {type(exc).__name__}: {safe_str(exc)}")
        if three_part:
            entries, files, status = outcome
            return (entries, files), status
        data, status = outcome
        return data, status

    def _analyze_user_paths(self, analyzer: FileAnalyzer) -> tuple[list[FileInfo], CheckStatus]:
        paths, notes = analyzer.expand_user_paths(self.config.extra_paths)
        analysed = [analyzer.analyze(path, source="user-path", hash_enabled=True, inspect=True) for path in paths]
        errors = sum(1 for info in analysed if info.error)
        detail = f"{len(analysed)} files analysed"
        if errors:
            detail += f", {errors} could not be read"
        if notes:
            detail += "; " + "; ".join(notes)
        status = COMPLETED if not errors and not notes else PARTIAL
        if not analysed and not notes:
            status = PARTIAL
            detail = "No files were found at the supplied paths."
        return analysed, CheckStatus("file_analysis", CHECK_LABELS["file_analysis"], status, detail, len(analysed))

    def _detect(self, result: ScanResult, intel: Optional[ThreatIntel]) -> tuple[list[Finding], CheckStatus]:
        engine = DetectionEngine(self.config)
        findings = engine.run(result.processes, result.startup_entries, result.files, result.telemetry,
                              drivers=result.drivers, settings=result.settings, events=result.events,
                              detections=result.detections, view_mismatches=result.view_mismatches, intel=intel)
        return findings, CheckStatus("detection_rules", CHECK_LABELS["detection_rules"], COMPLETED,
                                     f"{len(RULE_LIST)} rules evaluated; {len(findings)} findings", len(findings))

    def _score(self, scorer: RiskScorer, result: ScanResult) -> tuple[ScoreResult, CheckStatus]:
        score = scorer.score(result.findings, result.checks, result.processes, result.elevated)
        return score, CheckStatus("risk_scoring", CHECK_LABELS["risk_scoring"], COMPLETED,
                                  f"Score {score.total}/100 ({score.band})", 1)


# --------------------------------------------------------------------------- #
# Terminal user interface (rich)
# --------------------------------------------------------------------------- #
SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}
STATUS_STYLES = {COMPLETED: "green", PARTIAL: "yellow", SKIPPED: "dim", FAILED: "bold red", NOT_IN_MODE: "dim"}
BAND_STYLES = {"NONE": "green", "LOW": "green", "MODERATE": "yellow", "ELEVATED": "red", "HIGH": "bold red"}


class ConsoleUI:
    """All terminal output, built on rich."""

    def __init__(self, console: Optional["Console"] = None) -> None:
        self.console = console or Console(highlight=False)

    def banner(self) -> None:
        """Print the ShadowTrace banner."""
        title = Text()
        title.append("SHADOW", style="bold white")
        title.append("TRACE", style="bold cyan")
        title.append(f"  v{__version__}", style="dim")
        body = Text.assemble(title, "\n", (TAGLINE, "italic"), "\n",
                             ("Strictly read-only. Findings are leads, not verdicts.", "dim"))
        self.console.print(Panel(body, box=box.ROUNDED, border_style="cyan", padding=(0, 2)))

    def progress(self) -> "Progress":
        """Create a transient progress display."""
        return Progress(SpinnerColumn(), TextColumn("[bold]{task.description}"), BarColumn(),
                        TimeElapsedColumn(), console=self.console, transient=True)

    def show_summary(self, result: ScanResult, report_paths: list[Path], report_error: Optional[str]) -> None:
        """Print a concise end-of-scan summary."""
        c = result.counts
        facts = Table.grid(padding=(0, 2))
        facts.add_row("Scan date", scan_datetime(result).strftime("%m/%d/%Y"))
        facts.add_row("Mode", result.mode)
        facts.add_row("Duration", f"{result.duration_seconds:.1f}s")
        facts.add_row("Elevated", {True: "yes", False: "no", None: "unknown"}[result.elevated])
        facts.add_row("Processes examined", str(c.get("processes_examined", 0)))
        facts.add_row("Files hashed", str(c.get("files_hashed", 0)))
        facts.add_row("Startup entries", str(c.get("startup_entries_examined", 0)))
        status_counts = summarize_findings(result.findings)["by_status"]
        facts.add_row("Findings", f"{c.get('findings', 0)} (confirmed {status_counts['confirmed']}, "
                                  f"suspicious {status_counts['suspicious']}, informational {status_counts['informational']})")
        self.console.print(Panel(facts, title="Scan summary", border_style="cyan", box=box.ROUNDED))

        checks = Table(title="Checks", box=box.SIMPLE_HEAD, show_lines=False, expand=True)
        checks.add_column("Check", no_wrap=True)
        checks.add_column("Status", no_wrap=True)
        checks.add_column("Detail", overflow="fold")
        for check in result.checks:
            checks.add_row(check.label, Text(check.status, style=STATUS_STYLES.get(check.status, "")),
                           check.detail)
        self.console.print(checks)

        if result.findings:
            table = Table(title="Findings (investigation leads)", box=box.SIMPLE_HEAD, expand=True)
            table.add_column("ID", no_wrap=True)
            table.add_column("Severity", no_wrap=True)
            table.add_column("Rule", no_wrap=True)
            table.add_column("Title", overflow="fold")
            table.add_column("Affected", overflow="fold")
            for finding in result.findings[:25]:
                table.add_row(finding.finding_id,
                              Text(finding.severity.name, style=SEVERITY_STYLES[finding.severity.name]),
                              finding.rule_id, f"{finding.status.upper()}: {finding.title}", md_cell(finding.subject, 70))
            self.console.print(table)
            if len(result.findings) > 25:
                self.console.print(f"[dim]{len(result.findings) - 25} more findings are in the report.[/dim]")
        else:
            self.console.print("[green]No heuristic findings from the checks that completed.[/green] "
                               "[dim](This is not proof the computer is safe.)[/dim]")

        score = result.score
        if score is not None:
            style = BAND_STYLES.get(score.band, "")
            body = Text()
            body.append(f"{score.total}/100 ", style=f"bold {style}".strip())
            body.append(f"({score.band})\n", style=style)
            body.append(score.interpretation + "\n", style="")
            body.append(score.disclaimer, style="dim")
            self.console.print(Panel(body, title="Heuristic risk indicator", border_style=style or "cyan",
                                     box=box.ROUNDED))
        if report_paths:
            self.console.print("[bold]Report(s) written:[/bold]")
            for path in report_paths:
                self.console.print(f"  {path}", markup=False, soft_wrap=True)
            self.console.print("[dim]Reports contain local paths, command lines and possibly user or computer names. "
                               "Review them before sharing (--redact masks names, best effort).[/dim]")
        if report_error:
            self.console.print(f"[bold red]Report problem:[/bold red] {report_error}", markup=True)
            self.console.print("[yellow]The scan results above were kept in memory but no complete report "
                               "was saved. Check the output directory and try again.[/yellow]")
        self.console.print(f"[dim]{result.conclusion}[/dim]")

    def show_processes(self, processes: list[ProcessInfo], limit: int = 60) -> None:
        """Print a compact process table."""
        table = Table(title=f"Processes (first {min(limit, len(processes))} of {len(processes)})",
                      box=box.SIMPLE_HEAD, expand=True)
        table.add_column("PID", justify="right", no_wrap=True)
        table.add_column("PPID", justify="right", no_wrap=True)
        table.add_column("Name", no_wrap=True)
        table.add_column("Executable", overflow="fold")
        for proc in processes[:limit]:
            table.add_row(str(proc.pid), str(proc.ppid), proc.name, proc.exe or "(unavailable)")
        self.console.print(table)

    def show_modes(self) -> None:
        """Print what each scan mode checks and omits."""
        table = Table(title="ShadowTrace scan modes", box=box.SIMPLE_HEAD, expand=True)
        table.add_column("Mode", no_wrap=True)
        table.add_column("Purpose", overflow="fold")
        table.add_column("Checks", overflow="fold")
        table.add_column("Omits", overflow="fold")
        for name in MODE_ORDER:
            profile = MODE_PROFILES[name]
            checks = ", ".join(label for check_id, label in CHECK_LABELS.items() if check_id in profile.checks)
            table.add_row(name + (" (default)" if name == "full" else ""), profile.summary, checks, profile.omits)
        self.console.print(table)
        self.console.print("[dim]Every mode is manual, one-shot and read-only. --path files are analysed in any mode. "
                           "'--telemetry' adds the Defender status check; '--no-defender' removes all Defender queries.[/dim]")

    def show_history(self, entries: list["ReportEntry"], root: Path) -> None:
        """Print saved reports grouped by date, newest first."""
        if not entries:
            self.console.print(f"No saved reports found under {root}", markup=False, soft_wrap=True)
            return
        self.console.print(f"Saved reports (newest first) in {root}", markup=False, soft_wrap=True)
        last_date = ""
        for number, entry in enumerate(entries, start=1):
            if entry.date_text != last_date:
                self.console.print(f"\n{entry.date_text}", style="bold", markup=False)
                last_date = entry.date_text
            self.console.print(f"  {number}. {entry.time_text}   mode: {entry.mode}", markup=False)
            for kind, report_path in sorted(entry.paths.items()):
                self.console.print(f"       {kind}: {report_path}", markup=False, soft_wrap=True)
        self.console.print("\nOpen one with: python shadowtrace.py reports --open N", markup=False)

    def show_rules(self, details: bool) -> None:
        """Print the detection rule catalogue."""
        table = Table(title="ShadowTrace detection rules", box=box.SIMPLE_HEAD, expand=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("Category", no_wrap=True)
        table.add_column("Default", no_wrap=True)
        table.add_column("What it checks", overflow="fold")
        for spec in RULE_LIST:
            table.add_row(spec.rule_id, spec.category,
                          Text(spec.severity.name, style=SEVERITY_STYLES[spec.severity.name]),
                          f"[bold]{spec.title}[/bold]\n{spec.checks}")
        self.console.print(table)
        if details:
            for spec in RULE_LIST:
                self.console.print(Panel(
                    f"[bold]Why it matters:[/bold] {spec.explanation}\n"
                    f"[bold]Next step:[/bold] {spec.recommendation}\n"
                    f"[bold]False positives:[/bold] {spec.limitations}\n"
                    f"[bold]Confidence:[/bold] {spec.confidence.name} - {spec.confidence_note}",
                    title=f"{spec.rule_id} {spec.title}", border_style="dim"))
        self.console.print("[dim]Every finding is an investigation lead. Severity reflects how unusual the evidence "
                           "is, not a verdict. Thresholds live in ShadowTraceConfig.[/dim]")

    def show_info(self) -> None:
        """Print version, platform compatibility, capabilities and limitations."""
        grid = Table.grid(padding=(0, 2))
        grid.add_row("Version", __version__)
        grid.add_row("Python", f"{platform.python_version()} (requires {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+)")
        grid.add_row("Platform", describe_os())
        grid.add_row("Target platform", "Windows 10 / 11 (full functionality)")
        grid.add_row("Other platforms", "Not supported; `scan --allow-non-windows` runs a limited development mode")
        grid.add_row("Elevated", {True: "yes", False: "no", None: "unknown"}[is_elevated()])
        for name, module in (("psutil", psutil), ("typer", typer), ("rich", Console)):
            grid.add_row(f"Dependency: {name}", "installed" if module is not None else "MISSING")
        grid.add_row("winreg (registry)", "available" if winreg is not None else "not available on this platform")
        self.console.print(Panel(grid, title=f"{TOOL_NAME} info", border_style="cyan", box=box.ROUNDED))
        self.console.print("[bold]Capabilities[/bold]")
        for item in CAPABILITIES:
            self.console.print(f"  - {item}", markup=False)
        self.console.print("[bold]Safety guarantees[/bold]")
        for item in SAFETY_GUARANTEES:
            self.console.print(f"  - {item}", markup=False)
        self.console.print("[bold]Limitations[/bold]")
        for item in LIMITATIONS:
            self.console.print(f"  - {item}", markup=False)


# --------------------------------------------------------------------------- #
# Command-line interface (typer)
# --------------------------------------------------------------------------- #
class OutputFormat(str, Enum):
    """Report formats supported by ``scan --format``."""

    html = "html"
    json = "json"
    markdown = "markdown"
    both = "both"   # html + json (default)
    all = "all"     # html + json + markdown


class ModeOption(str, Enum):
    """Scan modes supported by ``scan --mode``."""

    quick = "quick"
    full = "full"
    malware = "malware"
    rootkit = "rootkit"
    dormant = "dormant"


def build_cli() -> "typer.Typer":
    """Construct the typer application (requires typer and rich)."""
    app = typer.Typer(
        name="shadowtrace",
        help="ShadowTrace - manual, read-only Windows threat assessment tool (keyloggers, malware, persistence, rootkit indicators).",
        add_completion=False,
        no_args_is_help=True,
    )

    @app.command()
    def scan(
        output: Annotated[Path, typer.Option("--output", "-o",
                                             help="Output location; reports go to <output>/reports/MM-DD-YYYY/.")] = Path("reports"),
        report_format: Annotated[OutputFormat, typer.Option("--format", "-f", case_sensitive=False,
                                                            help="Report format: html, json, markdown, both (html+json) or all.")] = OutputFormat.both,
        mode: Annotated[Optional[ModeOption], typer.Option("--mode", "-m", case_sensitive=False,
                                                           help="Scan mode: quick, full (default), malware, rootkit or dormant. See 'modes'.")] = None,
        quick: Annotated[bool, typer.Option("--quick", help="Same as --mode quick.")] = False,
        path: Annotated[Optional[list[Path]], typer.Option("--path", "-p",
                                                           help="File or directory to analyse (repeatable, bounded).")] = None,
        hash_list: Annotated[Optional[list[Path]], typer.Option(
            "--hash-list", help="Local text file of known-malicious SHA-256 hashes (repeatable). Never uploaded.")] = None,
        telemetry: Annotated[bool, typer.Option("--telemetry",
                                                help="Also read Microsoft Defender status in any mode (read-only).")] = False,
        no_defender: Annotated[bool, typer.Option("--no-defender",
                                                  help="Never run any Microsoft Defender query.")] = False,
        redact: Annotated[bool, typer.Option("--redact",
                                             help="Best-effort masking of user and computer names in reports.")] = False,
        no_prompt: Annotated[bool, typer.Option("--no-prompt", "--no-open",
                                                help="Do not ask to open the report (for automation).")] = False,
        max_seconds: Annotated[Optional[float], typer.Option("--max-seconds", min=5,
                                                             help="Wall-clock limit for the scan.")] = None,
        list_processes: Annotated[bool, typer.Option("--list-processes",
                                                     help="Also print a process table in the terminal.")] = False,
        allow_non_windows: Annotated[bool, typer.Option("--allow-non-windows",
                                                        help="Development mode on non-Windows systems (limited checks).")] = False,
        verbose: Annotated[bool, typer.Option("--verbose", help="Show debug logging.")] = False,
    ) -> None:
        """Run a one-shot, read-only scan, save the reports, then offer to open the HTML report."""
        ui = ConsoleUI()
        if verbose:
            logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
        ui.banner()
        if quick and mode is not None and mode.value != "quick":
            ui.console.print("[bold red]--quick conflicts with --mode.[/bold red] Use one of them.", markup=True)
            raise typer.Exit(code=2)
        chosen = mode.value if mode is not None else ("quick" if quick else "full")
        if not IS_WINDOWS and not allow_non_windows:
            ui.console.print(
                "[bold red]ShadowTrace targets Windows.[/bold red] This system is "
                f"{sys.platform}, so most checks cannot run.\n"
                "Re-run with [bold]--allow-non-windows[/bold] for a limited development mode "
                "(process inventory only).", markup=True)
            raise typer.Exit(code=2)
        config = ShadowTraceConfig(
            mode=chosen,
            output_dir=output,
            report_format=report_format.value,
            extra_paths=[str(p) for p in (path or [])],
            hash_list_paths=[str(p) for p in (hash_list or [])],
            telemetry=telemetry,
            no_defender=no_defender,
            redact=redact,
            time_limit_seconds=max_seconds,
            allow_non_windows=allow_non_windows,
        )
        ui.console.print(f"[bold]Mode:[/bold] {config.mode} - {config.profile.summary}", markup=True)
        if not is_elevated() and IS_WINDOWS:
            ui.console.print("[yellow]Not running as administrator: some checks will be limited and clearly "
                             "marked in the report.[/yellow]")
        app_runner = ShadowTraceApp(config)
        with ui.progress() as progress:
            task = progress.add_task("Starting", total=len(ShadowTraceApp.STEP_NAMES))

            def on_step(index: int, total: int, name: str) -> None:
                progress.update(task, description=name, completed=index)

            result = app_runner.run(on_step)
        report_paths: list[Path] = []
        report_error: Optional[str] = None
        try:  # 1. save the reports first, regardless of any later answer
            report_paths = ReportGenerator(config).write(result, config.report_format, config.output_dir)
        except ReportError as exc:
            report_error = str(exc)
            report_paths = exc.written
        ui.show_summary(result, report_paths, report_error)  # 2. then the summary
        if list_processes:
            ui.show_processes(result.processes)
        if report_error:
            raise typer.Exit(code=3)
        html_path = next((p for p in report_paths if p.suffix == ".html"), None)
        offer_to_view_report(  # 3. only now ask; the browser opens only after a Yes
            html_path, no_prompt=no_prompt,
            print_fn=lambda message: ui.console.print(message, markup=False, soft_wrap=True))

    @app.command()
    def info() -> None:
        """Show version, platform compatibility, capabilities and limitations."""
        ui = ConsoleUI()
        ui.banner()
        ui.show_info()

    @app.command()
    def modes() -> None:
        """Explain exactly what each scan mode checks and what it omits."""
        ui = ConsoleUI()
        ui.banner()
        ui.show_modes()

    @app.command()
    def rules(
        details: Annotated[bool, typer.Option("--details", help="Show explanations and false-positive notes.")] = False,
    ) -> None:
        """List the detection rules and explain what each one checks."""
        ui = ConsoleUI()
        ui.banner()
        ui.show_rules(details)

    @app.command()
    def reports(
        output: Annotated[Path, typer.Option("--output", "-o", help="Output location used for scans.")] = Path("reports"),
        open_report: Annotated[Optional[str], typer.Option(
            "--open", help="Open a saved HTML report: its number in the list (1 = newest) or a path to a .html file.")] = None,
        limit: Annotated[int, typer.Option("--limit", min=1, help="Maximum number of scans to list.")] = 50,
    ) -> None:
        """List saved reports (newest first) or open one explicitly, without running a scan."""
        ui = ConsoleUI()
        entries = list_report_history(output)
        if open_report is None:
            ui.show_history(entries[:limit], resolve_reports_root(output))
            return
        target: Optional[Path] = None
        if open_report.isdigit():
            index = int(open_report)
            if index < 1 or index > len(entries):
                ui.console.print(f"No saved report number {open_report}. Run 'reports' to see the list.", markup=False)
                raise typer.Exit(code=1)
            target = entries[index - 1].html
            if target is None:
                ui.console.print("That scan has no HTML report (it was saved as JSON/Markdown only).", markup=False)
                raise typer.Exit(code=1)
        else:
            target = Path(open_report)
        ok, reason = open_report_in_browser(target)
        if ok:
            ui.console.print(f"Opening {target} in your default browser.", markup=False, soft_wrap=True)
            return
        ui.console.print(f"Could not open the report automatically ({reason}).", markup=False)
        ui.console.print(f"Open it manually: {target}", markup=False, soft_wrap=True)
        raise typer.Exit(code=1)

    return app


def missing_dependencies() -> list[str]:
    """Names of required third-party packages that failed to import."""
    missing = []
    if psutil is None:
        missing.append("psutil")
    if typer is None:
        missing.append("typer")
    if Console is None:
        missing.append("rich")
    return missing


def main() -> None:
    """Entry point: validate the environment, then run the CLI."""
    if sys.version_info < MIN_PYTHON:
        sys.stderr.write(f"ShadowTrace requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer "
                         f"(found {platform.python_version()}).\n")
        raise SystemExit(2)
    missing = missing_dependencies()
    if missing:
        sys.stderr.write(
            f"ShadowTrace needs these packages: {', '.join(missing)}.\n"
            f"Install them with:  python -m pip install {' '.join(missing)}\n"
            "(or: python -m pip install -r requirements.txt)\n"
        )
        raise SystemExit(2)
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (OSError, ValueError):
                pass  # stream cannot be reconfigured; output may show replacement characters
    build_cli()()


if __name__ == "__main__":
    main()
