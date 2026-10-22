# ShadowTrace — Technical Reference

This document complements the [README](README.md). The README is the beginner-friendly overview and setup guide; this file records the implementation's detection scope, operating assumptions, report structure, rule catalogue, scoring model, and technical limitations.

ShadowTrace is a manual, one-shot, read-only Windows assessment tool. It collects selected system evidence and applies documented heuristics; it is not an antivirus engine and cannot prove a system is clean. Treat findings as investigation leads, not automatic diagnoses.

## Contents

- [What it does and does not do](#what-it-does-and-does-not-do)
- [Safety guarantees](#safety-guarantees)
- [Runtime requirements](#runtime-requirements)
- [Permissions](#permissions)
- [Scan modes](#scan-modes)
- [Commands and options](#commands-and-options)
- [After the scan: view the report?](#after-the-scan-view-the-report)
- [Reports: location, names, history, redaction](#reports-location-names-history-redaction)
- [JSON report schema](#json-report-schema)
- [Findings, severity and scoring](#findings-severity-and-scoring)
- [Detection rules](#detection-rules)
- [Known-hash lists](#known-hash-lists)
- [Privacy](#privacy)
- [Validation status](#validation-status)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)

## What it does and does not do

ShadowTrace inspects, in read-only fashion: running processes; files and scripts (hashes, script patterns, keyboard-API names, executable headers); startup persistence (registry autoruns, Winlogon, execution-hijack settings, Startup folders, services, scheduled tasks, WMI event subscriptions); kernel driver services; security configuration (Secure Boot, memory integrity, LSA protection, boot-integrity options, Defender policy and exclusions); PowerShell script-block log evidence; and Microsoft Defender status and detection history.

It **cannot** reliably detect kernel-level rootkits, firmware or hardware keyloggers, or malware that hides from software running inside Windows. It does not enumerate keyboard hooks (Windows has no documented API for that). It never removes or fixes anything: if you need remediation it tells you what to do with a trusted security product.

## Safety guarantees

- Manual, one-shot and read-only: no deleting, quarantining, renaming or moving files; no terminating, suspending or injecting into processes; no registry, service, task or security-setting changes; no driver loading; no persistence or background service.
- Nothing suspicious is ever executed. Files are only read, hashed and pattern-matched as text or bytes.
- No keystroke capture and no credential collection.
- No network access and no uploads: the program imports no networking library and never contacts a server. Reports stay on your disk; opening one in your browser only happens after you answer Yes.
- The only external programs started are three fixed, read-only Windows tools (PowerShell cmdlets, wevtutil, bcdedit) by absolute path, never through a shell and never with user-supplied text.
- Secrets in command lines are redacted and long values truncated before they reach a report; --redact also masks your user and computer names (best effort - review reports before sharing them).

The three external tools ShadowTrace may start (only on Windows, by absolute path from the Windows directory as reported by the Windows API (never an environment variable or a guess; if it cannot be determined nothing is launched and the checks are reported as skipped), never through a shell, never with user-supplied text, always with a timeout) are listed in `FIXED_COMMANDS`: PowerShell (read-only `Get-MpComputerStatus`, `Get-MpThreat`, `Get-MpThreatDetection`, `Get-CimInstance`), `wevtutil qe` (PowerShell script-block events) and `bcdedit /enum {current}`.

## Runtime requirements

- **Target OS:** Windows 10 or Windows 11.
- **Python:** 64-bit Python 3.11 or newer is required by the code. The README's Python 3.12 recommendation is a straightforward version to install. A 32-bit Python on 64-bit Windows can be affected by file-system redirection and make some `System32` paths appear missing.
- **Runtime dependencies:** `psutil`, `typer`, and `rich`, installed using the versions constrained in `requirements.txt`.
- **Other operating systems:** not supported for real assessments. `scan --allow-non-windows` exists only for limited development and diagnostic use; its output must not be interpreted as a Windows assessment.

For beginner-friendly installation and the first scan, follow the steps in the [README](README.md). The commands below are a compact reference for technical readers:

```powershell
python shadowtrace.py info
python shadowtrace.py scan
python shadowtrace.py scan --mode quick
python shadowtrace.py scan --mode dormant
python shadowtrace.py scan --mode malware --path C:\Users\you\Downloads --hash-list my-hashes.txt
python shadowtrace.py reports
python shadowtrace.py reports --open 1
```

## Permissions

ShadowTrace works without administrator rights and clearly marks what it could not read. Run the terminal **as Administrator** for fuller visibility.

| Needs administrator for full results | Why |
|---|---|
| Scheduled tasks, WMI subscriptions | Windows restricts these stores |
| Defender exclusions, tamper protection, detection history | Protected by Windows |
| Boot options (`bcdedit`) | Requires elevation |
| Some processes' paths and command lines | Protected processes |

Skipped, partial and failed checks appear in the report under **Could not be assessed**; they are never silently dropped or presented as "clean".

## Scan modes

Every mode is manual, one-shot, read-only and exits when done. `--quick` still works and means `--mode quick`; a scan with no mode option is a `full` scan. `--path` files are analysed in any mode. Run `python shadowtrace.py modes` for the same information in the terminal.

| Mode | Purpose | Checks | Omits |
|---|---|---|---|
| `quick` | Common keylogger indicators: running processes plus the highest-value persistence locations. | Running-process inventory, Registry startup keys, Startup folders | No hashing or file-content inspection, services, scheduled tasks, WMI, drivers, security settings, Defender or event logs. |
| `full` (default) | The broadest practical inspection: processes, files, every supported persistence location, services, scheduled tasks, WMI, drivers, security settings, Defender and PowerShell event-log evidence. | Running-process inventory, Registry startup keys, Registry execution-hijack settings, Startup folders, Auto-start Windows services, Scheduled tasks, WMI event subscriptions, Kernel drivers, Security settings, Suspicious-file sweep, Microsoft Defender status, Microsoft Defender detection history, PowerShell event-log evidence | Still bounded: no whole-drive scans, no memory or network inspection, no signature trust validation. |
| `malware` | Suspicious-file analysis: hashes, script and executable heuristics, known-hash lists you supply, plus available Microsoft Defender findings. | Running-process inventory, Registry startup keys, Startup folders, Auto-start Windows services, Scheduled tasks, Suspicious-file sweep, Microsoft Defender status, Microsoft Defender detection history | No drivers, security-setting review, WMI, registry hijack settings or event logs. |
| `rootkit` | Driver, kernel-related service and security-configuration indicators, plus a service cross-view check. | Auto-start Windows services, Kernel drivers, Security settings, Microsoft Defender status | No process, startup-folder, scheduled-task or WMI inspection. A rootkit that hides itself from software running inside Windows cannot be ruled out. |
| `dormant` | Threats that are not running now: autoruns, services, scheduled tasks, WMI subscriptions, execution-hijack settings and available PowerShell history. | Registry startup keys, Registry execution-hijack settings, Startup folders, Auto-start Windows services, Scheduled tasks, WMI event subscriptions, PowerShell event-log evidence | No running-process inventory, drivers, security settings or Defender. Event-log history depends on Windows logging being enabled. |

| Check | `quick` | `full` | `malware` | `rootkit` | `dormant` |
|---|---|---|---|---|---|
| Running-process inventory | yes | yes | yes | - | - |
| Registry startup keys | yes | yes | yes | - | yes |
| Registry execution-hijack settings | - | yes | - | - | yes |
| Startup folders | yes | yes | yes | - | yes |
| Auto-start Windows services | - | yes | yes | yes | yes |
| Scheduled tasks | - | yes | yes | - | yes |
| WMI event subscriptions | - | yes | - | - | yes |
| Kernel drivers | - | yes | - | yes | - |
| Security settings | - | yes | - | yes | - |
| Suspicious-file sweep | - | yes | yes | - | - |
| Selected file analysis | with `--path` | with `--path` | with `--path` | with `--path` | with `--path` |
| Microsoft Defender status | - | yes | yes | yes | - |
| Microsoft Defender detection history | - | yes | yes | - | - |
| PowerShell event-log evidence | - | yes | - | - | yes |
| Detection rules | always | always | always | always | always |
| Risk scoring | always | always | always | always | always |

Time limits per mode: quick 45 s, full 300 s, malware 300 s, rootkit 180 s, dormant 240 s (override with `--max-seconds`). Hashing and inspection also respect per-scan file-count, file-size and sweep limits (see `ShadowTraceConfig`). A single blocking Windows call (for example a stalled network drive) cannot be interrupted, so the time limit is a budget checked between operations, **not** a hard real-time guarantee.

## Commands and options

| Command | Purpose |
|---|---|
| `scan` | Run a scan (options below) |
| `modes` | What each mode checks and omits |
| `rules [--details]` | The detection rules, explanations and false-positive notes |
| `reports [--output DIR] [--open N or PATH] [--limit N]` | List saved reports, or open one explicitly |
| `info` | Version, platform, dependencies, capabilities, limitations |

`scan` options: `--mode/-m` (quick, full, malware, rootkit, dormant), `--quick`, `--output/-o DIR` (default `reports`), `--format/-f` (`html`, `json`, `markdown`, `both` = html+json (default), `all`), `--path/-p FILE_OR_DIR` (repeatable), `--hash-list FILE` (repeatable), `--telemetry` (add the Defender status check in any mode), `--no-defender` (never query Defender), `--redact`, `--no-prompt` / `--no-open`, `--max-seconds N`, `--list-processes`, `--allow-non-windows`, `--verbose`.

Exit codes: `0` completed, `1` a `reports` request could not be satisfied, `2` unsupported platform, bad option or missing dependency, `3` the scan completed but the report could not be saved (the results are still printed).

## After the scan: view the report?

The order is fixed: **scan, save the reports, show the summary, then ask**.

```
Scan complete. Would you like to view the report now? [Y/N]
```

- The reports are already saved before you are asked, whatever you answer.
- **Yes** (`Y`, `yes`, any case) opens the saved HTML report in your default browser. **No** leaves it saved and exits. Anything else re-asks (after 5 invalid answers it stops asking).
- Nothing opens before you agree. Opening a local `.html` file sends nothing anywhere; the report contains no scripts and no external resources.
- EOF, Ctrl+C and non-interactive runs (redirected input, CI) never hang: ShadowTrace skips the question and prints the report path. `--no-prompt` (alias `--no-open`) skips it explicitly.
- If opening fails, the exact path is shown with manual instructions.

## Reports: location, names, history, redaction

Reports go to `<output>/reports/MM-DD-YYYY/` (an `--output` that is already named `reports` is not nested again), for example `reports/10-16-2026/ShadowTrace_Report_143025.html` and `.json`. Dates inside reports and the terminal use `MM/DD/YYYY`. Names are `ShadowTrace_Report_HHMMSS` with a `_2`, `_3`, ... suffix when a scan finishes in the same second as another; files are created exclusively, so **existing reports are never overwritten** (and ShadowTrace never deletes old reports).

`python shadowtrace.py reports` lists scans grouped by date, newest first, with time, mode and file paths; `reports --open N` opens the HTML report of entry *N* without scanning.

Reports can contain local paths, command lines and user or computer names. **Review a report before sharing it.** `--redact` masks the current user and computer names and Windows profile folder names on a best-effort basis; it does not guarantee that all sensitive data is removed. Secrets in command lines (passwords, tokens, credentials in URLs, long opaque values) are redacted at collection time regardless.

The HTML report shows: scan date, mode, duration and coverage; counts by severity, status and type; findings grouped as **confirmed detections**, **suspicious indicators** and **informational findings**, each with exact artifact locations, evidence, why it was flagged, confidence, detection method, recommended next step and false-positive notes; **checks that failed, were skipped or were only partly possible**; limitations; and a warning that no findings do not guarantee a clean system. The JSON report carries the same information for tools.

## JSON report schema

`schema_version` `2.0`. Field names are stable within a schema version; new fields may be added, existing ones will not change meaning.

| Field | Content |
|---|---|
| `schema_version`, `tool`, `version` | Report format and ShadowTrace version |
| `report` | `scan_id`, `date` (MM/DD/YYYY), `folder_date` (MM-DD-YYYY), `redacted`, `generated_locally` (true), `network_used` (false) |
| `scan` | `started_at` (UTC), `started_local`, `finished_at`, `duration_seconds`, `mode`, `mode_summary`, `mode_omits`, `elevated`, `operating_system`, `python_version` |
| `summary` | Counts (`processes_examined`, `files_hashed`, `files_inspected`, `startup_entries_examined`, `files_analyzed`, `drivers_examined`, `settings_observed`, `findings`) plus `by_severity`, `by_status`, `by_category` |
| `coverage` | Check IDs grouped by status: `completed`, `partial`, `skipped`, `failed`, `not_in_mode` |
| `checks[]` | `name`, `label`, `status`, `detail`, `items` |
| `score` | `total` (0-100), `band`, `interpretation`, `groups[]`, `insufficient_evidence`, `coverage_notes[]`, `method`, `disclaimer` |
| `findings[]` | `finding_id`, `rule_id`, `category`, `title`, `severity`, `confidence`, `confidence_note`, `status` (`confirmed` / `suspicious` / `informational`), `detection_method` (`heuristic` / `known-hash` / `security-product`), `subject`, `related_subjects[]`, `artifacts[]` (exact locations), `evidence[]`, `explanation`, `recommendation`, `limitations`, `limiting_factors[]`, `source_check`, `counted_in_score`, `shares_evidence_with[]`, `evidence_key` |
| `processes[]`, `startup_entries[]`, `drivers[]`, `security_settings[]`, `event_evidence[]`, `defender_detections[]`, `files[]`, `telemetry[]`, `service_view_mismatches[]` | The collected data |
| `known_hash_list` | Description of the lists you supplied |
| `notes[]`, `limitations[]`, `not_inspected[]`, `conclusion` | Honest framing |

All text is valid UTF-8 JSON; unusual characters and lone surrogates in file names are replaced rather than breaking the file. Nothing is fabricated: absent data is `null`, empty, or listed under `coverage`.

## Findings, severity and scoring

**Status** separates what kind of statement a finding is:

| Status | Meaning |
|---|---|
| `confirmed` | A reliable source matched: a known-hash entry from a list you supplied (ST-M003), the EICAR test file (ST-M004), or Microsoft Defender's own detection history (ST-A001). Not "ShadowTrace scanned it". |
| `suspicious` | A heuristic matched. A lead to verify, never proof. |
| `informational` | Context or hardening information. Not scored. |

**Severity scheme**

| Severity | Meaning |
|---|---|
| `CRITICAL` | Confirmed by reliable evidence (known-hash match, active Defender threat) |
| `HIGH` | Strong, uncommon indicator that needs prompt review (not proof) |
| `MEDIUM` | Notable indicator worth reviewing |
| `LOW` | Weak or contextual signal; often benign |
| `INFO` | Context only; contributes no points |

**Confidence** (`LOW`, `MEDIUM`, `HIGH`) says how well the observed evidence supports the interpretation. **Detection method** is `heuristic`, `known-hash` or `security-product`; ShadowTrace ships no malware signatures.

**Score.** Points = severity (INFO 0, LOW 4, MEDIUM 15, HIGH 35, CRITICAL 60) x confidence multiplier (LOW 0.5, MEDIUM 0.8, HIGH 1.0). Findings resting on the same underlying evidence count once (strongest wins); groups are summed strongest-first with each further group weighted x0.75; capped at 100. Bands: 0 none, 1-14 low, 15-34 moderate, 35-59 elevated, 60+ high. **The score is not the probability that a computer is infected and not a malware verdict.** When key checks cannot run or most processes are unreadable, the report says the evidence is insufficient.

Deliberately *not* treated as suspicious on their own: an unsigned or unfamiliar file, a file in a user-writable folder (the file sweep reports content, never location alone), Microsoft-provided scheduled tasks, and programs in Program Files that happen to reference keyboard APIs.

## Detection rules

38 rules. `python shadowtrace.py rules --details` shows each rule's explanation, next step and false-positive notes.

| ID | Severity (default) | Status | Method | Title |
|---|---|---|---|---|
| ST-P001 | MEDIUM | suspicious | heuristic | Process running from a low-trust or user-writable location |
| ST-P002 | MEDIUM | suspicious | heuristic | Running process whose executable file no longer exists |
| ST-P003 | HIGH | suspicious | heuristic | Windows system process name running outside its expected folder |
| ST-P004 | MEDIUM | suspicious | heuristic | Executable name uses a deceptive double extension |
| ST-P005 | LOW | suspicious | heuristic | Process name looks randomly generated |
| ST-P006 | HIGH | suspicious | heuristic | System process started by an unexpected parent |
| ST-P007 | MEDIUM | suspicious | heuristic | Office application started a script host or shell |
| ST-P008 | MEDIUM | suspicious | heuristic | PowerShell started with an encoded command or hidden window |
| ST-P009 | INFO | suspicious | heuristic | Many instances of the same executable |
| ST-S001 | LOW | suspicious | heuristic | Startup entry points to a file that does not exist |
| ST-S002 | MEDIUM | suspicious | heuristic | Startup entry runs a program from a low-trust location |
| ST-S003 | LOW | suspicious | heuristic | Startup entry launches a script host or system utility |
| ST-S004 | LOW | suspicious | heuristic | Executable or script placed directly in a Startup folder |
| ST-S005 | HIGH | suspicious | heuristic | Winlogon Shell or Userinit differs from the Windows default |
| ST-F001 | LOW | suspicious | heuristic | Executable or script stored in a low-trust location |
| ST-F002 | MEDIUM | suspicious | heuristic | Executable content hidden behind a document or media extension |
| ST-F003 | MEDIUM | suspicious | heuristic | File name uses a deceptive double extension |
| ST-T001 | INFO | suspicious | heuristic | Microsoft Defender real-time protection reported as off |
| ST-T002 | INFO | suspicious | heuristic | Microsoft Defender reported as unavailable, disabled or out of date |
| ST-P010 | MEDIUM | suspicious | heuristic | Process command line shows obfuscation or download-and-execute patterns |
| ST-S006 | MEDIUM | suspicious | heuristic | Startup command shows obfuscation or download-and-execute patterns |
| ST-S007 | MEDIUM | suspicious | heuristic | Execution-hijack or auto-run registry setting is configured |
| ST-D001 | MEDIUM | suspicious | heuristic | Hidden scheduled task with a suspicious action |
| ST-W001 | MEDIUM | suspicious | heuristic | WMI event consumer that runs commands or scripts |
| ST-M001 | MEDIUM | suspicious | heuristic | Script file contains obfuscation or download-and-execute patterns |
| ST-M002 | LOW | suspicious | heuristic | Executable references keyboard-capture API names |
| ST-M003 | CRITICAL | confirmed | known-hash | File hash matches your supplied known-hash list |
| ST-M004 | LOW | confirmed | known-hash | Standard antivirus test file (EICAR) found |
| ST-R001 | HIGH | suspicious | heuristic | Kernel driver service points to a user-writable location |
| ST-R002 | LOW | suspicious | heuristic | Auto-start driver whose file is missing |
| ST-R003 | LOW | suspicious | heuristic | Driver outside standard folders without an embedded signature |
| ST-R004 | MEDIUM | suspicious | heuristic | Service visible in the service manager but missing from the registry |
| ST-R005 | MEDIUM | suspicious | heuristic | Driver signature enforcement or integrity checks appear relaxed |
| ST-R006 | MEDIUM | suspicious | heuristic | Microsoft Defender disabled by policy |
| ST-R007 | MEDIUM | suspicious | heuristic | Defender exclusion covers a user-writable or very broad location |
| ST-R008 | INFO | suspicious | heuristic | Security hardening feature not enabled |
| ST-E001 | MEDIUM | suspicious | heuristic | PowerShell script-block log shows suspicious patterns |
| ST-A001 | HIGH | confirmed | security-product | Microsoft Defender reports a detected threat |

## Known-hash lists

`--hash-list FILE` reads a local text file: one SHA-256 per line, optionally followed by `,label`; lines starting with `#` are comments; malformed lines are counted and ignored. Matches are reported as **confirmed** (ST-M003). The result is only as reliable as your list, and a missing match proves nothing. The file is never uploaded and no online lookups exist.

## Privacy

- Everything stays local. No telemetry, no automatic network lookups, no uploads; the program imports no networking library.
- No hashes, paths, user names, command lines or reports are transmitted anywhere. Opening a report in your browser happens only after you answer Yes (or run `reports --open`) and loads a local file with no external resources.
- Online reputation checks are **not implemented**. If you want one, look up a hash yourself; ShadowTrace will not do it for you. The `--telemetry` CLI option is a legacy name for an optional local Microsoft Defender status check; it does not send telemetry to a server. `--no-defender` disables Defender queries.
- Reports are sensitive. See [Reports](#reports-location-names-history-redaction) for redaction and review advice. Keep `reports/` out of version control (the supplied `.gitignore` does).

## Validation status

The development process used an automated test suite that simulates Windows components and static source checks. Those development tests are **not included in this public repository**. Testing on real Windows systems has been limited, so passing simulated tests should not be confused with exhaustive validation across Windows versions, configurations, privilege levels, or security products.

The tool can also run in a limited non-Windows development mode, but that mode does not validate Windows-specific collection. For any result, read the report's coverage section and pay attention to checks marked `skipped`, `partial`, or `failed`.

## Limitations

- ShadowTrace is a user-mode, point-in-time assessment. It cannot reliably detect kernel-level rootkits, firmware or hardware keyloggers, or malware that hides from software running inside Windows.
- Windows has no documented API for listing which processes installed keyboard hooks, so ShadowTrace does not claim to detect hooks or keystroke capture; ST-M002 only notes API names found inside files.
- Signature trust is not validated (no WinVerifyTrust, to avoid revocation lookups over the network); only the presence of an embedded certificate table is read. Unsigned does not mean malicious; signed does not mean safe.
- No malware signatures or online reputation lookups are included. Known-hash detections only happen for lists you supply with --hash-list and for the harmless EICAR test file.
- Defender history can include already-remediated items, and reading it is not the same as running a scan.
- Event-log evidence depends on logging being enabled and on the log not having rotated.
- Run as Administrator for fuller visibility (WMI, scheduled tasks, Defender exclusions, boot options and many processes need it). Skipped checks are listed in the report.
- Bounded work: time, file-size, file-count and per-check limits apply. A single blocking Windows call (for example a stalled network drive) cannot be interrupted, so the time limit is not a hard real-time guarantee.
- Services hosted by svchost are reported by their command line, not by the DLL they load. Browser extensions, memory contents and network traffic are not inspected.
- Cross-view (hidden-object) checks are limited to service/driver names; no independent user-mode view of processes exists that could reveal a hidden process reliably.
- A clean result is not proof the computer is clean, and a flagged item is not proof of infection.

Not inspected:

- Process memory, loaded modules and keyboard-hook tables
- Firmware, boot sector and kernel memory (a hidden rootkit may not be visible at all)
- Browser extensions and per-application plug-ins
- Network connections, DNS and traffic
- Active Setup, Shell extensions and other less common autostart locations
- Files outside the documented locations and any --path values
- Windows event logs other than PowerShell script-block (4104) events

If ShadowTrace flags something serious, use a trusted security product. For a suspected rootkit, use trusted offline or specialist forensic tools: a sophisticated kernel-level rootkit can hide from any scanner running inside the compromised operating system. You can start Microsoft Defender scans yourself (Windows Security > Virus & threat protection > Scan options, including Microsoft Defender Antivirus (offline scan)); ShadowTrace never starts scans or remediation.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ShadowTrace needs these packages: ...` | `python -m pip install -r requirements.txt` |
| `scan` says ShadowTrace targets Windows | Run it on Windows (`--allow-non-windows` is for development only) |
| Many checks show `skipped` or `partial` | Run the terminal as Administrator and re-run |
| System32 files reported missing | You are on 32-bit Python; install 64-bit Python |
| Prompt never appears | Input/output is redirected (non-interactive); use `reports --open 1` |
| Browser did not open | Open the printed path manually, or `reports --open 1` |
| Defender checks `skipped` | Defender may be absent or managed by another product; use `--no-defender` to silence them |
| Report could not be written (exit code 3) | Check the `--output` path and permissions; results are still printed |
| Antivirus quarantines a file during testing | ShadowTrace does not contain the EICAR string (only its hash); quarantined fixtures come from elsewhere |

## Project layout

```
shadowtrace.py      the complete tool (single file)
requirements.txt    the three runtime dependencies (psutil, typer, rich)
README.md           beginner-friendly overview and setup guide
TECHNICAL.md        detailed detection and report reference
.gitignore          keeps scan reports and local environments out of git
```
