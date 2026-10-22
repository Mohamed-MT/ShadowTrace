# ShadowTrace

**A free Windows tool that checks your computer for signs of spyware, keyloggers and other unwanted software, then gives you a plain-English report. It only looks. It never changes, deletes or uploads anything.**

> **Project status:** finished and not maintained. This is a personal portfolio project, so there is no support and no updates are planned.

## What it is

Think of ShadowTrace as a careful home inspector for your PC. It checks the places where unwanted software likes to hide, such as programs running right now, programs set to start by themselves, scheduled jobs and some security settings. Then it writes a report that explains **what looked unusual, why it matters, and what you could do next.**

It is a second opinion, and that's all. Two things to keep in mind:

- **It is not antivirus.** It doesn't clean or protect your computer, and it doesn't replace Windows Security.
- **"Nothing found" does not mean "your computer is clean."** Some threats hide from tools like this one, and every report says so.

A finding is a question, not an accusation. Perfectly normal software can look a little unusual, so don't panic and don't delete things just because they appear in a report. Only use it on computers you own or have permission to check.

## Why I built it

I'm a cybersecurity student, and I wanted a hands-on project that goes beyond reading about threats. I started with one idea: a keylogger detector. I didn't know how detection would work, so I began by researching how keyloggers operate and what traces they leave behind: where they hide, how they restart themselves, and how they send data out.

That research showed me that no single check can reliably catch a keylogger, so I widened the project into a broader tool. It now looks at many kinds of warning signs and weighs them together. I also set myself some rules from the start: it must never change anything on the computer it inspects, it must never touch the internet, and it must be honest about what it can't see.

## How it works

1. **Collect.** It gathers facts about your computer: running programs, startup items, scheduled tasks, services, drivers, selected security settings and Microsoft Defender's own history.
2. **Judge.** It applies 38 clearly documented rules to those facts. Each rule looks for one specific kind of unusual evidence, for example a Windows system program running from the wrong folder.
3. **Weigh.** Each finding gets a severity and a confidence level. Repeated evidence about the same thing is only counted once, and a score summarises the overall picture. The score is a guide, not a diagnosis.
4. **Report.** It saves an HTML report (for reading) and a JSON report (for other tools), then asks whether you'd like to open it.

### Scan modes

| Mode | What it's for |
|---|---|
| `quick` | A fast check of running programs and the most common startup locations |
| `full` (default) | The broadest check: everything below, within sensible time and size limits |
| `malware` | Suspicious files and scripts, plus anything Microsoft Defender has reported |
| `rootkit` | Drivers and security settings, where deep-hiding threats often leave traces |
| `dormant` | Things that aren't running now but are set to run later: startup items, scheduled tasks, hidden triggers |

## Is it safe to run?

By design, yes:

- **It only reads.** It doesn't delete, move, change, stop, disable or install anything on your computer.
- **It never uses the internet.** Nothing is sent anywhere, and there is no tracking.
- **The only thing it creates is its own report files**, in a `reports` folder next to the program. It never overwrites an earlier report.
- **It's one readable file** (`shadowtrace.py`), so you can see exactly what it does.
- **A report only opens in your browser if you say Yes** to a question at the end.

## Getting started

You need a Windows 10 or 11 computer and Python, a free installer that ShadowTrace runs on.

**Step 1. Install Python.** Go to [python.org/downloads](https://www.python.org/downloads/windows/), download a 64-bit **Python 3.12** installer, and run it. On the first screen, **tick "Add python.exe to PATH"**, then click *Install Now*.

**Step 2. Download ShadowTrace.** On this page, click the green **Code** button, then **Download ZIP**. Right-click the ZIP file and choose **Extract All**.

**Step 3. Open PowerShell in that folder.** Open the extracted folder (the one containing `shadowtrace.py`), click the address bar at the top, type `powershell` and press Enter.

**Step 4. Install the three helper libraries** (once only):

```
python -m pip install -r requirements.txt
```

**Step 5. Run a quick check:**

```
python shadowtrace.py scan --mode quick
```

A progress bar runs, the report is saved, a summary appears, and then you'll see:

```
Scan complete. Would you like to view the report now? [Y/N]
```

Type `Y` and press Enter to open the report in your browser, or `N` to skip. Either way the report is already saved in the `reports` folder, in a sub-folder named with the date.

**Step 6. For a deeper check, run as administrator.** Open the Start menu, type **PowerShell**, right-click it and choose **Run as administrator**. Go to your folder (type `cd ` followed by the folder's path) and run `python shadowtrace.py scan`. Administrator rights let it look in more places, such as scheduled tasks. A full scan takes a few minutes at most.

> If Windows says `python` isn't recognised, type `py` instead. If that fails too, reinstall Python with the "Add python.exe to PATH" box ticked.

## Reading your report

Start at the top and work down:

- **Summary** shows findings in three kinds: **Confirmed** (a trusted source such as Microsoft Defender reported it; look at these first), **Suspicious** (unusual and worth a look, though often harmless) and **Informational** (background facts, not problems).
- **Coverage** and **Could not be assessed** list what ShadowTrace couldn't check, usually because it wasn't run as administrator. Many gaps mean the report tells you less.
- **Findings** explain each item: what was seen, why it matters, how confident the tool is, **what harmless things can cause it**, and a suggested next step.

Colours run from red (look first) through orange and blue to grey (just information).

**If something worries you:** don't delete files you don't recognise. Look the name up first, or ask someone you trust. You can run a Microsoft Defender scan yourself (Windows Security → Virus & threat protection → Scan options; try *Microsoft Defender Antivirus (offline scan)* for stubborn problems). If you think your computer is seriously compromised, ask a professional for help.

**Before sharing a report**, read it first. It can contain your computer name, user name and file locations. Adding `--redact` to a scan hides your user and computer names, but it can't guarantee everything is hidden.

## Handy commands

| What you want | Command |
|---|---|
| Fast check | `python shadowtrace.py scan --mode quick` |
| Thorough check (default) | `python shadowtrace.py scan` |
| Suspicious files and scripts | `python shadowtrace.py scan --mode malware` |
| Things set to run later | `python shadowtrace.py scan --mode dormant` |
| Drivers and security settings | `python shadowtrace.py scan --mode rootkit` |
| Add a folder to the file check | add `--path "C:\path\to\folder"` |
| Hide your names in the report | add `--redact` |
| Skip the "view report?" question | add `--no-prompt` |
| List saved reports | `python shadowtrace.py reports` |
| Reopen your newest report | `python shadowtrace.py reports --open 1` |
| See what each mode checks | `python shadowtrace.py modes` |
| Explain every rule | `python shadowtrace.py rules --details` |

## Common problems

| What you see | What to do |
|---|---|
| `python is not recognized` | Use `py` instead, or reinstall Python with "Add python.exe to PATH" ticked |
| Messages about missing packages | Run `python -m pip install -r requirements.txt` again |
| Many checks say "skipped" or "partial" | Run PowerShell as administrator (Step 6) |
| The report didn't open | Open the file path shown on screen in your browser, or run `reports --open 1` |

To remove ShadowTrace, delete its folder. To also remove the helper libraries: `python -m pip uninstall psutil typer rich`.

## For technical readers

ShadowTrace is a single Python file built on `psutil` (process data), `typer` (command line) and `rich` (terminal display). The design choices I care most about:

- **Read-only by construction.** No code path deletes, renames, terminates or edits anything on the scanned system. Files are opened only for reading, plus one exclusive-create call that writes new reports without overwriting old ones.
- **Fails closed.** The only external programs it can start are three built-in Windows tools (read-only PowerShell queries, `wevtutil`, `bcdedit`), always by absolute path from the Windows directory *as reported by Windows itself*, never through a shell, never with user-supplied text, always with a timeout. If Windows can't report that directory, nothing is launched and the checks are marked skipped.
- **No network, no telemetry.** It imports no networking library, and the HTML report contains no scripts or external resources.
- **Honest output.** Findings are labelled confirmed, suspicious or informational; the score is explicitly not a probability of infection; skipped or partial checks are shown instead of hidden; "no findings" is never presented as "clean."
- **Evidence over alarm.** Being unsigned, unfamiliar or in a user-writable folder is deliberately not treated as suspicious on its own, and the same evidence is never counted twice.
- **Careful with untrusted input.** Secrets in command lines are redacted, XML containing entity declarations is rejected, regular expressions are bounded, and all work is limited by time, file size and file count.

I developed it with an automated test suite that simulates Windows (registry, scheduled tasks, services, Defender and so on) plus static security checks of the source. It has had limited testing on real Windows computers, so expect the occasional rough edge. If a check can't run, the report says so.

## What it can't do

It can't see threats that hide deep inside Windows or in hardware, and it can't prove a computer is clean. It doesn't inspect your network, browser extensions or the contents of memory. It never goes online, so it has no virus database of its own: its "confirmed" results come only from Microsoft Defender's history or from lists of file fingerprints you choose to supply with `--hash-list`.

## In this repository

```
shadowtrace.py     the whole tool
requirements.txt   the three libraries it needs
README.md          this guide
.gitignore         keeps scan reports out of version control
```

*Provided as-is, without warranty. ShadowTrace is not a substitute for antivirus software or professional security advice.*
