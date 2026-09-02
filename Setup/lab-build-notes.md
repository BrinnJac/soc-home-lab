# Lab Build Notes

Not a tutorial. This is a record of what broke while building the lab and how
each problem was diagnosed — mostly because almost every failure was silent, and
working out *that* something had failed turned out to be harder than fixing it.

---

## What got built

| Component | Detail |
|---|---|
| Hypervisor | VirtualBox on a Windows host |
| SIEM | Wazuh 4.14.7, deployed from the official OVA appliance |
| Monitored endpoint | Windows 11 evaluation VM, Wazuh agent + Sysmon |
| Sysmon config | SwiftOnSecurity `sysmonconfig-export.xml` |
| Attack simulation | Atomic Red Team (`Invoke-AtomicRedTeam`) |
| Network | VirtualBox Host-only, `192.168.56.0/24` |

**Retention note:** this Wazuh install keeps only events that match a rule.
`<logall>` and `<logall_json>` are both `no` by default, and
`/var/ossec/logs/archives/archives.log` is empty — nothing has ever been archived.
Everything that doesn't trigger a rule is evaluated and discarded at the manager,
so the Events view reads the alerts index rather than a raw event store. Detection
and retention are the same thing in this configuration; there is no retrospective
hunting. Found while investigating a zero-event result in the T1033 writeup.

Also present but unused so far: a Kali VM (for later network-based attacks) and
two Ubuntu VMs held in reserve as future monitored endpoints.

**Note on the Windows endpoint.** It runs a 90-day evaluation licence. Anyone
reproducing this will need to rebuild the VM when it expires, and the agent will
need re-registering with the manager afterward.

## Deploying the Wazuh appliance

Wazuh was deployed from the official pre-built OVA rather than installed
manually. This is the route the Wazuh documentation recommends for evaluation,
and it removes an entire category of setup problems — the manager, indexer, and
dashboard arrive already installed and configured together.

Followed along with: https://www.youtube.com/watch?v=ZsXQXUYFLoI

Steps taken:

- Imported via **File → Import Appliance** in VirtualBox (the `.ova` format
  requires this rather than the Add button, which expects `.vbox`)
- Allocated 8192 MB RAM and 4 CPUs
- Set my own credentials for the appliance's Linux account; left the Wazuh
  **dashboard** login at its default initially, changed later (see below)
- Dashboard reached over HTTPS from the host browser at the appliance's IP,
  accepting the self-signed certificate warning

Problems encountered: the dashboard was unreachable on first boot — it reported
that it wasn't ready. The three Wazuh services had not all come up on their own.
Starting them explicitly resolved it:

```bash
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-indexer
sudo systemctl start wazuh-dashboard
```

Worth understanding rather than just fixing: Wazuh is three separate services,
not one. The **manager** receives agent data, the **indexer** stores and searches
it, and the **dashboard** is the web interface. The dashboard depends on the
indexer, which depends on the manager producing data — so "dashboard not ready"
usually means something further down the stack hasn't started, not that the web
interface itself is broken.

That layering explains later behaviour too: the dashboard being reachable is not
by itself proof that agents are reporting, and an agent showing Active is not by
itself proof that events are being indexed.

All three services are enabled to start at boot (`systemctl is-enabled` confirms
it), so this was a first-boot timing issue rather than a configuration problem —
the services hadn't finished coming up when the dashboard was first tried. It has
not recurred on subsequent restarts.

**Consequence worth noting.** Because this required no manual install, nothing
memorable happened during setup — which is directly why the SIEM's location was
later hard to recall. See Problem 10.

---

## Installing the Wazuh agent on Windows

The agent is the piece that ships logs from the monitored host to the manager.
All commands in PowerShell **as Administrator**.

### 1. Download the installer

```powershell
curl.exe -L -o "$env:TEMP\wazuh-agent.msi" https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi
```

`curl.exe` rather than `Invoke-WebRequest` — see Problem 2 for why.

### 2. Verify the download

```powershell
Get-Item "$env:TEMP\wazuh-agent.msi"
```

Check `Length`. A real installer is several megabytes; a few hundred bytes means
an HTTP error page was saved instead. The point of `Get-Item` is to inspect the
file rather than trust that the command returned without complaint.

### 3. Install

```powershell
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q /l*v "$env:TEMP\wazuh-install.log" WAZUH_MANAGER="192.168.56.101" WAZUH_AGENT_NAME="Windows11VM_1"
```

`WAZUH_MANAGER` is the manager's address. The value above is the current one.
During the initial build the lab ran on the home LAN, so the address here was
originally a private address on that network — that has been redacted from these
notes and replaced with the current Host-only address. It changed for real when
the lab was isolated, which meant editing `ossec.conf` on the agent and
restarting the service.

Every address appearing in these notes is in `192.168.56.0/24`, VirtualBox's
default Host-only range. It is the same on any install of VirtualBox and reveals
nothing about the host network.

**This prints nothing.** `/q` is quiet mode — no window, no progress, no success
message, and no error message either. Wait about 30 seconds. `/l*v` writes a
verbose log so there's something to read if it fails, which is the only reason
failure is diagnosable at all here.

### 4. Start the service

```powershell
NET START WazuhSvc
```

This one does report back, either way.

If it says the service doesn't exist, the install failed silently:

```powershell
Select-String -Path "$env:TEMP\wazuh-install.log" -Pattern "error|failed"
```

### 5. Confirm it's running

```powershell
Get-Service WazuhSvc
```

Status should be `Running`.

### 6. Confirm it's talking to the manager

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30
```

Look for the agent starting up and connecting, with the manager's address
appearing. Repeated retries or timeouts mean the service is fine but the network
path isn't.

### 7. Prove logs actually reach the dashboard

```powershell
net user labtest <password> /add
net user labtest /delete
```

A disposable local account, created and immediately removed. Account creation is
noisy enough to surface quickly, and it maps to a real technique rather than
being arbitrary noise.

Then in the dashboard: **Threat Intelligence → Threat Hunting**. The events
should appear there.

**If they don't:** Windows may not be auditing account management. Check, then
enable:

```powershell
auditpol.exe --% /get /subcategory:"User Account Management"
auditpol.exe --% /set /subcategory:"User Account Management" /success:enable
```

The `--%` stops PowerShell interpreting the rest of the line, which older Windows
tools like `auditpol` need. If it already reports success auditing as enabled,
the logging side is fine and the problem is downstream — the agent, the manager,
or the dashboard query.

This distinction matters more than it looks. A healthy pipeline showing nothing
usually means the endpoint never generated the record, not that the plumbing
broke. Missing telemetry, not broken transport.

### 8. Snapshot

Once the agent shows **Active** in the dashboard, snapshot both VMs
(Machine → Take Snapshot). Shut them down cleanly first, and snapshot both
together — the agent holds a registration key that must match the manager's
record, so rolling one back alone can produce a mismatch that looks like a bug.

---

## Installing Sysmon on the Windows endpoint

Windows' default security logging is thin — it records that an account was
created but not which process created it, under what parent, or with what
command line. Sysmon fills that gap, and without it most of this lab has nothing
to look at.

Installed on the monitored Windows VM only. The Wazuh appliance doesn't need it;
it isn't a Windows host, and the manager monitors itself.

All commands run in PowerShell **as Administrator**.

### 1. Download and unpack Sysmon

```powershell
# Fetch the Sysmon installer
curl.exe -L -o "$env:TEMP\Sysmon.zip" https://download.sysinternals.com/files/Sysmon.zip

# Verify the download — Length should be in the millions
Get-Item "$env:TEMP\Sysmon.zip"

# Unzip to a working folder, overwriting rather than erroring if it exists
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
```

### 2. Download the configuration

```powershell
curl.exe -L -o "$env:TEMP\Sysmon\sysmonconfig.xml" https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml

# Verify — Length should be in the hundreds of thousands
Get-Item "$env:TEMP\Sysmon\sysmonconfig.xml"
```

**The config matters more than the install.** Sysmon's default settings log very
little of value. SwiftOnSecurity's `sysmonconfig-export.xml` is the community
standard starting point — heavily commented, tuned to exclude routine activity
that would otherwise bury everything else. Running Sysmon without a config is
close to not running it at all.

The trade-off is that the config *is* excluding things by design. Knowing what it
filters is part of knowing what an empty search result means.

### 3. Install

```powershell
cd "$env:TEMP\Sysmon"
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

If PowerShell can't find `Sysmon64.exe`, run `dir` — some Sysinternals releases
ship a single `Sysmon.exe` instead.

### 4. Confirm Sysmon is logging

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

`MaxEvents` caps the output, most recent first. "Process Create" entries are a
good sign. Sysmon starts capturing immediately, and a running Windows host
creates processes constantly, so events should appear within seconds.

> **If this returns "there is not an event log on the localhost computer that
> matches," don't assume the install failed.** It happened here while Sysmon was
> running correctly and already feeding the SIEM, and the cause was never
> established. Enumerate before concluding anything:
>
> ```powershell
> Get-Service | Where-Object { $_.Name -like "*ysmon*" }
> Get-WinEvent -ListLog * | Where-Object { $_.LogName -like "*Sysmon*" } | Select-Object LogName, RecordCount
> ```
>
> Note that a genuine permissions problem gives a different message —
> "Attempted to perform an unauthorized operation" — so this error is not the
> elevation issue that causes several other problems in these notes.

### 5. Point the Wazuh agent at the Sysmon channel

**Installing Sysmon does not make Wazuh aware of it.** The agent has to be told
to read that channel. Skip this and Sysmon logs perfectly into a channel nobody
reads, with no error anywhere to indicate a problem.

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Look for this block, just above the closing `</ossec_config>` tag:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

If it isn't there, see the troubleshooting section below — writing to this file
is harder than it looks.

### 6. Restart the agent

```powershell
Restart-Service WazuhSvc
Get-Service WazuhSvc
```

### 7. Prove the whole chain works

```powershell
Get-Date   # note the time
whoami /all > $env:TEMP\sysmontest.txt
```

Then in the dashboard, with the time range set to the last 15 minutes:

```
data.win.system.providerName:"Microsoft-Windows-Sysmon"
data.win.system.eventID:1
```

Incidentally, `whoami /all` is itself a real attacker technique — MITRE ATT&CK
T1033, System Owner/User Discovery. Convenient as a test precisely because it's
the sort of thing worth detecting.

---

## Troubleshooting: Sysmon logging but nothing reaching the dashboard

**This took about an hour.** The chain has four links and the failure is silent
at every one, so the only way through is testing each in order.

**Link 1 — is Sysmon logging at all?**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Nothing, or a "log does not exist" error → check the channel name for typos
before concluding the install failed.

**Link 2 — did it record the specific command?**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 200 |
    Where-Object { $_.Message -like "*whoami*" }
```

Events exist but not this one → the SwiftOnSecurity config is filtering it. Not
a fault.

**Link 3 — is the agent reading the Sysmon channel?** *(This was the actual
problem.)*

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "Sysmon"
```

**No return value means failure.** The edit never saved. See Problem 5 below —
`C:\Program Files (x86)\` is protected, and both Notepad and `Set-Content`
fail there without surfacing an error.

**Fix:**

```powershell
# Back up first
Copy-Item "C:\Program Files (x86)\ossec-agent\ossec.conf" "C:\Program Files (x86)\ossec-agent\ossec.conf.bak"
```

Open Notepad **as Administrator** — right-click the Start-menu entry → Run as
administrator — then File → Open the config from inside it. Set the file-type
dropdown to All Files or the `.conf` won't be listed.

Add this immediately above the final `</ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Save with **Ctrl+S**, not Save As — Save As invites writing to a different
location, which is its own version of this failure. Close, then verify the edit
actually landed by re-running the `Select-String` check above.

```powershell
Restart-Service WazuhSvc
Start-Sleep -Seconds 10
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30
```

That last command shows whether the agent restarted cleanly and connected. A
malformed config produces errors here rather than silence.

**Link 4 — recheck the dashboard** with the searches from step 7.

**Two XML details that will silently break the config:** the channel name has no
internal spaces, and `</log_format>` needs its closing slash. A malformed config
stops the agent from starting properly.

### Snapshot once it works

Take a snapshot of both the Windows and Wazuh VMs, named something like
"Sysmon working." Right-click the VM → Snapshots → Take, or Machine → Take
Snapshot.

Shut both down cleanly first — snapshots of powered-off VMs are smaller and
restore more predictably:

- Windows: Start → Shut down
- Wazuh: `sudo shutdown -h now`

Snapshot both at the same time. The agent holds a registration key that must
match what the manager has on file, so rolling one back independently can
produce a mismatch that looks like a bug.

---

## Installing Atomic Red Team

Atomic Red Team is a library of small scripts, each simulating one documented
ATT&CK technique. Installed on the Windows VM — the same machine being
monitored. These tests run locally and model an attacker who already has code
execution on the host; they are not network attacks launched from elsewhere.

**Install this while the VM still has internet.** The test library comes from
GitHub, so it cannot be fetched once the lab is isolated.

```powershell
# Allow scripts in this PowerShell session only. Prints nothing.
Set-ExecutionPolicy Bypass -Scope Process -Force

# Download the installer script and execute it. Prints nothing.
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

# Verify the function loaded — the previous command gives no indication either way
Get-Command Install-AtomicRedTeam

# Run the installer. Prompts to install additional packages (yes).
Install-AtomicRedTeam -getAtomics

# Verify the test library actually downloaded — see the problem below
Get-ChildItem C:\AtomicRedTeam\atomics | Measure-Object
```

**On that `IEX (IWR ...)` line.** It downloads code and executes it immediately,
at whatever privilege the shell holds, with no chance to read it first. Two
nested commands: `IWR` (`Invoke-WebRequest`) fetches, `-UseBasicParsing` skips
HTML rendering, and `IEX` (`Invoke-Expression`) runs the result as code.

It is also a well-documented attacker technique — ATT&CK T1059.001 — used
precisely because nothing touches disk for file-based scanning to catch. See the
section on running code from the internet, below.

**The library may not land where the documentation says.** It didn't here. If
`C:\AtomicRedTeam\atomics` is missing, look one level up:

```powershell
Get-ChildItem C:\AtomicRedTeam
Get-ChildItem C:\ -Filter "T1033" -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
```

The parent of any `T1033` folder is the atomics path. Note it down — it's needed
for every test run, and it isn't the path in the docs.

---

## The recurring theme: silent failure

Nearly every problem in this build shared one shape — **an operation that
reports nothing on success also reports nothing on failure.**

Commands that produced no output either way:

- `msiexec /q` (quiet install)
- `Set-ExecutionPolicy`
- `Import-Module`
- `IEX (IWR ...)`
- Saving a file in Notepad
- `Set-Content` writing to a protected directory

In each case the only way to know the outcome was to ask a separate question:
*what would prove this worked?* That question, asked immediately after every
silent command, is what eventually made the build tractable.

---

## Problem 1 — Kali VM aborted with no log file

**Symptom.** VM failed to start. VirtualBox reported "aborted" and
`E_FAIL (0x80004005)` — a generic error code carrying no information. Attempting
to view the log returned: no log files found.

**Diagnosis.** The absence of the log was the clue. VirtualBox writes a log the
moment it attempts to start a VM, so no log meant the process died before it
could write one. The log path pointed inside `C:\Program Files\Oracle\` — the VM
had been extracted into a directory Windows protects. VirtualBox needs write
access there for logs, saved state, and the virtual disk itself, was denied on
first write, and died before producing the log that would have explained why.

**Fix.** Unregister the VM (Remove → *Remove only*, not Delete all files), move
the folder to a writable location, re-add it via **Add** (not Import Appliance —
that's for `.ova`), and set the default machine folder so it doesn't recur.

**Takeaway.** Missing diagnostic output is itself diagnostic. The question
"why is there no log?" led straight to the answer; "what does E_FAIL mean?"
would have led nowhere.

---

## Problem 2 — Wazuh agent download returned HTTP 403

**Symptom.** `Invoke-WebRequest` fetching the agent MSI returned 403 Forbidden.

**Diagnosis.** The URL and version were correct — verified independently. So the
refusal was coming from something between the host and the package server, not
from a bad path.

**Fix.** Used `curl.exe` (bundled with Windows 11) instead, which doesn't share
PowerShell's web stack. Worked immediately.

**Root cause: never determined.** Worked around rather than solved. That curl
succeeded against the same URL from the same machine points at something specific
to `Invoke-WebRequest` — its user agent or TLS negotiation being rejected — rather
than a network-level block, but this was not tested. Candidate explanations not
ruled out: an upstream filter, or security software intercepting HTTPS.

**Also fixed in passing.** The original command wrote to `$env:tmp\wazuh-agent`
with no `.msi` extension. `msiexec` will refuse a file that isn't named `.msi`,
so this would have failed at the next step regardless of the download.

---

## Problem 3 — Three commands pasted as one line

**Symptom.** Pasted a download command, an install command, and a service-start
command as a single block. Nothing happened.

**Diagnosis.** PowerShell read the entire block as one `curl.exe` invocation.
Everything after the URL was passed to curl as extra arguments rather than being
executed. `msiexec` never ran at all.

**Fix.** One command per line, checking output after each.

**Takeaway.** This is the same failure mode as the silent-command problem, from
a different direction: an apparent no-op that was actually a mis-parse. Running
commands individually costs seconds and eliminates a whole class of confusion.

---

## Problem 4 — Verifying a download actually downloaded

**Method.** After fetching an installer:

```powershell
Get-Item "$env:TEMP\wazuh-agent.msi" | Select-Object Name, Length
```

A `Length` in the millions means a real installer. Hundreds of bytes means an
HTTP error page was saved instead. The gap between the two is about four orders
of magnitude, so no reference figure is needed — only the order of magnitude.

For actual verification rather than a plausibility check, Wazuh publishes SHA-512
checksums per release; `Get-FileHash -Algorithm SHA512` compares against them.
Not done here, but it's the rigorous version.

---

## Problem 5 — Config edits that silently didn't save

**The worst one.** Adding the Sysmon event channel to the agent's `ossec.conf`
required four attempts:

1. **Notepad** — saved with no error. File unchanged.
2. **`Set-Content` from PowerShell** — no error. File unchanged.
3. **`Start-Process notepad -Verb RunAs`** — did not actually elevate.
4. **Right-click Notepad → Run as administrator, then File → Open** — worked.

**Diagnosis.** `C:\Program Files (x86)\` is protected. Non-elevated processes are
denied writes, and Notepad in particular can fail to save without surfacing a
meaningful error.

**How each failure was detected.** Not by any error message — by reading the
file back:

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "Sysmon"
```

Empty result meant the edit hadn't landed, regardless of what the editor claimed.

**Takeaway.** "It saved" is not evidence. This is the same root cause as
Problem 1 — Windows silently denying writes to protected directories — and it
cost two separate debugging sessions before the pattern became obvious.

---

## Problem 6 — Here-strings don't survive terminal paste

**Symptom.** A PowerShell here-string (`@"` … `"@`) threw a syntax error when
pasted into the terminal.

**Cause.** Here-string delimiters must occupy their own lines with nothing before
or after. Interactive paste frequently mangles that.

**Fix.** Used a single-line string with explicit `` `r`n `` newline escapes, or
avoided the construct entirely and hand-edited the file. Hand-editing turned out
to be both easier to verify and easier to reason about than a regex replacement.

---

## Problem 7 — Verified that a command ran, not that it worked

**Symptom.** `Install-AtomicRedTeam -getAtomics` appeared to complete. Ran
`Get-ChildItem C:\AtomicRedTeam\atomics`, glanced at it, moved on. Much later,
`Invoke-AtomicTest T1033` couldn't find the technique — the folder existed but
was empty.

**The mistake was the verification.** `Get-ChildItem` on a folder that exists
returns without error whether that folder holds four hundred items or zero.
Checking that a command *ran* is not the same as checking that it *worked*:

```powershell
Get-ChildItem C:\AtomicRedTeam\atomics | Measure-Object
```

A count in the hundreds is the actual test. This is a variant of the silent
failure theme running through the rest of this document — not a silent error,
but a check that succeeded while measuring the wrong thing.

**Root cause: not determined.** The obvious explanation was that the VM had no
internet, since the test library downloads from GitHub. The command history rules
that out: the immediately preceding `IEX (IWR ...)` fetched the installer script
from GitHub successfully, and `Get-Command Install-AtomicRedTeam` confirmed it
had loaded. Connectivity was working seconds before.

Remaining candidates, none tested: the installer prompts during execution and an
answer may have skipped the atomics download, or it failed partway and reported
success anyway. Left open rather than guessed at.

**Fix.** Re-ran the install with internet confirmed available, and verified the
count this time rather than the folder's existence.

**Second-order takeaway.** The first explanation I reached for was plausible,
fitted the symptom, and was wrong. It survived until the command history
contradicted it. Plausible-and-untested is how a lot of incorrect root causes get
written down.

---

## Problem 8 — Session state vs disk state

**Symptom.** `Install-AtomicRedTeam` stopped being recognized after a reboot.

**Cause.** The function was loaded into memory by `IEX (IWR ...)`. It lives only
in that PowerShell session. Rebooting the VM, or closing the window, discards it.
Installed software and downloaded files persist; loaded functions and
`-Scope Process` settings do not.

**Takeaway.** When something that worked earlier stops being recognized, check
whether it was ever on disk in the first place.

---

## Problem 9 — "No event log matches" while Sysmon was demonstrably working

**Symptom.** `Get-WinEvent` reported that no event log matching
`Microsoft-Windows-Sysmon/Operational` existed — despite Sysmon events having
already reached the SIEM and generated alerts.

**Diagnosis by contradiction.** Both things could not be true. Alerts in Wazuh
proved the channel existed and was being read. So the error had to be about the
query or its context, not about Sysmon.

Confirmed by enumerating rather than assuming:

```powershell
Get-Service | Where-Object { $_.Name -like "*ysmon*" }
Get-WinEvent -ListLog * | Where-Object { $_.LogName -like "*Sysmon*" } | Select-Object LogName, RecordCount
```

The service was running and the channel was present with a healthy record count.
Re-running the query with the enumerated name worked.

**Root cause: not determined.** The obvious explanation was a typo in the channel
name — it's long, and PowerShell returns this same message for a name that
doesn't exist. Command history rules that out: every logged invocation spells
`Sysmon` correctly.

Privilege was the next candidate, since insufficient rights caused Problems 1 and
5. Tested directly by running the same query in a non-elevated shell: that returns
"Attempted to perform an unauthorized operation," an explicit and clearly
different error. Ruled out.

No further hypothesis. The query failed, the same query later succeeded, and
nothing in the evidence explains the difference. Recorded as unresolved rather
than filled in with a plausible guess.

**Takeaway.** When two pieces of evidence contradict each other, one is being
misread, and resolving the contradiction is faster than investigating either
claim in isolation.

Separately, and more usefully: I proposed two confident explanations for this
error and both were wrong — one disproved by command history, one by a two-minute
test. Neither was unreasonable. Both fit the symptom. That is exactly how
incorrect root causes end up written down as fact, and the only thing that
prevented it here was checking.

---

## Problem 10 — Losing track of which VM ran the SIEM

**Symptom.** Couldn't say with confidence which machine was running the Wazuh
manager, despite the agent reporting to `192.168.56.101` successfully throughout.

**Cause.** Wazuh was deployed from the official OVA appliance — a pre-built VM
that required no manual install. Nothing memorable happened, so nothing was
remembered. It had simply been running correctly, accessed only through a
browser.

**Fix.** Read the VirtualBox VM list. The appliance was named plainly and had
been running the whole time.

**Takeaway.** Infrastructure that works without attention becomes invisible. That
is fine until it matters — and it matters as soon as you need to write down what
your environment actually is.

---

## Notes on running commands from the internet

The Atomic Red Team install uses the pattern:

```powershell
IEX (IWR '<url>' -UseBasicParsing)
```

This downloads code and executes it immediately, at whatever privilege the shell
holds, with no opportunity to read it first. It's also a well-documented attacker
technique (T1059.001), used precisely because nothing is written to disk for
file-based scanning to catch.

It was run here because it's what the project's documentation recommends, in a
disposable VM, against the project's official repository. But it's worth naming:
the reason this pattern is normalized is that legitimate projects publish it, and
the muscle memory transfers.

The alternative, which costs two extra steps:

```powershell
curl.exe -L -o "$env:TEMP\install.ps1" '<url>'
notepad "$env:TEMP\install.ps1"
. "$env:TEMP\install.ps1"
```

---

## Open items

- **The Wazuh dashboard shipped with default credentials.** Those are published
  in Wazuh's documentation and offer no protection at all. This went unnoticed
  through the whole initial build — the appliance sits on an isolated Host-only
  network with no route from anywhere else, so nothing broke, but running attack
  simulations against an environment whose SIEM has a publicly known login is
  inconsistent at best. Password changed. The `admin` username was left as-is:
  on an isolated network the username is not the control doing the work, and
  renaming it in Wazuh is disproportionate to the benefit.
- Wazuh's manager is reachable; whether its own config and installation
  directory are covered by file integrity monitoring is untested. Tampering with
  agent configuration is a standard defense-evasion move (T1562), and this build
  involved a great deal of editing that directory without checking whether any
  of it was logged.
- The Kali and Ubuntu VMs are not yet part of the monitored environment. Ubuntu
  is still on NAT rather than the isolated network.

---

## Credits

- [Wazuh](https://wazuh.com/) — SIEM, deployed from the official OVA appliance
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) — Microsoft Sysinternals
- [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) by SwiftOnSecurity — Sysmon configuration
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary — attack simulation tests
- Wazuh OVA deployment followed https://www.youtube.com/watch?v=ZsXQXUYFLoI
