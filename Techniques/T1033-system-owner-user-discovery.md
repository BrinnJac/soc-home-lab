# T1033 — System Owner/User Discovery

**Tactic:** Discovery 
**Date tested:** 08/25/2026
**Test executed:** Atomic Red Team T1033, Test 1

---

## Lab environment

| Component | Detail |
|---|---|
| SIEM | Wazuh 4.14.7 OVA appliance, 192.168.56.101
| Monitored endpoint | Windows 11 (evaluation), 192.168.56.102
| End telemetry | Sysmon with SwiftOnSecurity config
| Agent | Wazuh agent, reporting on 1514/tcp
| Network | VirtualBox Host-only, 192.168.56.0/24, no internet egress

The Windows VM is both the simulated victim and the point of execution — this
test models an attacker who already has a foothold, not initial access.

---

## What the technique is

Once an attacker has code execution on a host, one of the first things they
need to know is *whose* account they're running as and what it can do. That
determines whether they escalate, move laterally, or start collecting data.
T1033 covers the commands used to answer that question.

Individually these commands are indistinguishable from routine adminstration, 
which is what makes the technique a useful first detection exercise.

---

## Execution

```powershell
Invoke-AtomicTest T1033 -TestNumbers 1
```

The test attempts several enumeration commands in sequence.

**Result: partial success, exit code 1.**

| Command | Outcome |
|---|---|
| whoami | Succeeded — returned windows11\vboxuser |
| wmic | Not recognized — binary absent |
| quser | Not recognized — binary absent |
| qwinsta | Not recognized — binary absent |

---

### Why three of four commands failed

Microsoft has deprecated wmic, and it is absent from current Windows 11 builds. 
quser and qwinsta are Remote Desktop Services utilities that ship with
 Windows Server but not with all desktop editions.

**Implication:** a detection rule written to match on `wmic` command lines
would find nothing on this host — not because the technique isn't being used,
but because the tooling moved. The same enumeration is now typically performed
through PowerShell CIM cmdlets, which produce entirely different command-line
strings. Detections tied to specific binaries decay as the platform changes.

---

## What I predicted

Nothing — this was my first Atomic Red Team test and I had no basis for
forming an expectation. Recording a prediction before execution is a practice
I'm adopting from T1082 onward, since comparing expected against observed is
what makes an unexpected result visible rather than just unremarkable.

---

## What the telemetry showed

**Events collected (Sysmon, Event ID 1 — Process Creation)**
All processes ran as WINDOWS11\vboxuser. All images are in C:\Windows\System32\ unless noted.

|image | parentImage | commandLine | processId / parentProcessId |
|---|---|---|---|
| whoami.exe | cmd.exe | whoami | 7292 / 5104 |
| cmd.exe | cmd.exe | cmd.exe /c qwinsta /server:localhost \| findstr "Active Disc" | 3304 / 484 |
| cmd.exe | cmd.exe | cmd.exe /C whoami | 5104 / 484 |
| cmd.exe | powershell.exe | cmd.exe /c cmd.exe /C whoami & wmic useraccount... (full below) | 484 / 9076 |

**Process Tree** 
powershell.exe (9076)          — session Atomic Red Team ran from
└─ cmd.exe (484)               — outer chained command
   ├─ cmd.exe (3304)           — qwinsta | findstr branch
   └─ cmd.exe (5104)
      └─ whoami.exe (7292)     — the only discovery binary that executed


**Full command line as observed in Sysmon:**

"cmd.exe" /c cmd.exe /C whoami & wmic useraccount get /ALL & quser /SERVER:"localhost" 
& quser & qwinsta.exe /server:localhost & qwinsta.exe & for /F "tokens=1,2" %i in 
('qwinsta /server:localhost ^| findstr "Active Disc"') do @echo %i | find /v "#" | 
find /v "console" || echo %j > computers.txt & @FOR /F %n in (computers.txt) 
DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') 
do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt

Command line shown unescaped; the Wazuh dashboard renders & as &amp; and > as &gt;.

---

### Alerts raised (Wazuh)

| Rule ID | Level | Description | Count |
|---|---|---|---|
| 92032 | 3 | Suspicious Windows cmd shell execution | 3 |
| 92052 | 4 | Windows command prompt started by an abnormal process | 1 |

Both rules are defined in the manager's ruleset file 0800-Sysmon_id_1.xml.

---

### Open Question: are failed executions logged?
Three of the four commands referenced binaries that don't exist on this host. 
Did Sysmon record anything for them?

**Method** Searched Event ID 1 records for each binary name, then checked the
Image field on every match rather than trusting the text hit.

**Result**
| Search Term | Matches | Image on matches | Process actually created? |
|---|---|---|---|
| whoami | 3 + 3| whoami.exe and cmd.exe | Yes |
| wmic | 3 | cmd.exe only | no |
| quser | 3 | cmd.exe only | no |
| qwinsta | 3 | cmd.exe only | no |

**Answer.** Sysmon does not create Event ID 1 records for binaries that fail to
execute — no process is created, so there is nothing to log. The attempted binary
names do persist in the commandLine field of the parent process that tried to invoke
them, which is why text searches returned hits.

---

## Analysis

**1. Text matching conflates "executed" with "referenced"**
Searching the Sysmon log for wmic returned three hits, which looked like evidence that
 wmic had run. It hadn't. All there were cmd.exe events that happened to contain the string 
 "wmic" inside their command line — the search mathed against the full event text, and the
 command line is part of that text.

 Only the Image field distinguishes the two cases. Checking it showed whoami.exe as a real
 image value and the other three names appearing noweher except inside a command line.

 This is a straightforward route to a wrong conclusion that looks well-evidenced: the query
 returns hits, the hits are genuine events, and the interpretation is still incorrect. The
 habit that prevents it is confirming the field, not the match.

 **2. The alerts fired on how the commands were launched, not what they did**
Four alerts were raised. All four described the same thing in different words — a command
prompt started by an unusual parent process. None describe user or account enumeration.

So the SIEM noticed the *delivery mechanism* and not the *technique*. The whoami executions,
which are the actual behavior T1033 describes, were collected as events but raised no alert 
of their own.

Worth stating the limit of this finding precisely: I know what these four alerts say, 
not that no other rule could ever fire on this behavior. But within this test, nothing
alerted on the discovery activity itself — only on the process ancestry created by the 
Atomic Red Team harness. An attacker running the same commands from a process that already
looks ordinary would likely produce nothing.

Alert levels were 3 and 4 — Informational. In production these would not page anyone,
which is probably the right call given how noisy the alternative would be.

**3. Process-name detection misses this entirely**
Three of the four tools never existed as processes, so a rule matching on process image
name has only whoami.exe and cmd.exe to work with — both entirely ordinary on a Windows host.

Everything that makes this activity suspicious lives in the command-line text: the chaining,
the tool names, the output redirection. A detection that reads process names sees a normal machine.
A detection that reads command lines sees reconnaissance.

---

## Would I detect on this?

**Not on whoami execution alone.** Administrators, login scripts, and
software installers run it constantly. A rule matching on it would generate
false positives indefinitely and be tuned out within a week.

**Candidate detections that might be worth the noise:**

1. **Anomalous parent process.** `whoami.exe` spawned by a web server process,
   a database service, or an Office application is meaningfully different from
   `whoami.exe` spawned by an interactive shell. The parent is the signal.

2. **Enumeration clustering.** One discovery command is noise. Several distinct
   discovery techniques within a short window — user, system, network, domain —
   is a pattern. This requires correlation across events rather than a
   single-event rule.

3. **Context.** Same command, unusual hour, from a host that has no history of
   it, under an account that doesn't normally run it.

**Where each of these produces false positives:** _[Your turn. Think through
what legitimate activity would trip each one. This section is where the actual
reasoning lives.]_

---
## Would I detect on this?

Not on whoami execution alone. Administrators, login scripts, and software 
installers run it constantly. A rule matching on it would generate false 
positives indefinitely and be tuned out within a week.

But the observed command line is highly detectable. It chains eight discovery 
commands with &, redirects output to computers.txt and usernames.txt, and nests
a loop enumerating sessions on remote hosts. No administrator types this interactively.

**Candidate detections**
**1. Multiple discovery binaries in a single command line.** The signature here is 
composition, not individual tool. Likely low false-positive rate.

**2. Discovery commands with output redirection to a file.** Staging results for later
collection is attacker behavior, not troubleshooting behavior

**3. Anomalous parent process.** whoami.exe under a web server or database process 
is meaningfully different from whoami.exe under an interactive shell.

**4. Enumeration clustering.** Several distinct discovery techniques within a short window,
correlated across events rather than match in a single rule.

**Where each would produce false positives**
**1. Multiple discovery binaries in one command line.** Software installers and setup scripts
routinely chain enumeration commands to check the environment before installing. Asset inventory
and endpoint management agents do the same on a schedule, by design. Vulnerability scanners run
discovery as their whole purpose. In an enterprise this rule would fire constantly on management
tooling unless those parent processes were excluded — and maintaining that exclusion list is 
ongoing work, not a one-time tuning pass.

**2.Discovery output redirected to a file.** IT scripts write inventory to files all the time:
audit reporting, license reconciliation, troubleshooting data collection, onboarding checks. The 
behavior is identical to staging for exfiltration; only intent differs, and intent isn't in the log. 
Narrwoing to unusual output locations (temp directories, user profile roots) would cut the noise but
also miss an attacker who writes somewhere ordinary

**3. Anomalous parent process.** This one depends entirely on having a baseline, and "anomalous" means
different things per environment. Legitmate applications shell out — monitoring agents, remote management tools, 
build systems, and some line-of-business software all spawn shells as designed. Without knowing what's 
normal for a given host, the rule is either too broad or arbitrary. Worth noting that this is precisely
the rule that fired on my own test harness rather than on the technique.

**4. Enumeration clustering.** New machine provisioning, IT audits, and vulnerability scans all produce 
dense bursts of discovery activity. So does an administrator actively troubleshooting a problem — they 
run many discovery comamnds quickly, which exactly the pattern being matched. Time-of-day or acount-based
context would help but wouldn't eliminate it.

**Limitation of this lab for answering the question.** All of the above is reasoned rather than measured. 
This environment has one monitored host, no user population, and no normal business activity, so there's no
baseline to test false-positives rates against. Assessing these rules properly would require running them against
real traffic over time — which is the part of detection engineering a home lab can't reproduce.

---

## What I'd do differently next time
**Run one test at a time.** Did this, and it was the right call — every event traced unambiguously back to 
a single command.

**Check the Image field before drawing any conclusion from a text search.** Three of my four apparent findings
dissolved on inspection.

**Record the exact log channel name and query up front.** Time was lost to a mistyped channel name that produced 
a "log does not exist" error, which looked like a broken Sysmon install rather than a typo.

**Note the start time before executing.** Reconstructing which events belonged to the test meant searching a 
wider window than necessary.

**Capture processGuid alongside PIDs.** PIDs are reused by Windows once a process exits, so they can't reliably identify 
a process on their own. I initially transcribed the PID/PPID columns transposed and the tree didn't close — GUIDs would 
have made the error obvious immediately.

**Read the SwiftOnSecurity config before relying on the telemetry.** It deliberately excludes activity to control volume. 
Knowing what's filtered is part of knowing what "no events" means.

---

## Open questions

Does Wazuh's default ruleset contain any rule that would alert on discovery behavior itself, rather than on process ancestry?
I know what these four alerts say; I haven't reviewed the ruleset to see what else exists.

Would my own monitoring detect tampering with the agent's configuration? During setup I edited 
C:\Program Files (x86)\ossec-agent\ossec.conf several times, and several attempts failed silently on permissions.
I never checked whether any of it was recorded. This matters beyond the setup annoyance: modifying or disabling an agent 
config is a standard defense-evasion move (T1562), and anyone who can write to that file can blind the SIEM. Does the SwiftOnSecurity 
config generate Event ID 11 or 23 for that path? Does Wazuh's file integrity monitoring cover its own installation directory by default? 
Untested.

What would this technique look like executed through PowerShell CIM cmdlets instead of the deprecated wmic? That's the modern equivalent, 
and it would produce entirely different telemetry — likely the more realistic test.

Would a command-line-based detection survive simple obfuscation (variable substitution, string concatenation, encoded commands)? Untested.
