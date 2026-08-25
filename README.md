# SOC Home Lab

A small detection lab built to practice endpoint monitoring and detection
analysis: run a known attacker technique against a monitored host, hunt for it
in the SIEM, and write up what the telemetry did and didn't show.

## Environment

| Component | Detail |
|---|---|
| Hypervisor | VirtualBox |
| SIEM | Wazuh 4.14.7 (OVA appliance) |
| Monitored endpoint | Windows 11, Wazuh agent + Sysmon (SwiftOnSecurity config) |
| Attack simulation | Atomic Red Team |
| Network | Host-only, isolated from the internet during testing |

## Contents

- [`techniques/`](techniques/) — one writeup per MITRE ATT&CK technique tested:
  what was executed, what appeared in the logs, what alerted, and what a
  detection for it would need to match on.
- `setup/` — build notes and the problems hit along the way. _(coming)_

## Approach

Each technique is run in isolation rather than in a batch, so every event traces
back to a single command. Writeups record what was predicted before execution
alongside what was actually observed, and note where the detection failed or
where the finding is limited by the lab itself.

## Techniques tested

| ID | Name | Notes |
|---|---|---|
| [T1033](techniques/T1033-system-owner-user-discovery.md) | System Owner/User Discovery | Alerts fired on process ancestry, not on the discovery behavior |
