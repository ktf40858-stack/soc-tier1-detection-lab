# RB-004 — Persistence: Run key and scheduled task

| | |
|---|---|
| **Detection** | SOC-004 (Wazuh 100007) and SOC-005 (Wazuh 100006) |
| **ATT&CK** | T1547.001 Registry Run Keys · T1053.005 Scheduled Task |
| **Severity** | Medium — but see the note below |
| **Target triage time** | 20 minutes |

## Why medium and not high

Legitimate software writes Run keys and creates scheduled tasks constantly. On an unbaselined
endpoint this detection is noisy, which is why it sits at medium.

**It stops being medium the moment it correlates.** Persistence on its own is ambiguous;
persistence within an hour of SOC-001 or SOC-003 on the same host is an intrusion chain, and
the chain is what you are actually looking for. Check for correlation before you dismiss it.

## Step 1 — What was written, exactly

For SOC-004 (registry):

```
win.eventdata.targetObject  -> which key, and which hive (HKCU = user, HKLM = machine-wide)
win.eventdata.details       -> the command that will run at logon
win.eventdata.image         -> what process wrote it
```

For SOC-005 (scheduled task), read the full `schtasks /create` line: `/tn` is the task name,
`/tr` is what runs, `/sc` and `/st` the schedule, `/ru` the account it runs as.

`/ru SYSTEM` on a task created by a script interpreter is privilege escalation, not just
persistence. Treat it as high.

## Step 2 — Read the payload

Same questions as the Run key value or the task action:

| In the value | Reading |
|---|---|
| A path under `\AppData\`, `\Temp\`, `\Users\Public\` | Not where software installs. Suspicious. |
| powershell / cmd / mshta / rundll32 / wscript | Living-off-the-land persistence. Suspicious. |
| An encoded or obfuscated command | Go to [RB-001](RB-001-encoded-powershell.md), decode first. |
| A path under `\Program Files\` with a signed binary | Probably legitimate — verify the signature. |
| A misspelled system binary name (svch0st, lsass.exe outside System32) | Masquerading. Escalate. |

## Step 3 — Who wrote it, and was it expected?

```
win.eventdata.image (SOC-004) or parentImage (SOC-005)
```

| Writer | Reading |
|---|---|
| msiexec.exe, TrustedInstaller.exe | Installer — suppressed by rule 100008, should not have alerted |
| A signed updater (Chrome, Teams, Slack) | Expected per-user persistence |
| powershell.exe, cmd.exe, wscript.exe, mshta.exe | **Not how software installs itself.** Suspicious. |
| An Office application | **Phishing chain.** Escalate. |

Then ask the operational question: was anything installed on this host today? A change record
or a helpdesk ticket resolves most of these in one minute.

## Step 4 — Correlate on the host

This is the step that changes the verdict.

```
agent.name:<host> AND rule.id:(100001 OR 100003 OR 100004 OR 100005 OR 100006 OR 100007)
over the last 24h
```

| Correlation | Verdict |
|---|---|
| Persistence alone, signed writer, Program Files path | False positive, tune it |
| Persistence + SOC-003 (download) | **Intrusion chain.** Escalate. |
| Persistence + SOC-001 (encoded PowerShell) | **Intrusion chain.** Escalate. |
| Persistence + a 4624 from RB-002 | **Compromise with persistence established.** Incident. |

## Step 5 — Enumerate the rest of the persistence

If you have decided this is malicious, one Run key is rarely the only thing. Before
remediating, enumerate — removing one mechanism while three remain teaches the operator that
you are watching.

```powershell
# autoruns, run as admin, from a Sysinternals copy on removable media
autorunsc64.exe -accepteula -a * -h -s -nobanner

# the same ground, natively
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ScheduledTask | Where-Object State -ne 'Disabled'
Get-Service | Where-Object { $_.PathName -notlike 'C:\Windows\*' }
Get-CimInstance -Namespace root\subscription -Class __EventFilter   # WMI persistence
```

WMI event subscriptions are the one people forget, and the one Autoruns shows on a tab
nobody opens.

## Disposition

| Finding | Action |
|---|---|
| Signed installer, Program Files path, matching change record | **False positive.** Add the writer to the 100008 filter. |
| Per-user updater in AppData (Teams, Chrome) | **False positive**, expected. Baseline it. |
| Script interpreter writing persistence, no change record | **Escalate to Tier 2.** |
| Correlates with SOC-001 or SOC-003 | **Incident.** Isolate the host. |
| Task running as SYSTEM created by a script | **Incident.** Privilege escalation. |

## Escalation package

The exact key or task name · the full payload · the writing process and its parent chain ·
the correlation search results for the last 24 hours · the full autoruns output. State
explicitly whether other persistence mechanisms were found, because that decides whether the
host can be cleaned or has to be rebuilt.
