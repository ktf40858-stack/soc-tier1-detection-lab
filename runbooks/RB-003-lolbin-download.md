# RB-003 — LOLBin download / suspicious signed binary

| | |
|---|---|
| **Detection** | SOC-003 (Wazuh 100003) and SOC-006 (Wazuh 100004, 100005) |
| **ATT&CK** | T1105 Ingress Tool Transfer · T1218.011 Rundll32 |
| **Severity** | High |
| **Target triage time** | 15 minutes |

## Why signed binaries are the hard case

certutil.exe, bitsadmin.exe, rundll32.exe and curl.exe are all Microsoft-signed and ship with
Windows. Application allowlisting passes them. AV rarely flags them. The only thing separating
abuse from intended use is **the arguments and the parent process** — which is exactly what
the detection reads, and exactly what you re-read during triage.

Reference for what each binary can be made to do: [LOLBAS](https://lolbas-project.github.io/).

## Step 1 — Extract the URL or the DLL from the command line

Read `win.eventdata.commandLine` from the alert.

| Pattern | What to extract |
|---|---|
| certutil -urlcache -f URL OUTFILE | the URL and the output path |
| bitsadmin /transfer job URL OUTFILE | the URL and the output path |
| curl -o OUTFILE URL | the URL and the output path |
| PowerShell DownloadFile / DownloadString | the URL and the output path |
| rundll32 DLL,Export | the DLL path and the exported function name |
| rundll32 with **no arguments** | nothing to extract — that is the finding itself |

**rundll32 with an empty command line is not a download.** It is close to always process
injection or hollowing: the process is started suspended and its memory replaced. Escalate
that case immediately; the rest of this runbook does not apply to it.

## Step 2 — Assess the destination

- Newly registered domain? Raw IP address? Paste site, Discord CDN, GitHub raw, dynamic DNS?
- Check reputation (VirusTotal, URLhaus, the org feed).
- **Do not browse to it from your own workstation.** Use the analysis sandbox, or do not fetch it.
- Correlate with Sysmon EID 22 (DNS) and EID 3 (network) for the same host and PID — you need
  to know whether the transfer completed, not just that it was attempted.

## Step 3 — Find what landed on disk

The output path from step 1 is where to look; Sysmon EID 11 (file create) on the same host in
the same window confirms it.

```
agent.name:<host> AND rule.groups:sysmon_eid11 AND <time window>
```

If the file is there: hash it (SHA256) and check the hash against intel. Do **not** open or
execute it. A write into `\AppData\`, `\Users\Public\`, `\ProgramData\` or `\Temp\` — a
user-writable directory outside the normal install paths — is staging, not installation.

## Step 4 — Did it run?

The download is stage one. Look for a process creation event whose `Image` matches the output
path in the minutes after. If the dropped file executed, this is an active intrusion rather
than an attempted one.

Check as well whether SOC-004 or SOC-005 fired on the same host: download followed by
persistence is a complete intrusion chain and raises the severity on its own.

## Step 5 — The parent process

| Parent | Reading |
|---|---|
| Office application | **Phishing.** Escalate. |
| powershell.exe, cmd.exe | Interactive or scripted — find what launched *that* |
| explorer.exe | The user did it — legitimate developer action? |
| A service or svchost.exe | Established persistence executing. Escalate. |
| A PKI or deployment script | Possible legitimate certutil use — verify against the change record |

## Disposition

| Finding | Action |
|---|---|
| certutil from a known PKI script, internal destination | **False positive.** Filter on that parent, document it. |
| curl on a developer workstation to a package registry | **False positive.** Scope the rule away from developer OUs. |
| Any download from an external low-reputation destination | **Escalate.** Isolate the host. |
| The downloaded file executed | **Incident.** Escalate immediately. |
| rundll32 with no arguments | **Escalate immediately** — assume injection. |

## Escalation package

Full command line · extracted URL or IP with its reputation verdict · output path · SHA256 of
the dropped file if present · whether it executed · parent chain · any correlated SOC-004 or
SOC-005 alert on the same host.
