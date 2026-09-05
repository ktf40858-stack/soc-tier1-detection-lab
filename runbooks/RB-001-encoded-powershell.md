# RB-001 — Encoded PowerShell command line

| | |
|---|---|
| **Detection** | SOC-001 · Wazuh rule 100001 · Sigma `proc_creation_win_powershell_encodedcommand.yml` |
| **ATT&CK** | T1059.001 Command and Scripting Interpreter: PowerShell |
| **Severity** | High |
| **Target triage time** | 15 minutes to a disposition |

## What fired

A process matching `powershell.exe` or `pwsh.exe` was started with an encoded command
payload. The command line is base64 and is not readable as-is.

## Step 1 — Decode the payload first

Everything downstream depends on what the payload actually is. Decode it before touching
anything else.

```powershell
$b64 = "<VALUE FROM THE ALERT>"
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
```

PowerShell encodes as UTF-16LE, so `Unicode`, not `UTF8`. If it comes out as garbage with
null bytes between characters, you used the wrong encoding.

If the decoded string is itself base64 or compressed (`FromBase64String`, `GzipStream`,
`IO.MemoryStream` in the decoded text), repeat until you reach readable code. Layered
encoding is itself an indicator — legitimate tooling does not nest three deep.

## Step 2 — Read the decoded payload for these

| Look for | Means |
|---|---|
| `IEX`, `Invoke-Expression`, `.Invoke()` | Executes a string — download cradle likely |
| `DownloadString`, `Invoke-WebRequest`, `Net.WebClient` | Fetching a stage 2 — get the URL |
| `-w hidden`, `-WindowStyle Hidden`, `-nop`, `-noni` | Deliberately hidden from the user |
| `FromBase64String`, `Gzip`, `Deflate` | Another layer, go back to step 1 |
| Long hex or byte arrays, `VirtualAlloc`, `CreateThread` | Shellcode. Escalate now, do not continue triage. |
| A UNC path, an internal share | Possible lateral movement |

## Step 3 — Establish the parent chain

```
Wazuh dashboard → filter agent.name = <host> → rule.id = 61603
Look at win.eventdata.parentImage and parentCommandLine
```

| Parent | Reading |
|---|---|
| `winword.exe`, `excel.exe`, `outlook.exe` | **Phishing.** Office does not spawn PowerShell in normal use. Escalate. |
| `wscript.exe`, `mshta.exe`, `cscript.exe` | Script dropper. Escalate. |
| `explorer.exe` | The user ran it — check whether they are an admin or a developer |
| `services.exe`, `svchost.exe` | Something installed persistence. Escalate. |
| Known management agent | Compare against rule 100002 — it may be the known-good job |

## Step 4 — Pivot on the same host

```
# other processes from the same parent PID, ±10 minutes
rule.groups:sysmon AND agent.name:<host>
```

Check specifically for: an outbound connection from the PowerShell process (Sysmon EID 3),
a file written to `\AppData\` or `\Users\Public\` (EID 11), a new Run key or scheduled task
(SOC-004 / SOC-005 firing on the same host in the same window). Two of these together turn
a single suspicious process into an incident.

## Disposition

| Finding | Action |
|---|---|
| Decodes to known admin/inventory work, parent is the management agent | **False positive.** Add to the 100002 filter, note it in the Sigma `falsepositives` block. |
| Decodes to a download cradle, or the parent is Office | **Escalate to Tier 2.** Isolate the host. |
| Contains shellcode markers | **Escalate immediately.** Do not reboot the host — memory is evidence. |
| Cannot decode, or payload is unclear | **Escalate.** An undecodable payload is not a benign one. |

## Escalation package

Hostname and IP · user account · full decoded payload · parent process chain · destination
URL or IP if any · timestamp in UTC · the alert ID. Attach the raw Sysmon EID 1 JSON.

## Containment (Tier 2 authorises, Tier 1 executes)

```bash
# Wazuh active response - isolate the agent
/var/ossec/bin/agent_control -b <AGENT_IP> -f firewall-drop -u <AGENT_ID>
```

Do not power the host off. A live host with a network block preserves memory; a powered-off
host destroys it.
