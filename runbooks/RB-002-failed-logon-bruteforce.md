# RB-002 — Failed logon burst / password spraying

| | |
|---|---|
| **Detection** | SOC-002 · Wazuh rules 100010 (brute force) and 100011 (spraying) |
| **ATT&CK** | T1110.001 Password Guessing · T1110.003 Password Spraying |
| **Severity** | Medium (100010) / High (100011) |
| **Target triage time** | 20 minutes |

## Read the shape before anything else

Which rule fired tells you what you are looking at, and the two need different responses.

| | 100010 — brute force | 100011 — spraying |
|---|---|---|
| Shape | many attempts, one account | few attempts, many accounts |
| Usually means | a targeted account, or a stale credential | a credential-stuffing or spray campaign |
| Lockout | usually trips it | deliberately stays under it |
| Real risk | one account compromised | **one weak password anywhere in the org** |

100011 is the more serious of the two, even though it produces fewer events per account.

## Step 1 — Where is the source?

```
Wazuh -> rule.id:(100010 OR 100011) -> win.eventdata.ipAddress
```

| Source | Reading |
|---|---|
| Internal, a workstation | Already-compromised host spraying internally. **Escalate.** |
| Internal, a server | Could be a service account with a stale password — check step 4 first |
| External, one address | Internet-facing exposure — which service is reachable? |
| External, many addresses, same accounts | Credential stuffing from a botnet. Escalate. |
| Empty or ::1 | Local attempt — check the logon type below |

## Step 2 — Which logon type?

Field `win.eventdata.logonType` on the 4625 event:

| Type | Meaning | Note |
|---|---|---|
| 2 | Interactive (console) | physical or console session |
| 3 | Network (SMB, share) | most common in spraying |
| 8 | NetworkCleartext | **credentials sent in the clear — raise this regardless of the outcome** |
| 10 | RemoteInteractive (RDP) | is RDP exposed? check the perimeter |

Logon type 8 is worth a finding of its own even if the burst turns out to be benign.

## Step 3 — Did any attempt succeed?

This is the question that decides everything else.

```
Search 4624 (successful logon) from the SAME source, in and just after the SAME window
Wazuh: rule.id:60106 AND win.eventdata.ipAddress:<SOURCE_IP>
```

**A 4624 from that source after a burst of 4625 is a confirmed compromise.** Stop triage,
escalate, and start the account response below.

Also check 4740 (account locked out) and 4672 (special privileges assigned — an
administrative logon).

## Step 4 — Rule out the boring explanation

Before escalating a single-account 100010:

- Was the password changed recently? A stale saved credential in a mapped drive, a scheduled
  task, or a phone mail client produces exactly this pattern.
- Is the target a service account? Same story, and it repeats every N minutes with machine
  regularity — that regularity is the tell.
- Does `workstationName` match a device the user actually owns?

A human brute force is irregular. A stale credential retries on a timer. Look at the interval
between attempts before you look at anything else.

## Disposition

| Finding | Action |
|---|---|
| One account, regular interval, source is the user's own device | **False positive** — stale credential. Have the user re-save it. |
| One account, irregular, external source | Reset password, enforce MFA, monitor. Ticket to Tier 2. |
| Many accounts, one source (100011) | **Escalate.** Spray campaign — block the source, then audit for weak passwords. |
| Any 4624 success from the source | **Incident.** Escalate immediately. |

## Account response, when a success is confirmed

1. **Disable** the account — do not merely reset the password, an active session survives a reset.
2. Invalidate active sessions / revoke tokens.
3. Block the source at the perimeter.
4. Pull that account's logon history across all hosts — where else did it get in?
5. Then reset the password and re-enable, with MFA.

The order matters. Resetting first and disabling second leaves the attacker's live session running.

## Escalation package

Source IP with geolocation and ASN · target accounts · attempt count and window · logon type ·
whether any 4624 succeeded · affected host. Include the exact search that answers "did any
succeed", so Tier 2 does not have to rebuild it.
