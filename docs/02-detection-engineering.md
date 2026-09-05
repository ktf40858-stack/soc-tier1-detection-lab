# 2. How each detection was written

The rules in this repo are not copied from a ruleset. Each one went through the same five
steps, and the steps matter more than the rules — a ruleset ages, the method does not.

## The loop

```
1. Hypothesis     What would an attacker do here, concretely?
2. Telemetry      Which event proves it, and is that event actually being collected?
3. Rule           Write the narrowest thing that catches the behaviour, not the tool.
4. Validate       Fire the technique. If no alert, the rule is wrong, not the lab.
5. Tune           Run it against a week of normal activity. Every FP is a filter or a downgrade.
```

Step 4 is the one people skip. A rule that has never fired is a guess.

## Worked example — SOC-001, encoded PowerShell

**Hypothesis.** An operator who lands on a workstation runs PowerShell, and does not want the
command readable in the process table, so they base64 the payload.

**Telemetry.** Sysmon Event ID 1 gives the full command line and the parent. Windows 4688
does not give the parent command line, which is what turns "PowerShell ran" into "Word
spawned PowerShell". Sysmon it is.

**First attempt, and why it was wrong.**

```yaml
CommandLine|contains: '-EncodedCommand'
```

This fails on the first real sample. PowerShell accepts any unambiguous prefix of a parameter
name: `-e`, `-en`, `-enc`, `-encod` all work. Matching the full word catches only the operator
who typed it out in full. The rule became a regex over every valid abbreviation.

**Validation.** Atomic Red Team T1059.001-1. Alert fired, Wazuh rule 100001, level 12.

**Tuning.** One week of normal use produced two false positives, both from the same endpoint
management agent encoding its own inventory job. That became rule 100002 at level 0 — a child
rule that suppresses its parent for that one parent process. Not a widened regex.

## Why a tuning note is worth more than a rule

Anyone can publish a detection. What a SOC actually pays for is someone who can say *why the
threshold is 10 and not 5*, and what the rule costs the analyst on a normal Tuesday. So each
Sigma file carries a `falsepositives` block that is written from what was actually observed
in this lab, not copied from the template.

## Brute force is not password spraying

Two different shapes of the same intent, and one rule cannot see both:

| | Brute force | Password spraying |
|---|---|---|
| Accounts | one | many |
| Attempts per account | many | 2–3, deliberately below lockout |
| What to group on | source + account | source, counting *distinct* accounts |
| Rule | 100010 | 100011 (`different_field`) |

A SOC that only counts failures per account never sees the spray. This is the single most
useful thing in this repo and it took two rewrites to get right.

## What I would add next

- Command-line entropy scoring instead of keyword matching for obfuscation
- Parent-child process baselining, so "Word spawned anything" becomes the detection
- A `sigma-cli` conversion step in CI so the Sigma and Wazuh rules cannot drift apart
