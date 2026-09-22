# Win-Audit

A PowerShell security audit tool for Windows 10 and 11.

Win-Audit checks common Windows security settings, reports anything worth reviewing, and can optionally apply a limited set of remediation steps.

The audit itself is read-only.

## What it checks

Win-Audit currently covers more than 50 checks across areas including:

* Secure Boot and TPM
* BitLocker
* Microsoft Defender
* Windows Firewall
* local accounts and password policy
* UAC
* SMB and RDP
* VBS, HVCI and Credential Guard
* exploit mitigations
* services and scheduled tasks
* listening ports
* event log configuration
* selected Active Directory, IIS and SQL Server checks when present

Each finding includes a severity and a stable finding ID.

The script also calculates a simple hardening score to make repeated scans easier to compare.

## Requirements

* Windows 10 or Windows 11
* PowerShell 5.1 or newer
* Administrator access for checks that require elevated privileges

PowerShell 7 is supported but not required.

## Usage

Run a full audit:

```powershell
.\Win-Audit.ps1
```

Run a quicker scan:

```powershell
.\Win-Audit.ps1 -Fast
```

Only print the summary:

```powershell
.\Win-Audit.ps1 -Summary
```

Suppress console output and only write reports:

```powershell
.\Win-Audit.ps1 -Quiet
```

Write reports to another directory:

```powershell
.\Win-Audit.ps1 -OutputDir C:\Reports
```

If PowerShell blocks the script:

```powershell
powershell -ExecutionPolicy Bypass -File .\Win-Audit.ps1
```

## Output

A normal run can generate:

| File                        | Purpose                                                |
| --------------------------- | ------------------------------------------------------ |
| `Win-Audit-Report.html`     | Human-readable HTML report                             |
| `Win-Audit-Report.json`     | Machine-readable report used by the remediation script |
| `Win-Audit-Report.md`       | Markdown summary                                       |
| `Win-Audit-Report.txt`      | Plain-text report                                      |
| `Win-Audit-Remediation.txt` | Suggested remediation steps                            |

Reports can contain information about the scanned machine, including hostnames, accounts and listening ports.

Do not commit your own scan results to a public repository.

## Remediation

`Invoke-WinAuditRemediation.ps1` can apply fixes for a subset of findings.

See what can be changed:

```powershell
.\Invoke-WinAuditRemediation.ps1 -ListOnly
```

Preview low-risk fixes:

```powershell
.\Invoke-WinAuditRemediation.ps1 -FixSafeOnly -WhatIf
```

Apply them:

```powershell
.\Invoke-WinAuditRemediation.ps1 -FixSafeOnly
```

Higher-impact fixes require confirmation:

```powershell
.\Invoke-WinAuditRemediation.ps1 -FixConfirmFirst
```

Not every finding has an automatic fix. Anything without a reviewed remediation action is left for manual review.

## Example

```text
[+] Disk Encryption (BitLocker)
 [OK         ] C: BitLocker                 FullyEncrypted, Protection On

[+] Memory Integrity & Virtualization Security
 [OK         ] HVCI (Memory Integrity)      Running
 [OK         ] Virtualization-Based Security Running

=================================================
Hardening Index: 94 / 100
Duration: 32 seconds
  OK Findings:  105
  Suggestions:   13
  Warnings:       0
=================================================
```

## Accuracy and limitations

Win-Audit is a general-purpose security inspection tool, not a compliance scanner.

Some checks are inspired by Lynis and CIS guidance, but the project is not affiliated with CIS and is not a replacement for CIS-CAT or an official benchmark assessment.

Some results depend on the machine's role and configuration. For example, Microsoft Defender may legitimately be disabled when another antivirus product is active.

Review important findings against the relevant Microsoft or vendor documentation before making changes.

The current version has primarily been tested on Windows 11 Pro. Other Windows editions and configurations may behave differently.

## Project files

```text
Win-Audit.ps1
    Main audit script

Invoke-WinAuditRemediation.ps1
    Optional remediation tool

CHANGELOG.md
    Release history

CONTRIBUTING.md
    Contribution notes
```

## Contributing

Bug reports and fixes are welcome, particularly for checks that behave differently across Windows editions or configurations.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
