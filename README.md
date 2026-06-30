# Win-Audit

A **Lynis-style security auditor for Windows 10/11**, written in pure PowerShell.
One script inspects 50+ security checks across 30+ categories, computes a
**Hardening Index (0–100)**, and writes console + Text + JSON + Markdown + HTML
reports. A companion script offers **safety-tiered remediation** with previews.

No dependencies, no install — drop the script on any machine and run it.

> ⚠️ **Status: beta.** The checks are validated on Windows 11 Pro. Behaviour on
> other editions/configs may vary — see [Accuracy & limitations](#accuracy--limitations).
> Treat results as guidance, not a certified compliance audit.

---

## Features

- **50+ checks / 30+ categories** — Secure Boot, TPM, BitLocker, Defender,
  firewall, accounts & password policy, UAC, SMB, RDP, VBS/HVCI/Credential
  Guard, exploit mitigations, event-log sizing, services, scheduled tasks,
  open ports, CIS-style spot checks, AD/IIS/SQL (auto-skipped if absent), and more.
- **Hardening Index** — a single 0–100 score (each check contributes OK=100 /
  Suggestion=50 / Warning=20).
- **Rich findings** — every finding carries a stable Finding ID, severity
  (Critical→Info), and a remediation-safety tier (SafeAuto / ConfirmFirst /
  ManualOnly).
- **5 output formats** — colored console, `.txt`, `.json` (schema-versioned),
  `.md`, and a styled `.html` report.
- **Safety-tiered remediation** — `Invoke-WinAuditRemediation.ps1` reads the
  JSON report and applies only *vetted* fixes, gated by tier, with `-WhatIf`
  preview and per-item confirmation.
- **Read-only by default** — the audit changes nothing; only the remediation
  script (when you explicitly pass a fix flag) modifies the system.
- **Portable** — self-contained, auto-elevates, writes reports next to itself.
  Run it on any PC and you get *that* machine's score.

## Requirements

- Windows 10 or 11
- PowerShell 5.1+ (Windows PowerShell) or PowerShell 7+
- Administrator rights (the script auto-elevates; many checks need it)

## Usage

```powershell
# Full audit (auto-elevates, writes reports beside the script)
.\Win-Audit.ps1

# Faster run, skip slow inventory/process scans
.\Win-Audit.ps1 -Fast

# Quiet (files only) or just the summary
.\Win-Audit.ps1 -Quiet
.\Win-Audit.ps1 -Summary

# Send reports elsewhere
.\Win-Audit.ps1 -OutputDir C:\Reports
```

If scripts are blocked, run once with:
`powershell -ExecutionPolicy Bypass -File .\Win-Audit.ps1`

### Remediation (optional, changes the system)

```powershell
# See what's actionable and which fixes are automatable
.\Invoke-WinAuditRemediation.ps1 -ListOnly

# Preview, then apply low-risk fixes
.\Invoke-WinAuditRemediation.ps1 -FixSafeOnly -WhatIf
.\Invoke-WinAuditRemediation.ps1 -FixSafeOnly

# Apply higher-impact fixes (prompts per item)
.\Invoke-WinAuditRemediation.ps1 -FixConfirmFirst
```

Only findings with a vetted fix in the script's registry are auto-applied;
everything else is reported as manual.

## Output

| File | Contents |
|------|----------|
| `Win-Audit-Report.html` | Styled report with score card, top findings, ports |
| `Win-Audit-Report.json` | Machine-readable (schema 2); consumed by remediation |
| `Win-Audit-Report.md`   | Markdown summary |
| `Win-Audit-Report.txt`  | Plain text |
| `Win-Audit-Remediation.txt` | Prioritised remediation guide |

> These files contain details about the scanned machine (hostname, accounts,
> open ports). They are git-ignored by default — **don't commit your own scans.**

## Accuracy & limitations

This is a heuristic auditor, **inspired by** [Lynis](https://github.com/CISOfy/lynis)
and CIS benchmarks — it is **not** an official CIS-CAT or certified compliance
tool, and the "CIS x.x" labels are informal references. Some findings are
intentionally context-dependent (e.g. Windows Defender shows as "off" when a
third-party AV is your primary engine — that's expected, not a gap). Verify
anything important against the authoritative source before acting. Bug reports
and check fixes are very welcome — see [CONTRIBUTING](CONTRIBUTING.md).

## Support

If Win-Audit saved you time, you can support development with a coffee:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/T5L622BXC6)

GitHub sponsorships are also available via the **Sponsor** button at the top of the repo.

## Disclaimer

Provided "as is", without warranty (see [LICENSE](LICENSE)). The remediation
script changes system configuration; review the planned actions with `-WhatIf`
and ensure you have a restore point/backup before applying. You are responsible
for changes made to your systems.

## License

[MIT](LICENSE) © 2026 YoshKoz
