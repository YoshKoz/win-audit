# Contributing to Win-Audit

Thanks for helping improve Win-Audit. The most valuable contributions are
**accuracy fixes** — checks that misreport on a particular Windows edition or
configuration.

## Reporting a bad check

Open an issue with:
- The finding line as shown (e.g. `[Suggestion] Virtualization-Based Security: Disabled`)
- What the real state is, and how you verified it (the authoritative command)
- Your Windows edition + build (`winver`)

## Adding or fixing a check

Checks live in `Win-Audit.ps1` as `Test-*` functions and are called from `Main`.
A check just calls `Write-AuditResult`:

```powershell
Write-AuditResult "<Category>" "<Item>" "<OK|Suggestion|Warning>" "<message>"
```

Guidelines:
- **Read authoritative state, not policy registry keys** where possible
  (e.g. `Win32_DeviceGuard` for VBS/HVCI, `Get-BitLockerVolume` for encryption).
  Several historical bugs came from reading keys that are absent even when a
  feature is active.
- **Cast before numeric comparison** — values parsed from text (`net accounts`,
  regex) are strings; `"5" -le "10"` is false. Use `[int]`.
- **Don't assume edition** — gate on capability (does the cmdlet/feature exist?),
  not on `OSProductType` or the edition string.
- **The secure state is OK.** A disabled remote-access feature should score OK,
  not Suggestion.
- **Degrade gracefully** — wrap edition/role-specific checks in try/catch and
  skip cleanly when not applicable (AD/IIS/SQL already do this).

### Finding metadata

To attach a stable Finding ID, severity, and remediation safety tier, add an
entry to `$Global:CheckCatalog` keyed by the exact `Item` string. Findings not
in the catalog get a deterministic slug ID and conservative defaults.

### Remediation fixes

If a finding is auto-fixable, add an entry to `$FixRegistry` in
`Invoke-WinAuditRemediation.ps1` with an `Action` and a `Validate` scriptblock.
Keep `Validate` aligned with the audit's pass condition so the two agree, and
choose the safety tier conservatively (default to `ManualOnly` when unsure).

## Testing

Run on your own machine before submitting:

```powershell
.\Win-Audit.ps1 -NoElevate -OutputDir .\_test   # if already elevated
```

Validate syntax:

```powershell
[System.Management.Automation.Language.Parser]::ParseFile(
  "$PWD\Win-Audit.ps1", [ref]$null, [ref]([System.Management.Automation.Language.ParseError[]]@()))
```

A [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) pass
(`Invoke-ScriptAnalyzer .\Win-Audit.ps1`) is appreciated for new code.

Please don't commit generated `Win-Audit-Report.*` / log files — they're
git-ignored and contain machine-specific data.
