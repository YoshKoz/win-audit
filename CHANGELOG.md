# Changelog

All notable changes to Win-Audit.ps1 are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-05-13

### Added
- **Active Directory & Group Policy** (`Test-ActiveDirectory`): domain password policy, lockout threshold, password complexity, reversible encryption, Domain Admins count, KRBTGT password age, stale computer accounts, unlinked GPOs. Gracefully skips if RSAT not installed or machine not domain-joined.
- **IIS Web Server Security** (`Test-IISSecurity`): HTTPS-only bindings per site, directory browsing, server header disclosure, request size limits, anonymous authentication, app pool identity (LocalSystem/NetworkService check). Gracefully skips if IIS not installed.
- **SQL Server Security** (`Test-SQLServerSecurity`): instance detection, SQL Browser exposure, SQL Agent auto-start, port 1433 binding scope, service account privilege, SQL Agent per-instance. Gracefully skips if no SQL Server detected.

### Fixed
- 15 bugs: null dereference on missing registry keys (`$TranscriptLogging`, `$UAC`, `$ConsentPrompt`, `$AMSIRegistry`, `$USBPolicy`, `$AutoRun`, `$LSAAnonymous`, `$NTLMMinLevel`, `$EnableVirtualization`)
- `Test-CertificateValidation`: inverted logic treated missing TLS 1.2 registry key as "OK" — now correctly reports absent config as OK (Windows default) vs. explicitly disabled as Warning
- `Test-ExploitProtection`: null dereference on `$ExploitGuard.Count` and `$DEPPolicy.EnableDEP` when keys absent
- `Test-CodeIntegrity`: missing else branch for `Driver Signature Enforcement` when registry key absent
- `Test-RegistrySecurity`: double boolean check caused null pipeline enumeration
- `Test-StartupPrograms`: scalar `.Property.Count` unreliable; now uses `@(...).Count`
- `Test-EventLogs`: WMI null dereference when log file object missing; now guards and reports "Cannot determine size"

## [1.0.0] — 2026-04-24

### Added
- Initial public release as Lynis-equivalent for Windows 11
- **72 security checks** across 20+ audit categories
- Hardening Index scoring (0–100)
- Multi-format reporting: Text, JSON, HTML with professional CSS styling
- Malwarebytes antivirus detection alongside Windows Defender
- **Memory Integrity & Virtualization**: HVCI and Virtualization-Based Security (VBS) checks
- **Exploit Protection**: Validate DEP, CFG, ROP protection enforcement
- **Virtual Machine Platform**: Detect Hyper-V, Virtual Machine Platform, Windows Sandbox
- **Additional CIS Benchmarks**: PowerShell v2 legacy, unsigned driver restrictions
- **Device Encryption**: Enhanced BitLocker volume status checking
- **Printer Security**: Print Spooler status and PrintNightmare (KB5005010, KB5003671) patches
- **Secure Boot Detailed**: UEFI Secure Boot validation and DBX revocation status
- Automatic remediation suggestions with ready-to-run PowerShell commands
- Detailed audit log with timestamps
- Self-elevation mechanism for admin-required checks
- `-NoElevate` flag for CI/CD pipelines
- `-Summary` flag for quick console summary
- `-Mode Quick|Thorough` for scan depth control
- `-OutputDir` for custom report location
- `-Quiet` for silent operation

### Features
- **Zero Dependencies**: Pure PowerShell, no external modules or tools
- **Fast Execution**: ~40 seconds for comprehensive audit
- **Windows 11 Native**: Leverages modern security features (TPM 2.0, Secure Boot UEFI, etc.)
- **Malwarebytes Support**: Recognizes Malwarebytes as valid AV alternative to Defender
- **Modern Hardening**: Covers kernel hardening, DEP/ASLR, CFG, HVCI, VBS, Exploit Guard
- **Compliance Ready**: CIS Benchmark checks, LAPS detection, AppLocker validation
- **Professional HTML Reports**: Gradient styling, color-coded findings, responsive layout
- **JSON Export**: Parse results programmatically for automation and dashboards

### Security Checks Include
- System info and boot configuration (OS, UEFI, Secure Boot, TPM, BCD)
- User accounts and authentication (password policy, guest account, lockout thresholds)
- Windows services (TlntSvr, SMB, SNMP, NetBT)
- Firewall (profiles, inbound/outbound rules, default policies)
- Antivirus (Defender or Malwarebytes, real-time protection, signatures)
- Disk encryption (BitLocker volumes and device encryption)
- Event logging (log sizes, retention)
- Windows Updates (hotfixes, age of latest patch)
- Networking (adapters, DNS, LLMNR, NetBIOS, SMBv1/v2, SMB encryption)
- Open ports and listening services
- Running processes (count, suspicious detection)
- Scheduled tasks (count, enabled tasks)
- Device drivers (enumeration, signature enforcement, unsigned driver restrictions)
- User Account Control (UAC enablement, elevation prompt level, virtualization)
- Registry hardening (WDigest, NTLMv2, anonymous logon restrictions)
- Network Security (LLMNR disabled, NetBIOS over TCP/IP disabled)
- Kernel hardening (DEP/ASLR availability and enforcement)
- Remote Desktop (RDP enablement and security)
- Code Integrity (CFG, Driver Signature Enforcement)
- File system (critical path ACLs, Program Files permissions)
- File shares (non-administrative shares)
- Software inventory (installed products count)
- Time sync (W32Time service status)
- Credential Guard and Device Guard
- AMSI (Antimalware Scan Interface) status
- USB and AutoRun/AutoPlay policies
- Malware detection tools (Malwarebytes presence)
- Certificate validation (TLS 1.0/1.1 disabled, TLS 1.2 enabled)
- Memory integrity and VBS
- Exploit Protection configuration
- AppLocker policy enforcement
- CIS Benchmarks (password history, LAPS, PowerShell v2, driver installation)
- Print Spooler and PrintNightmare patch status
- Secure Boot detailed validation

### Known Limitations
- Some checks require admin elevation (Get-WindowsOptionalFeature, DISM queries)
- BitLocker not available on Home edition (returns "Not available")
- Home edition lacks HVCI, VBS, and some Group Policy features
- PrintNightmare patch detection via file enumeration (future: KB registry checks)
- Hyper-V, Virtual Machine Platform, Windows Sandbox features unavailable on Home
- Cannot fully enumerate drivers without elevation

## [0.5.0] — 2026-04-23

### Pre-Release (Internal Testing)
- Initial development and feature completion
- 50+ checks before expanded feature set
- Text and JSON report generation
- Basic remediation suggestions
- Malwarebytes integration testing
- TLS and registry hardening validation

---

## Versioning Policy

- **Major (X.0.0)**: Breaking changes to check categories, API, or report schema
- **Minor (0.X.0)**: New security checks or features (backwards compatible)
- **Patch (0.0.X)**: Bug fixes, performance improvements, documentation updates

## Future Roadmap

### Planned v1.1
- [ ] PowerShell 7+ parameter validation (PSv5 compat mode)
- [ ] Distributed audit via PSRemoting (farm reporting)
- [ ] Excel export (XLSX with charts)
- [ ] Dashboard integration (send to Grafana, Splunk)
- [ ] Windows Event Log forwarding audit

### Planned v1.2
- [ ] Active Directory group policy compliance checks
- [ ] Exchange Server security audit mode
- [ ] SQL Server hardening checks
- [ ] IIS security configuration audit
- [ ] Network device enumeration (printers, IoT hardening)

### Planned v2.0
- [ ] Web UI dashboard with historical trending
- [ ] Multi-machine central reporting
- [ ] Automated remediation engine with rollback
- [ ] Threat modeling output (STRIDE/PASTA integration)
- [ ] CVSS score assignment for vulnerabilities

---

## Migration Guide

### v0.5 → v1.0
No breaking changes for end users.

**For developers**:
- New test functions added; existing functions remain stable
- JSON schema expanded; previous fields preserved
- HTML report is new; no impact on existing JSON/text exports

### Updating Scripts
```powershell
# Old way (still works)
.\Win-Audit.ps1 -OutputDir C:\Reports

# New way (recommended)
.\Win-Audit.ps1 -Mode Thorough -OutputDir C:\Reports -Summary
```

---

## Credits

- **Inspiration**: Lynis (Michael Boelen, CISOfy)
- **Community**: Windows Security and PowerShell community feedback

## Support

- Issues & feature requests: [GitHub Issues](https://github.com/yoshi/win-audit/issues)
- Security vulnerabilities: See [SECURITY.md](SECURITY.md)
- Contributing: See [CONTRIBUTING.md](CONTRIBUTING.md)

---

**Release Date**: 2026-04-24  
**Last Updated**: 2026-04-24
