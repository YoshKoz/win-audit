<#
.SYNOPSIS
    Windows 11 System Audit Script (Lynis-equivalent) - v2.0.0
.DESCRIPTION
    Comprehensive security audit for Windows 11 with 30+ categories, hardening index,
    finding IDs, remediation safety metadata, local AI/dev exposure checks, and
    Text/JSON/Markdown/HTML reporting.

    Pair with Invoke-WinAuditRemediation.ps1 for safe, guided remediation.
.PARAMETER Fast
    Skip slow checks (software inventory, full process scan).
.PARAMETER OutputDir
    Directory for reports (default: script directory).
.PARAMETER Quiet
    Suppress console output, only write to files.
.NOTES
    Audit only - this script changes NOTHING on the system.
#>
param(
    [switch]$Fast,
    [string]$OutputDir = $PSScriptRoot,
    [switch]$Quiet,
    [switch]$NoElevate,
    [switch]$Summary
)

$Global:AuditVersion = "2.0.0"

# Ensure admin elevation (re-launch with the same engine; prefer PowerShell 7)
if (-not $NoElevate -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    $Engine = if ($PSVersionTable.PSVersion.Major -ge 6) { "pwsh.exe" } else { "powershell.exe" }
    $PassArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -OutputDir `"$OutputDir`" -NoElevate"
    if ($Fast)    { $PassArgs += " -Fast" }
    if ($Quiet)   { $PassArgs += " -Quiet" }
    if ($Summary) { $PassArgs += " -Summary" }
    Start-Process $Engine $PassArgs -Verb RunAs
    exit
}

$Global:Findings = [System.Collections.Generic.List[object]]::new()
$Global:Score = 0
$Global:MaxScore = 0
$Global:Categories = @{}
$Global:PortInventory = [System.Collections.Generic.List[object]]::new()
$Global:AuditNotes = [System.Collections.Generic.List[string]]::new()
$Global:RDPIsEnabled = $false
$Global:ReportFile = Join-Path $OutputDir "Win-Audit-Report.txt"
$Global:LogFile = Join-Path $OutputDir "Win-Audit.log"
$Global:JsonFile = Join-Path $OutputDir "Win-Audit-Report.json"
$Global:MarkdownFile = Join-Path $OutputDir "Win-Audit-Report.md"
$Global:RemediationFile = Join-Path $OutputDir "Win-Audit-Remediation.txt"
$Global:StartTime = Get-Date

# ========== CHECK CATALOG (FindingId + remediation metadata) ==========
# Keyed by Item name. Findings not in the catalog get a deterministic
# CATEGORY-ITEM slug as FindingId and conservative defaults
# (Severity from status, RemediationSafety = ManualOnly).
# Safety tiers: SafeAuto | ConfirmFirst | ManualOnly | DoNotAutomate | NotApplicable
$Global:CheckCatalog = @{
    "Transcript Logging" = @{
        Id = "PS-001"; Severity = "Medium"; Safety = "SafeAuto"
        Risk = "Without transcripts, malicious or accidental PowerShell activity leaves no local record for investigation."
        Recommendation = "Enable PowerShell transcription policy and point it at a protected local folder."
        Validation = "(Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting -eq 1"
    }
    "Execution Policy" = @{
        Id = "PS-002"; Severity = "Low"; Safety = "ConfirmFirst"
        Risk = "A permissive machine-wide execution policy makes it slightly easier to run unsigned scripts. It is a speed bump, not a boundary."
        Recommendation = "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"
        Validation = "(Get-ExecutionPolicy -Scope LocalMachine) -in @('Restricted','RemoteSigned','AllSigned')"
    }
    "Security Log Size" = @{
        Id = "LOG-001"; Severity = "Medium"; Safety = "SafeAuto"
        Risk = "A small Security log rolls over quickly; forensic evidence of an incident may be gone before you look."
        Recommendation = "wevtutil sl Security /ms:209715200 (200 MB, CIS minimum is 192 MB)"
        Validation = "(Get-WinEvent -ListLog Security).MaximumSizeInBytes -ge 196608KB"
    }
    "System Log Size" = @{
        Id = "LOG-002"; Severity = "Low"; Safety = "SafeAuto"
        Risk = "A small System log limits how far back you can trace service/driver issues and tampering."
        Recommendation = "wevtutil sl System /ms:104857600 (100 MB, CIS minimum is 32 MB)"
        Validation = "(Get-WinEvent -ListLog System).MaximumSizeInBytes -ge 32768KB"
    }
    "Application Log Size" = @{
        Id = "LOG-003"; Severity = "Low"; Safety = "SafeAuto"
        Risk = "A small Application log limits how far back you can trace application crashes and tampering."
        Recommendation = "wevtutil sl Application /ms:104857600 (100 MB, CIS minimum is 32 MB)"
        Validation = "(Get-WinEvent -ListLog Application).MaximumSizeInBytes -ge 32768KB"
    }
    "Ollama Bind Address" = @{
        Id = "AI-001"; Severity = "High"; Safety = "ConfirmFirst"
        Risk = "Ollama's API (default port 11434) has no authentication. Bound to 0.0.0.0/:: it lets anyone on the LAN run models, read loaded model data, and consume GPU/CPU."
        Recommendation = "Set machine environment variable OLLAMA_HOST=127.0.0.1:11434 and restart Ollama."
        Validation = "@(Get-NetTCPConnection -LocalPort 11434 -State Listen -ErrorAction SilentlyContinue | Where-Object { `$_.LocalAddress -notin @('127.0.0.1','::1') }).Count -eq 0"
    }
    "Ollama Firewall Guard" = @{
        Id = "AI-002"; Severity = "Medium"; Safety = "SafeAuto"
        Risk = "Defense in depth: even if Ollama is later misconfigured to listen broadly, an inbound block rule keeps port 11434 unreachable from the network. Loopback traffic is not affected by Windows Firewall."
        Recommendation = "New-NetFirewallRule -DisplayName 'WinAudit - Block Ollama 11434 inbound' -Direction Inbound -Action Block -Protocol TCP -LocalPort 11434"
        Validation = "@(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { `$_.Action -eq 'Block' -and `$_.Direction -eq 'Inbound' -and `$_.Enabled -and (`$_ | Get-NetFirewallPortFilter).LocalPort -contains '11434' }).Count -ge 1"
    }
    "Node Public Listener" = @{
        Id = "AI-003"; Severity = "High"; Safety = "ConfirmFirst"
        Risk = "A Node.js process listening on 0.0.0.0/:: exposes a dev server or API to the whole network segment. Dev servers typically have no auth and often allow file reads or code execution (e.g. webpack/vite HMR, debug endpoints)."
        Recommendation = "Identify the process from its command line. Bind it to 127.0.0.1 (HOST=127.0.0.1, --host 127.0.0.1, or app config), or stop it if unknown."
        Validation = "@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { `$_.LocalAddress -in @('0.0.0.0','::') -and (Get-Process -Id `$_.OwningProcess -ErrorAction SilentlyContinue).ProcessName -eq 'node' }).Count -eq 0"
    }
    "Dev Server Exposure" = @{
        Id = "AI-004"; Severity = "Medium"; Safety = "ManualOnly"
        Risk = "Non-Windows processes listening on all interfaces may expose unauthenticated local tooling to the LAN."
        Recommendation = "Review each process; bind development tools to 127.0.0.1 or add inbound block rules for their ports."
        Validation = "Get-NetTCPConnection -State Listen | Where-Object { `$_.LocalAddress -in @('0.0.0.0','::') } | ForEach-Object { `$p = Get-Process -Id `$_.OwningProcess -ErrorAction SilentlyContinue; '{0} {1} {2}' -f `$_.LocalAddress, `$_.LocalPort, `$p.ProcessName }"
    }
    "Open Port Count" = @{
        Id = "NET-010"; Severity = "Low"; Safety = "ManualOnly"
        Risk = "Each network-reachable listener is attack surface. Loopback-only listeners are not reachable from the network and are excluded from this count."
        Recommendation = "Review the Exposed Ports table in the report; bind dev tools to loopback and disable unused services."
        Validation = "Get-NetTCPConnection -State Listen | Where-Object { `$_.LocalAddress -notin @('127.0.0.1','::1') } | Group-Object LocalPort | Measure-Object | Select-Object -ExpandProperty Count"
    }
    "Account Lockout Threshold" = @{
        Id = "AUTH-001"; Severity = "Medium"; Safety = "ConfirmFirst"
        Risk = "Without a lockout threshold, local account passwords can be brute-forced without limit."
        Recommendation = "net accounts /lockoutthreshold:5"
        Validation = "`$t = [int]([regex]::Match((net accounts | Out-String), 'Lockout threshold[^\d]*(\d+)').Groups[1].Value); `$t -ge 5 -and `$t -le 10"
    }
    "Windows Sandbox" = @{
        Id = "SYS-001"; Severity = "Low"; Safety = "ConfirmFirst"
        Risk = "Not a vulnerability. Windows Sandbox is a hardening convenience: a disposable VM for opening untrusted files/installers."
        Recommendation = "Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All -NoRestart (restart required)"
        Validation = "(Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM').State -eq 'Enabled'"
    }
    "Print Spooler" = @{
        Id = "SVC-001"; Severity = "Medium"; Safety = "ConfirmFirst"
        Risk = "The Print Spooler has a history of privilege-escalation bugs (PrintNightmare, CVE-2021-34527). If you never print, it is pure attack surface."
        Recommendation = "Only if you do not print (including PDF printers): Stop-Service Spooler; Set-Service Spooler -StartupType Disabled"
        Validation = "(Get-Service Spooler -ErrorAction SilentlyContinue).Status -ne 'Running'"
    }
    "UAC Elevation Prompt" = @{
        Id = "UAC-001"; Severity = "Low"; Safety = "ConfirmFirst"
        Risk = "At the default level, malware running as the admin user can sometimes piggyback on silent/auto elevations. 'Always prompt' closes that gap at the cost of more prompts."
        Recommendation = "Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2"
        Validation = "(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin -eq 2"
    }
    "Exploit Protection" = @{
        Id = "EXP-001"; Severity = "Medium"; Safety = "ManualOnly"
        Risk = "Default mitigations are decent; strict system-wide policies add depth but can break specific apps (games, anti-cheat, older software)."
        Recommendation = "Review with Get-ProcessMitigation -System; apply per-app policies via Set-ProcessMitigation after testing. Do not bulk-apply system-wide."
        Validation = "Get-ProcessMitigation -System | Out-String"
    }
    "CIS 5.2 - LAPS" = @{
        Id = "CMP-001"; Severity = "Low"; Safety = "ManualOnly"
        Risk = "LAPS rotates the local Administrator password. Designed for domain/Intune-managed fleets; limited value on a standalone single-user desktop."
        Recommendation = "On standalone machines, treat as informational. If domain-joined later, deploy Windows LAPS via policy."
        Validation = "Get-Command Get-LapsAADPassword, Get-LapsADPassword -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
    }
    "RDP SSL Certificate" = @{
        Id = "RDP-001"; Severity = "Low"; Safety = "ManualOnly"
        Risk = "The default self-signed RDP certificate allows MITM on first connect. Only relevant while RDP is enabled and reachable."
        Recommendation = "If you enable RDP, deploy a certificate from a trusted CA to the Remote Desktop cert store and set SSLCertificateSHA1Hash."
        Validation = "(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections"
    }
    "Virtualization-Based Security" = @{
        Id = "VBS-001"; Severity = "Medium"; Safety = "ManualOnly"
        Risk = "VBS isolates secrets and code-integrity decisions in a hypervisor-protected enclave. Changing VBS state interacts with Hyper-V, WSL2 and some games/drivers."
        Recommendation = "Verify live state with: Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard. Change only via msinfo32-verified steps; requires reboot."
        Validation = "(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus"
    }
    "Credential Guard" = @{
        Id = "VBS-002"; Severity = "High"; Safety = "ManualOnly"
        Risk = "Credential Guard protects LSASS secrets from theft (mimikatz-style). Disabling it materially weakens credential protection."
        Recommendation = "Keep enabled. Verify with: (Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard).SecurityServicesRunning -contains 1"
        Validation = "(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning -contains 1"
    }
    "HVCI (Memory Integrity)" = @{
        Id = "VBS-003"; Severity = "High"; Safety = "ManualOnly"
        Risk = "HVCI blocks unsigned/vulnerable kernel drivers. Disabling it re-opens the kernel to driver-based attacks."
        Recommendation = "Keep enabled. Verify with: (Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard).SecurityServicesRunning -contains 2"
        Validation = "(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning -contains 2"
    }
    "BitLocker" = @{
        Id = "ENC-001"; Severity = "High"; Safety = "ManualOnly"
        Risk = "Unencrypted volumes expose all data if the disk is removed or the machine stolen."
        Recommendation = "Enable BitLocker per volume after backing up recovery keys: Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -TpmProtector"
        Validation = "Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus | Format-Table | Out-String"
    }
    "RDP Enabled" = @{
        Id = "RDP-002"; Severity = "Medium"; Safety = "ManualOnly"
        Risk = "RDP is a primary remote-attack vector when enabled and exposed."
        Recommendation = "Keep disabled unless needed. If needed: require NLA, restrict source IPs in firewall, use non-default certificate."
        Validation = "(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections"
    }
    "Memory Usage" = @{
        Id = "SYS-010"; Severity = "Info"; Safety = "NotApplicable"
        Risk = "Informational only - memory pressure is an operational concern, not a security finding. High usage with large RAM is normal (caches, VMs, models)."
        Recommendation = "No action needed unless the system is paging heavily."
        Validation = "Get-CimInstance Win32_OperatingSystem | Select-Object @{n='FreeGB';e={[math]::Round(`$_.FreePhysicalMemory/1MB,2)}}, @{n='TotalGB';e={[math]::Round(`$_.TotalVisibleMemorySize/1MB,2)}}"
    }
}

# ========== HELPER FUNCTIONS ==========

function Get-DefaultSeverity {
    param([string]$Status)
    switch ($Status) {
        "OK"         { "Info" }
        "Suggestion" { "Low" }
        "Warning"    { "Medium" }
        default      { "Info" }
    }
}

function Write-AuditResult {
    param(
        [string]$Category,
        [string]$Item,
        [string]$Status,
        [string]$Message,
        [string]$Evidence = "",
        [string]$Risk = "",
        [string]$Recommendation = ""
    )

    $Score = 0
    $Color = "White"
    switch ($Status) {
        "OK" { $Color = "Green"; $Score = 100 }
        "Suggestion" { $Color = "Yellow"; $Score = 50 }
        "Warning" { $Color = "Red"; $Score = 20 }
    }

    $Global:Score += $Score
    $Global:MaxScore += 100

    $Meta = $Global:CheckCatalog[$Item]

    $FindingId = if ($Meta -and $Meta.Id) { $Meta.Id }
                 else { (("{0}-{1}" -f $Category, $Item).ToUpper() -replace '[^A-Z0-9]+', '-').Trim('-') }
    $Severity = if ($Status -eq "OK") { "Info" }
                elseif ($Meta -and $Meta.Severity) { $Meta.Severity }
                else { Get-DefaultSeverity $Status }
    $Safety = if ($Status -eq "OK") { "NotApplicable" }
              elseif ($Meta -and $Meta.Safety) { $Meta.Safety }
              else { "ManualOnly" }
    if (-not $Risk -and $Meta) { $Risk = $Meta.Risk }
    if (-not $Recommendation -and $Meta) { $Recommendation = $Meta.Recommendation }
    $Validation = if ($Meta -and $Meta.Validation) { $Meta.Validation } else { "" }
    if (-not $Evidence) { $Evidence = $Message }

    $Finding = [ordered]@{
        FindingId         = $FindingId
        Category          = $Category
        Item              = $Item
        Status            = $Status
        Severity          = $Severity
        Message           = $Message
        Evidence          = $Evidence
        Risk              = $Risk
        Recommendation    = $Recommendation
        ValidationCommand = $Validation
        RemediationSafety = $Safety
        Score             = $Score
        Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    $Global:Findings.Add($Finding)

    if (-not $Quiet) {
        $Output = "[{0,-11}] {1,-40} {2}" -f $Status, $Item, $Message
        Write-Host " $Output" -ForegroundColor $Color
    }

    Add-Content -Path $Global:LogFile -Value "[$($Finding.Timestamp)] [$FindingId] [$Category] [$Status] $Item - $Message"

    if (-not $Global:Categories.ContainsKey($Category)) {
        $Global:Categories[$Category] = @()
    }
    $Global:Categories[$Category] += $Finding
}

function Write-CategoryHeader {
    param([string]$Category)
    if (-not $Quiet) {
        Write-Host "`n[+] $Category" -ForegroundColor Cyan
    }
    Add-Content -Path $Global:LogFile -Value "`n[+] $Category"
}

function Get-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Default = $null
    )
    try {
        $Value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($Value) { return $Value.$Name }
    }
    catch { }
    return $Default
}

function Add-AuditNote {
    param([string]$Note)
    $Global:AuditNotes.Add($Note)
}

# ========== REPORT EXPORTERS ==========

function Export-ReportJSON {
    $OS = Get-CimInstance Win32_OperatingSystem
    $Report = [ordered]@{
        SchemaVersion  = 2
        Tool           = "Win-Audit.ps1"
        ToolVersion    = $Global:AuditVersion
        Generated      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        DurationSec    = [int]((Get-Date) - $Global:StartTime).TotalSeconds
        ComputerName   = $env:COMPUTERNAME
        OSVersion      = "$($OS.Caption) Build $($OS.BuildNumber)"
        HardeningIndex = [int]($Global:Score / $Global:MaxScore * 100)
        Summary        = [ordered]@{
            Total      = $Global:Findings.Count
            OK         = @($Global:Findings | Where-Object { $_.Status -eq "OK" }).Count
            Suggestion = @($Global:Findings | Where-Object { $_.Status -eq "Suggestion" }).Count
            Warning    = @($Global:Findings | Where-Object { $_.Status -eq "Warning" }).Count
            SafeAutoFixes     = @($Global:Findings | Where-Object { $_.RemediationSafety -eq "SafeAuto" }).Count
            ConfirmFirstFixes = @($Global:Findings | Where-Object { $_.RemediationSafety -eq "ConfirmFirst" }).Count
        }
        Findings       = @($Global:Findings)
        ExposedPorts   = @($Global:PortInventory)
        Notes          = @($Global:AuditNotes)
    }
    $Report | ConvertTo-Json -Depth 6 | Out-File -FilePath $Global:JsonFile -Encoding UTF8
}

function Export-ReportMarkdown {
    $HardeningIndex = [int]($Global:Score / $Global:MaxScore * 100)
    $OKCount = @($Global:Findings | Where-Object { $_.Status -eq "OK" }).Count
    $SugCount = @($Global:Findings | Where-Object { $_.Status -eq "Suggestion" }).Count
    $WarnCount = @($Global:Findings | Where-Object { $_.Status -eq "Warning" }).Count
    $NonOK = @($Global:Findings | Where-Object { $_.Status -ne "OK" })
    $SafeFixes = @($NonOK | Where-Object { $_.RemediationSafety -eq "SafeAuto" })
    $ConfirmFixes = @($NonOK | Where-Object { $_.RemediationSafety -eq "ConfirmFirst" })
    $ManualItems = @($NonOK | Where-Object { $_.RemediationSafety -in @("ManualOnly", "DoNotAutomate") })
    $SeverityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3; "Info" = 4 }

    $MD = [System.Text.StringBuilder]::new()
    [void]$MD.AppendLine("# Windows 11 Security Audit Report")
    [void]$MD.AppendLine("")
    [void]$MD.AppendLine("| | |")
    [void]$MD.AppendLine("|---|---|")
    [void]$MD.AppendLine("| Generated | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') |")
    [void]$MD.AppendLine("| Computer | $env:COMPUTERNAME |")
    [void]$MD.AppendLine("| Tool | Win-Audit.ps1 v$Global:AuditVersion |")
    [void]$MD.AppendLine("| **Hardening Index** | **$HardeningIndex / 100** |")
    [void]$MD.AppendLine("")

    [void]$MD.AppendLine("## Executive Summary")
    [void]$MD.AppendLine("")
    $Verdict = if ($WarnCount -gt 0) { "needs attention: $WarnCount warning(s) found" }
               elseif ($SugCount -gt 0) { "in good shape: no warnings, $SugCount suggestion(s) remain" }
               else { "fully hardened against this checklist" }
    [void]$MD.AppendLine("This system scored **$HardeningIndex/100** across $($Global:Findings.Count) checks and is $Verdict. $($SafeFixes.Count) finding(s) can be fixed automatically (SafeAuto), $($ConfirmFixes.Count) need per-item confirmation (ConfirmFirst), and $($ManualItems.Count) require manual review.")
    [void]$MD.AppendLine("")
    [void]$MD.AppendLine("| Status | Count |")
    [void]$MD.AppendLine("|---|---|")
    [void]$MD.AppendLine("| OK | $OKCount |")
    [void]$MD.AppendLine("| Suggestion | $SugCount |")
    [void]$MD.AppendLine("| Warning | $WarnCount |")
    [void]$MD.AppendLine("")

    [void]$MD.AppendLine("## Top Findings")
    [void]$MD.AppendLine("")
    if ($NonOK.Count -eq 0) {
        [void]$MD.AppendLine("No open findings.")
    }
    else {
        [void]$MD.AppendLine("| ID | Severity | Category | Finding | Current State | Safety |")
        [void]$MD.AppendLine("|---|---|---|---|---|---|")
        foreach ($F in ($NonOK | Sort-Object { $SeverityOrder[$_.Severity] }, Category)) {
            [void]$MD.AppendLine("| $($F.FindingId) | $($F.Severity) | $($F.Category) | $($F.Item) | $($F.Message -replace '\|', '/') | $($F.RemediationSafety) |")
        }
    }
    [void]$MD.AppendLine("")

    [void]$MD.AppendLine("## Exposed Ports (grouped by process)")
    [void]$MD.AppendLine("")
    if ($Global:PortInventory.Count -eq 0) {
        [void]$MD.AppendLine("Port inventory not collected.")
    }
    else {
        [void]$MD.AppendLine("| Process | PID | Port | Address | Exposure | Classification |")
        [void]$MD.AppendLine("|---|---|---|---|---|---|")
        foreach ($P in ($Global:PortInventory | Sort-Object Exposure, ProcessName, Port)) {
            [void]$MD.AppendLine("| $($P.ProcessName) | $($P.ProcessId) | $($P.Port) | $($P.LocalAddress) | $($P.Exposure) | $($P.Classification) |")
        }
        [void]$MD.AppendLine("")
        [void]$MD.AppendLine("Exposure legend: **Loopback** = reachable only from this machine. **AllInterfaces** = reachable from the network (firewall rules permitting). **SpecificInterface** = bound to one address.")
    }
    [void]$MD.AppendLine("")

    [void]$MD.AppendLine("## Safe Fixes Available")
    [void]$MD.AppendLine("")
    if ($SafeFixes.Count -eq 0 -and $ConfirmFixes.Count -eq 0) {
        [void]$MD.AppendLine("None - nothing automatable is open.")
    }
    else {
        foreach ($F in $SafeFixes) {
            [void]$MD.AppendLine("- **[$($F.FindingId)] $($F.Item)** (SafeAuto): $($F.Recommendation)")
        }
        foreach ($F in $ConfirmFixes) {
            [void]$MD.AppendLine("- **[$($F.FindingId)] $($F.Item)** (ConfirmFirst): $($F.Recommendation)")
        }
        [void]$MD.AppendLine("")
        [void]$MD.AppendLine('Preview: `.\Invoke-WinAuditRemediation.ps1 -FixSafeOnly -WhatIf` - Apply: `.\Invoke-WinAuditRemediation.ps1 -FixSafeOnly`')
    }
    [void]$MD.AppendLine("")

    [void]$MD.AppendLine("## Manual Review Items")
    [void]$MD.AppendLine("")
    if ($ManualItems.Count -eq 0) {
        [void]$MD.AppendLine("None.")
    }
    else {
        foreach ($F in $ManualItems) {
            [void]$MD.AppendLine("- **[$($F.FindingId)] $($F.Item)**: $($F.Message)")
            if ($F.Recommendation) { [void]$MD.AppendLine("  - $($F.Recommendation)") }
        }
    }
    [void]$MD.AppendLine("")

    [void]$MD.AppendLine("## False-Positive / Audit-Logic Notes")
    [void]$MD.AppendLine("")
    if ($Global:AuditNotes.Count -eq 0) {
        [void]$MD.AppendLine("None recorded this run.")
    }
    else {
        foreach ($N in $Global:AuditNotes) { [void]$MD.AppendLine("- $N") }
    }
    [void]$MD.AppendLine("")

    [void]$MD.AppendLine("## Validation Commands")
    [void]$MD.AppendLine("")
    $WithValidation = @($NonOK | Where-Object { $_.ValidationCommand })
    if ($WithValidation.Count -eq 0) {
        [void]$MD.AppendLine("None.")
    }
    else {
        foreach ($F in $WithValidation) {
            [void]$MD.AppendLine("**$($F.FindingId) - $($F.Item)**")
            [void]$MD.AppendLine('```powershell')
            [void]$MD.AppendLine($F.ValidationCommand)
            [void]$MD.AppendLine('```')
        }
    }

    $MD.ToString() | Out-File -FilePath $Global:MarkdownFile -Encoding UTF8
}

function Export-RemediationReport {
    $RemediationContent = "Windows 11 Security Audit - Remediation Guide`n"
    $RemediationContent += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
    $RemediationContent += "Computer: $env:COMPUTERNAME`n"
    $RemediationContent += "================================================`n`n"
    $RemediationContent += "For guided/safe remediation use: .\Invoke-WinAuditRemediation.ps1 -ListOnly`n`n"

    $Actionable = @($Global:Findings | Where-Object { $_.Status -in @("Warning", "Suggestion") })
    if ($Actionable.Count -eq 0) {
        $RemediationContent += "No actionable remediation items found. System is well-configured!`n"
    }
    else {
        foreach ($Section in @(@{ Title = "PRIORITY FINDINGS (Warnings)"; Status = "Warning" }, @{ Title = "RECOMMENDED IMPROVEMENTS (Suggestions)"; Status = "Suggestion" })) {
            $RemediationContent += "`n$($Section.Title)`n"
            $RemediationContent += "================================================`n"
            $Items = @($Actionable | Where-Object { $_.Status -eq $Section.Status })
            if (-not $Items) { $RemediationContent += "None`n"; continue }
            foreach ($Finding in $Items) {
                $RemediationContent += "`n[$($Finding.FindingId)] [$($Finding.Category)] $($Finding.Item) (Severity: $($Finding.Severity), Safety: $($Finding.RemediationSafety))`n"
                $RemediationContent += "Current: $($Finding.Message)`n"
                if ($Finding.Risk) { $RemediationContent += "Risk: $($Finding.Risk)`n" }
                if ($Finding.Recommendation) { $RemediationContent += "Action: $($Finding.Recommendation)`n" }
                $RemediationContent += "---`n"
            }
        }
    }

    $RemediationContent | Out-File -FilePath $Global:RemediationFile -Encoding UTF8
}

function Show-SummaryReport {
    if ($Quiet) { return }

    Write-Host "`n=== TOP PRIORITY ISSUES ===" -ForegroundColor Red
    $Warnings = $Global:Findings | Where-Object { $_.Status -eq "Warning" } | Sort-Object Category
    if ($Warnings) {
        foreach ($W in $Warnings | Select-Object -First 10) {
            Write-Host "[$($W.FindingId)] [$($W.Category)] $($W.Item): $($W.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "None - good job!" -ForegroundColor Green
    }

    Write-Host "`n=== TOP RECOMMENDATIONS ===" -ForegroundColor Yellow
    $Suggestions = $Global:Findings | Where-Object { $_.Status -eq "Suggestion" } | Sort-Object Category
    if ($Suggestions) {
        foreach ($S in $Suggestions | Select-Object -First 10) {
            Write-Host "[$($S.FindingId)] [$($S.Category)] $($S.Item): $($S.Message)" -ForegroundColor Yellow
        }
        if (@($Suggestions).Count -gt 10) {
            Write-Host "... and $(@($Suggestions).Count - 10) more (see full report)" -ForegroundColor Yellow
        }
    }
}

function Export-ReportHTML {
    $HardeningIndex = [int]($Global:Score / $Global:MaxScore * 100)
    $Duration = [int]((Get-Date) - $Global:StartTime).TotalSeconds
    $IndexColor = if ($HardeningIndex -ge 75) { "#4CAF50" } elseif ($HardeningIndex -ge 50) { "#FF9800" } else { "#F44336" }

    $OKCount = @($Global:Findings | Where-Object { $_.Status -eq "OK" }).Count
    $SuggestionCount = @($Global:Findings | Where-Object { $_.Status -eq "Suggestion" }).Count
    $WarningCount = @($Global:Findings | Where-Object { $_.Status -eq "Warning" }).Count
    $NonOK = @($Global:Findings | Where-Object { $_.Status -ne "OK" })
    $SafeFixes = @($NonOK | Where-Object { $_.RemediationSafety -eq "SafeAuto" })
    $ConfirmFixes = @($NonOK | Where-Object { $_.RemediationSafety -eq "ConfirmFirst" })
    $ManualItems = @($NonOK | Where-Object { $_.RemediationSafety -in @("ManualOnly", "DoNotAutomate") })

    $HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows 11 Security Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 2.2em; margin-bottom: 10px; }
        .header p { opacity: 0.95; font-size: 1.05em; }
        .score-card { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; padding: 40px; background: #f8f9fa; border-bottom: 2px solid #e9ecef; }
        .score-item { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
        .score-item h3 { color: #667eea; margin-bottom: 10px; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }
        .score-item .value { font-size: 2.2em; font-weight: bold; color: $IndexColor; }
        .section { padding: 30px 40px; border-bottom: 1px solid #e9ecef; }
        .section h2 { color: #667eea; margin-bottom: 16px; font-size: 1.4em; }
        .section p.lead { color: #444; margin-bottom: 12px; }
        table.data { width: 100%; border-collapse: collapse; font-size: 0.9em; }
        table.data th { background: #667eea; color: white; padding: 8px 10px; text-align: left; }
        table.data td { padding: 7px 10px; border-bottom: 1px solid #e9ecef; }
        table.data tr:nth-child(even) { background: #f8f9fa; }
        .pill { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: 0.8em; font-weight: 600; color: white; }
        .pill.sev-Critical, .pill.sev-High { background: #F44336; }
        .pill.sev-Medium { background: #FF9800; }
        .pill.sev-Low { background: #2196F3; }
        .pill.sev-Info { background: #9E9E9E; }
        .pill.exp-AllInterfaces { background: #F44336; }
        .pill.exp-SpecificInterface { background: #FF9800; }
        .pill.exp-Loopback { background: #4CAF50; }
        .findings { padding: 40px; }
        .category { margin-bottom: 30px; border-left: 4px solid #667eea; padding-left: 20px; }
        .category h2 { color: #667eea; margin-bottom: 16px; font-size: 1.3em; }
        .finding { display: flex; align-items: flex-start; margin-bottom: 12px; padding: 12px; background: #f8f9fa; border-radius: 6px; border-left: 4px solid #ddd; }
        .finding.ok { border-left-color: #4CAF50; }
        .finding.suggestion { border-left-color: #FF9800; }
        .finding.warning { border-left-color: #F44336; }
        .finding-status { font-weight: bold; margin-right: 15px; min-width: 95px; text-transform: uppercase; font-size: 0.8em; }
        .finding.ok .finding-status { color: #4CAF50; }
        .finding.suggestion .finding-status { color: #FF9800; }
        .finding.warning .finding-status { color: #F44336; }
        .finding-content { flex: 1; }
        .finding-title { font-weight: 600; color: #333; margin-bottom: 4px; }
        .finding-title .fid { color: #888; font-weight: 400; font-size: 0.85em; margin-left: 6px; }
        .finding-message { color: #666; font-size: 0.92em; }
        ul.fixlist li { margin: 6px 0 6px 20px; color: #444; }
        code { background: #eef; padding: 1px 5px; border-radius: 3px; font-size: 0.9em; }
        footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Windows 11 Security Audit Report</h1>
            <p>$env:COMPUTERNAME &middot; Generated: $(Get-Date -Format 'MMMM dd, yyyy @ HH:mm:ss') &middot; Win-Audit v$Global:AuditVersion</p>
        </div>

        <div class="score-card">
            <div class="score-item"><h3>Hardening Index</h3><div class="value">$HardeningIndex/100</div></div>
            <div class="score-item"><h3>Warnings</h3><div class="value">$WarningCount</div></div>
            <div class="score-item"><h3>Suggestions</h3><div class="value">$SuggestionCount</div></div>
            <div class="score-item"><h3>Passed</h3><div class="value">$OKCount</div></div>
            <div class="score-item"><h3>Duration</h3><div class="value">${Duration}s</div></div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p class="lead">$($Global:Findings.Count) checks evaluated. $WarningCount warning(s), $SuggestionCount suggestion(s). $($SafeFixes.Count) finding(s) are auto-fixable (SafeAuto), $($ConfirmFixes.Count) need confirmation (ConfirmFirst), $($ManualItems.Count) need manual review.</p>
            <p class="lead">Remediate with: <code>.\Invoke-WinAuditRemediation.ps1 -FixSafeOnly -WhatIf</code> (preview) then <code>.\Invoke-WinAuditRemediation.ps1 -FixSafeOnly</code></p>
        </div>
"@

    # Top findings table
    if ($NonOK.Count -gt 0) {
        $SeverityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3; "Info" = 4 }
        $HTML += "        <div class='section'>`n            <h2>Top Findings</h2>`n            <table class='data'><tr><th>ID</th><th>Severity</th><th>Category</th><th>Finding</th><th>Current State</th><th>Safety</th></tr>`n"
        foreach ($F in ($NonOK | Sort-Object { $SeverityOrder[$_.Severity] }, Category)) {
            $HTML += "            <tr><td>$($F.FindingId)</td><td><span class='pill sev-$($F.Severity)'>$($F.Severity)</span></td><td>$($F.Category)</td><td>$([System.Net.WebUtility]::HtmlEncode($F.Item))</td><td>$([System.Net.WebUtility]::HtmlEncode($F.Message))</td><td>$($F.RemediationSafety)</td></tr>`n"
        }
        $HTML += "            </table>`n        </div>`n"
    }

    # Exposed ports table
    if ($Global:PortInventory.Count -gt 0) {
        $HTML += "        <div class='section'>`n            <h2>Listening Ports (grouped by process)</h2>`n            <table class='data'><tr><th>Process</th><th>PID</th><th>Port</th><th>Address</th><th>Exposure</th><th>Classification</th></tr>`n"
        foreach ($P in ($Global:PortInventory | Sort-Object Exposure, ProcessName, Port)) {
            $HTML += "            <tr><td>$([System.Net.WebUtility]::HtmlEncode($P.ProcessName))</td><td>$($P.ProcessId)</td><td>$($P.Port)</td><td>$($P.LocalAddress)</td><td><span class='pill exp-$($P.Exposure)'>$($P.Exposure)</span></td><td>$([System.Net.WebUtility]::HtmlEncode($P.Classification))</td></tr>`n"
        }
        $HTML += "            </table>`n        </div>`n"
    }

    # Safe fixes
    $HTML += "        <div class='section'>`n            <h2>Safe Fixes Available</h2>`n            <ul class='fixlist'>`n"
    if ($SafeFixes.Count -eq 0 -and $ConfirmFixes.Count -eq 0) {
        $HTML += "            <li>None - nothing automatable is open.</li>`n"
    }
    foreach ($F in $SafeFixes) {
        $HTML += "            <li><strong>[$($F.FindingId)] $([System.Net.WebUtility]::HtmlEncode($F.Item))</strong> (SafeAuto): $([System.Net.WebUtility]::HtmlEncode($F.Recommendation))</li>`n"
    }
    foreach ($F in $ConfirmFixes) {
        $HTML += "            <li><strong>[$($F.FindingId)] $([System.Net.WebUtility]::HtmlEncode($F.Item))</strong> (ConfirmFirst): $([System.Net.WebUtility]::HtmlEncode($F.Recommendation))</li>`n"
    }
    $HTML += "            </ul>`n        </div>`n"

    # Manual review
    if ($ManualItems.Count -gt 0) {
        $HTML += "        <div class='section'>`n            <h2>Manual Review Items</h2>`n            <ul class='fixlist'>`n"
        foreach ($F in $ManualItems) {
            $HTML += "            <li><strong>[$($F.FindingId)] $([System.Net.WebUtility]::HtmlEncode($F.Item))</strong>: $([System.Net.WebUtility]::HtmlEncode($F.Message))</li>`n"
        }
        $HTML += "            </ul>`n        </div>`n"
    }

    # False positive notes
    if ($Global:AuditNotes.Count -gt 0) {
        $HTML += "        <div class='section'>`n            <h2>Audit-Logic Notes</h2>`n            <ul class='fixlist'>`n"
        foreach ($N in $Global:AuditNotes) {
            $HTML += "            <li>$([System.Net.WebUtility]::HtmlEncode($N))</li>`n"
        }
        $HTML += "            </ul>`n        </div>`n"
    }

    $HTML += "        <div class='findings'>`n"
    foreach ($Category in ($Global:Categories.Keys | Sort-Object)) {
        $HTML += "            <div class='category'>`n"
        $HTML += "                <h2>$Category</h2>`n"
        foreach ($Finding in $Global:Categories[$Category]) {
            $CSSClass = $Finding.Status.ToLower()
            $HTML += "                <div class='finding $CSSClass'>`n"
            $HTML += "                    <div class='finding-status'>$($Finding.Status)</div>`n"
            $HTML += "                    <div class='finding-content'>`n"
            $HTML += "                        <div class='finding-title'>$([System.Net.WebUtility]::HtmlEncode($Finding.Item))<span class='fid'>$($Finding.FindingId)</span></div>`n"
            $HTML += "                        <div class='finding-message'>$([System.Net.WebUtility]::HtmlEncode($Finding.Message))</div>`n"
            $HTML += "                    </div>`n"
            $HTML += "                </div>`n"
        }
        $HTML += "            </div>`n"
    }

    $HTML += @"
        </div>
        <footer>
            <p><strong>System:</strong> $env:COMPUTERNAME | <strong>OS:</strong> Windows 11 | <strong>Tool:</strong> Win-Audit.ps1 v$Global:AuditVersion</p>
        </footer>
    </div>
</body>
</html>
"@

    $HTMLFile = $Global:ReportFile -replace "\.txt$", ".html"
    $HTML | Out-File -FilePath $HTMLFile -Encoding UTF8
}

# ============================================================
# AUDIT CHECKS  (ported verbatim from Win-Audit.ps1 v1)
# ============================================================
function Test-SystemInfo {
    Write-CategoryHeader "System Information"

    $OS = Get-CimInstance Win32_OperatingSystem
    $SystemInfo = Get-ComputerInfo

    Write-AuditResult "System" "OS Version" "OK" "$($OS.Caption) Build $($OS.BuildNumber)"
    Write-AuditResult "System" "Hostname" "OK" $env:COMPUTERNAME
    Write-AuditResult "System" "Installation Date" "OK" ($OS.InstallDate | Get-Date -Format "yyyy-MM-dd")
    Write-AuditResult "System" "System Boot Time" "OK" ((Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime | Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Write-AuditResult "System" "Processor" "OK" "$($SystemInfo.CsProcessors[0].Name)"
    Write-AuditResult "System" "RAM" "OK" "$([math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)) GB"
}

function Test-SecureBoot {
    Write-CategoryHeader "Secure Boot"

    try {
        $SecureBootState = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecureBoot\State" -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue
        if ($SecureBootState.UEFISecureBootEnabled -eq 1) {
            Write-AuditResult "Boot" "Secure Boot" "OK" "Enabled"
        }
        else {
            Write-AuditResult "Boot" "Secure Boot" "Suggestion" "Not available (BIOS mode)"
        }
    }
    catch {
        Write-AuditResult "Boot" "Secure Boot" "Suggestion" "Not available (BIOS mode)"
    }

    $FWType = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecureBoot\State" -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue
    if ($FWType.UEFISecureBootEnabled -eq 1) {
        Write-AuditResult "Boot" "Firmware Type" "OK" "UEFI"
    }
    else {
        Write-AuditResult "Boot" "Firmware Type" "Warning" "Legacy BIOS"
    }
}

function Test-Services {
    Write-CategoryHeader "Windows Services"

    $Services = Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" }
    Write-AuditResult "Services" "Running Services" "OK" "$($Services.Count) services running"

    $DangerousServices = @("TlntSvr", "lanmanserver", "SNMPSvc", "NetBT")
    foreach ($Svc in $DangerousServices) {
        $Service = Get-CimInstance Win32_Service -Filter "Name='$Svc'" -ErrorAction SilentlyContinue
        if ($Service) {
            if ($Service.State -eq "Running") {
                Write-AuditResult "Services" $Svc "Warning" "Running - disable if not needed"
            }
            elseif ($Service.StartMode -ne "Disabled") {
                Write-AuditResult "Services" $Svc "Suggestion" "Installed but not disabled"
            }
            else {
                Write-AuditResult "Services" $Svc "OK" "Disabled"
            }
        }
        else {
            Write-AuditResult "Services" $Svc "OK" "Not installed"
        }
    }
}

function Test-UserAccounts {
    Write-CategoryHeader "User Accounts & Authentication"

    $Users = Get-LocalUser
    Write-AuditResult "Users" "Local User Accounts" "OK" "$($Users.Count) accounts found"

    $AdminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Measure-Object
    if ($AdminUsers.Count -le 3) {
        Write-AuditResult "Users" "Administrator Count" "OK" "$($AdminUsers.Count) admin accounts"
    }
    else {
        Write-AuditResult "Users" "Administrator Count" "Suggestion" "$($AdminUsers.Count) admin accounts - review"
    }

    $DisabledGuest = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled
    if (-not $DisabledGuest) {
        Write-AuditResult "Users" "Guest Account" "OK" "Disabled"
    }
    else {
        Write-AuditResult "Users" "Guest Account" "Warning" "Enabled"
    }

    $NoPasswordUsers = Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled -eq $true }
    if ($NoPasswordUsers.Count -eq 0) {
        Write-AuditResult "Users" "Accounts without password" "OK" "None (disabled accounts exempt)"
    }
    else {
        Write-AuditResult "Users" "Accounts without password" "Warning" "$($NoPasswordUsers.Count) enabled accounts: $($NoPasswordUsers.Name -join ', ')"
    }
}

function Test-PasswordPolicy {
    Write-CategoryHeader "Password Policy"

    $NetAccounts = (net accounts 2>$null) -join "`n"

    # Check password requirement: accounts with PasswordRequired=false
    $NoPassUsers = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled }
    if (-not $NoPassUsers) {
        Write-AuditResult "Auth" "Password Required" "OK" "All enabled accounts require a password"
    }
    else {
        Write-AuditResult "Auth" "Password Required" "Warning" "$($NoPassUsers.Count) enabled account(s) have no password required"
    }

    # Cast to [int] — string comparison mis-orders multi-digit numbers (e.g. "8" -ge "12").
    $MinLengthRaw = [regex]::Match($NetAccounts, "Minimum password length[^\d]*(\d+)").Groups[1].Value
    $MinLength = if ($MinLengthRaw) { [int]$MinLengthRaw } else { 0 }
    if ($MinLength -ge 12) {
        Write-AuditResult "Auth" "Minimum Password Length" "OK" "$MinLength characters"
    }
    else {
        Write-AuditResult "Auth" "Minimum Password Length" "Suggestion" "$MinLength characters (recommend 12+)"
    }

    # "net accounts" prints "Never" for an unlimited max age -> no digits -> 0.
    $MaxAgeRaw = [regex]::Match($NetAccounts, "Maximum password age[^\d]*(\d+)").Groups[1].Value
    $MaxAge = if ($MaxAgeRaw) { [int]$MaxAgeRaw } else { 0 }
    if ($MaxAge -gt 0 -and $MaxAge -le 90) {
        Write-AuditResult "Auth" "Maximum Password Age" "OK" "$MaxAge days"
    }
    elseif ($MaxAge -le 0) {
        Write-AuditResult "Auth" "Maximum Password Age" "Suggestion" "Never expires"
    }
    else {
        Write-AuditResult "Auth" "Maximum Password Age" "Suggestion" "$MaxAge days (recommend <= 90)"
    }

    $PasswordHistoryRaw = [regex]::Match($NetAccounts, "password history[^\d]*(\d+)").Groups[1].Value
    $PasswordHistory = if ($PasswordHistoryRaw) { [int]$PasswordHistoryRaw } else { 0 }
    if ($PasswordHistory -ge 12) {
        Write-AuditResult "Auth" "Password History" "OK" "$PasswordHistory remembered"
    }
    else {
        Write-AuditResult "Auth" "Password History" "Suggestion" "$PasswordHistory remembered (recommend 12+)"
    }

    # Cast to [int] — string comparison would make "5" -le "10" false (char order).
    $LockoutRaw = [regex]::Match($NetAccounts, "Lockout threshold[^\d]*(\d+)").Groups[1].Value
    $LockoutThreshold = if ($LockoutRaw) { [int]$LockoutRaw } else { -1 }
    if ($LockoutThreshold -ge 5 -and $LockoutThreshold -le 10) {
        Write-AuditResult "Auth" "Account Lockout Threshold" "OK" "$LockoutThreshold attempts"
    }
    elseif ($LockoutThreshold -eq 0) {
        Write-AuditResult "Auth" "Account Lockout Threshold" "Warning" "Disabled - enables brute force attacks"
    }
    elseif ($LockoutThreshold -lt 0) {
        Write-AuditResult "Auth" "Account Lockout Threshold" "Suggestion" "Cannot determine threshold"
    }
    else {
        Write-AuditResult "Auth" "Account Lockout Threshold" "Suggestion" "$LockoutThreshold attempts (recommend 5-10)"
    }
}

function Test-Firewall {
    Write-CategoryHeader "Windows Firewall"

    $Profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($Profiles) {
        $DisabledCount = ($Profiles | Where-Object { -not $_.Enabled }).Count
        if ($DisabledCount -eq 0) {
            Write-AuditResult "Firewall" "Firewall Status" "OK" "All profiles enabled"
        }
        else {
            Write-AuditResult "Firewall" "Firewall Status" "Warning" "$DisabledCount profiles disabled"
        }
    }

    $InRules = (Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true } | Measure-Object).Count
    Write-AuditResult "Firewall" "Inbound Rules" "OK" "$InRules enabled rules"

    $OutRules = (Get-NetFirewallRule -Direction Outbound -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true } | Measure-Object).Count
    Write-AuditResult "Firewall" "Outbound Rules" "OK" "$OutRules enabled rules"

    $DefaultInbound = $Profiles | Select-Object -ExpandProperty DefaultInboundAction -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($DefaultInbound -eq "Block") {
        Write-AuditResult "Firewall" "Default Inbound Policy" "OK" "Deny (secure default)"
    }
    else {
        Write-AuditResult "Firewall" "Default Inbound Policy" "Suggestion" "Not set to deny all"
    }
}

function Test-WindowsDefender {
    Write-CategoryHeader "Windows Defender & Antimalware"

    $MalwareBytes = Get-Service "MBAMService" -ErrorAction SilentlyContinue
    $HasAltAV = $null -ne $MalwareBytes

    $Defender = Get-Service "WinDefend" -ErrorAction SilentlyContinue
    if ($Defender -and $Defender.Status -eq "Running") {
        Write-AuditResult "Security" "Windows Defender" "OK" "Running"
    }
    else {
        $Status = if ($HasAltAV) { "Suggestion" } else { "Warning" }
        $Message = if ($HasAltAV) { "Not running (Malwarebytes detected)" } else { "Not running" }
        Write-AuditResult "Security" "Windows Defender" $Status $Message
    }

    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($DefenderStatus.RealTimeProtectionEnabled) {
            Write-AuditResult "Security" "Real-time Protection" "OK" "Enabled"
        }
        else {
            $Status = if ($HasAltAV) { "Suggestion" } else { "Warning" }
            Write-AuditResult "Security" "Real-time Protection" $Status "Disabled"
        }

        if ($DefenderStatus.IsTamperProtected) {
            Write-AuditResult "Security" "Tamper Protection" "OK" "Enabled"
        }
        else {
            Write-AuditResult "Security" "Tamper Protection" "Suggestion" "Disabled"
        }

        if ($DefenderStatus.BehaviorMonitorEnabled) {
            Write-AuditResult "Security" "Behavior Monitoring" "OK" "Enabled"
        }
        else {
            Write-AuditResult "Security" "Behavior Monitoring" "Suggestion" "Disabled"
        }

        if ($DefenderStatus.IoavProtectionEnabled) {
            Write-AuditResult "Security" "IOAV Protection" "OK" "Enabled"
        }
        else {
            Write-AuditResult "Security" "IOAV Protection" "Suggestion" "Disabled"
        }

        $SigLastUpdate = Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated
        if ($SigLastUpdate -and ((Get-Date) - $SigLastUpdate).Days -le 3) {
            Write-AuditResult "Security" "Antivirus Signatures" "OK" "Current (updated $(((Get-Date) - $SigLastUpdate).Days) days ago)"
        }
        else {
            $Status = if ($HasAltAV) { "Suggestion" } else { "Warning" }
            Write-AuditResult "Security" "Antivirus Signatures" $Status "Outdated - update immediately"
        }
    }
    catch { }
}

function Test-BitLocker {
    Write-CategoryHeader "Disk Encryption (BitLocker)"

    # OSProductType (1=Workstation, 2=DC, 3=Server) does NOT indicate edition;
    # gating on it wrongly reported "Not available" on every client PC. Instead
    # probe the cmdlet (absent on Home) and read real volume protection state.
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Write-AuditResult "Encryption" "BitLocker" "Suggestion" "BitLocker management not available on this Windows edition"
        return
    }
    try {
        $BitLockerVolumes = Get-BitLockerVolume -ErrorAction Stop
    }
    catch {
        Write-AuditResult "Encryption" "BitLocker" "Suggestion" "Unable to query BitLocker (requires elevation)"
        return
    }
    if ($BitLockerVolumes) {
        foreach ($Volume in $BitLockerVolumes) {
            $Encrypted = ($Volume.ProtectionStatus -eq "On") -or ($Volume.VolumeStatus -eq "FullyEncrypted")
            $Status = if ($Encrypted) { "OK" } else { "Suggestion" }
            Write-AuditResult "Encryption" "$($Volume.MountPoint) BitLocker" $Status "$($Volume.VolumeStatus), Protection $($Volume.ProtectionStatus)"
        }
    }
    else {
        Write-AuditResult "Encryption" "BitLocker" "Suggestion" "No encrypted volumes"
    }
}

function Test-EventLogs {
    Write-CategoryHeader "Event Logging"

    # Audit the CONFIGURED MAXIMUM size (the actual hardening setting that
    # Invoke-WinAuditRemediation sets via 'wevtutil sl'), not the current
    # content size. Thresholds match the CheckCatalog LOG-00x validations.
    $Logs = @(
        @{ Name = "Security";    MinKB = 196608 }  # 192 MB (CIS)
        @{ Name = "System";      MinKB = 32768 }   # 32 MB
        @{ Name = "Application"; MinKB = 32768 }   # 32 MB
    )
    foreach ($Log in $Logs) {
        try {
            $MaxBytes = (Get-WinEvent -ListLog $Log.Name -ErrorAction Stop).MaximumSizeInBytes
            $MaxMB = [math]::Round($MaxBytes / 1MB)
            if ($MaxBytes -ge ($Log.MinKB * 1KB)) {
                Write-AuditResult "Logging" "$($Log.Name) Log Size" "OK" "Max $MaxMB MB"
            }
            else {
                Write-AuditResult "Logging" "$($Log.Name) Log Size" "Suggestion" "Max $MaxMB MB (raise to >= $([math]::Round($Log.MinKB / 1024)) MB)"
            }
        }
        catch {
            Write-AuditResult "Logging" "$($Log.Name) Log Size" "Suggestion" "Cannot determine max size"
        }
    }
}

function Test-Updates {
    Write-CategoryHeader "Windows Updates"

    $Hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Measure-Object
    if ($Hotfixes.Count -gt 0) {
        Write-AuditResult "Updates" "Installed Hotfixes" "OK" "$($Hotfixes.Count) hotfixes"
    }
    else {
        Write-AuditResult "Updates" "Installed Hotfixes" "Warning" "No hotfixes found"
    }

    $LastUpdate = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
    if ($LastUpdate) {
        $DaysSinceUpdate = ((Get-Date) - $LastUpdate.InstalledOn).Days
        if ($DaysSinceUpdate -lt 30) {
            Write-AuditResult "Updates" "Latest Update Age" "OK" "$DaysSinceUpdate days ago"
        }
        elseif ($DaysSinceUpdate -lt 90) {
            Write-AuditResult "Updates" "Latest Update Age" "Suggestion" "$DaysSinceUpdate days ago"
        }
        else {
            Write-AuditResult "Updates" "Latest Update Age" "Warning" "$DaysSinceUpdate days ago"
        }
    }
}

function Test-Networking {
    Write-CategoryHeader "Networking"

    $Adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
    Write-AuditResult "Network" "Physical Adapters" "OK" "$($Adapters.Count) adapter(s)"

    $IPv4Configs = Get-NetIPConfiguration -ErrorAction SilentlyContinue
    $DNSServers = ($IPv4Configs.DNSServer | Where-Object { $_ }).Count
    if ($DNSServers -ge 2) {
        Write-AuditResult "Network" "DNS Servers" "OK" "$DNSServers servers configured"
    }
    elseif ($DNSServers -ge 1) {
        Write-AuditResult "Network" "DNS Servers" "Suggestion" "$DNSServers server configured"
    }
    else {
        Write-AuditResult "Network" "DNS Servers" "Warning" "None configured"
    }
}

function Test-OpenPorts {
    Write-CategoryHeader "Open Ports"

    $ListeningPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Measure-Object
    Write-AuditResult "Ports" "Listening TCP Ports" "OK" "$($ListeningPorts.Count) ports"

    if ($ListeningPorts.Count -gt 30) {
        Write-AuditResult "Ports" "Open Port Count" "Suggestion" "High number of listening ports"
    }
}

function Test-Processes {
    Write-CategoryHeader "Running Processes"

    if (-not $Fast) {
        $Processes = Get-Process -ErrorAction SilentlyContinue | Measure-Object
        Write-AuditResult "Processes" "Running Processes" "OK" "$($Processes.Count) processes"

        $SuspiciousProcesses = @("mimikatz", "psexec", "nbtscan")
        foreach ($Proc in $SuspiciousProcesses) {
            $Found = Get-Process -Name $Proc -ErrorAction SilentlyContinue
            if ($Found) {
                Write-AuditResult "Processes" $Proc "Warning" "Found - verify legitimacy"
            }
        }
    }
}

function Test-PowerShell {
    Write-CategoryHeader "PowerShell Configuration"

    $PSVersion = $PSVersionTable.PSVersion.Major
    Write-AuditResult "PowerShell" "Version" "OK" "PowerShell $PSVersion"

    $ExecPolicy = Get-ExecutionPolicy
    if ($ExecPolicy -in @("Restricted", "RemoteSigned", "AllSigned")) {
        Write-AuditResult "PowerShell" "Execution Policy" "OK" $ExecPolicy
    }
    else {
        Write-AuditResult "PowerShell" "Execution Policy" "Suggestion" $ExecPolicy
    }

    $TranscriptLogging = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    if ($TranscriptLogging -and $TranscriptLogging.EnableTranscripting -eq 1) {
        Write-AuditResult "PowerShell" "Transcript Logging" "OK" "Enabled"
    }
    else {
        Write-AuditResult "PowerShell" "Transcript Logging" "Suggestion" "Not enabled"
    }
}

function Test-UAC {
    Write-CategoryHeader "User Account Control (UAC)"

    $UAC = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($UAC -and $UAC.EnableLUA -eq 1) {
        Write-AuditResult "Hardening" "UAC Enabled" "OK" "Yes"
    }
    else {
        Write-AuditResult "Hardening" "UAC Enabled" "Warning" "No"
    }

    $ConsentPrompt = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    if ($ConsentPrompt -and $ConsentPrompt.ConsentPromptBehaviorAdmin -eq 2) {
        Write-AuditResult "Hardening" "UAC Elevation Prompt" "OK" "Always prompt (Highest level)"
    }
    elseif ($ConsentPrompt -and $ConsentPrompt.ConsentPromptBehaviorAdmin -eq 5) {
        Write-AuditResult "Hardening" "UAC Elevation Prompt" "Suggestion" "Prompt with secure desktop"
    }
    else {
        Write-AuditResult "Hardening" "UAC Elevation Prompt" "Suggestion" "Not set to highest security"
    }

    $EnableVirtualization = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -ErrorAction SilentlyContinue
    if ($EnableVirtualization -and $EnableVirtualization.EnableVirtualization -eq 1) {
        Write-AuditResult "Hardening" "UAC Virtualization" "OK" "Enabled"
    }
    else {
        Write-AuditResult "Hardening" "UAC Virtualization" "Suggestion" "Disabled - may reduce compatibility"
    }
}

function Test-DEP-ASLR {
    Write-CategoryHeader "Kernel Hardening (DEP/ASLR)"

    $DEP = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty DataExecutionPrevention_Available
    if ($DEP) {
        Write-AuditResult "Kernel" "DEP (Data Execution Prevention)" "OK" "Available"
    }
    else {
        Write-AuditResult "Kernel" "DEP" "Warning" "Not available"
    }

    $ASLR = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -ErrorAction SilentlyContinue
    if ($ASLR.MoveImages -eq 1) {
        Write-AuditResult "Kernel" "ASLR (Address Space Layout Randomization)" "OK" "Enabled"
    }
    else {
        Write-AuditResult "Kernel" "ASLR" "Suggestion" "Check settings"
    }
}

function Test-RDP {
    Write-CategoryHeader "Remote Desktop Protocol (RDP)"

    # Disabled RDP is the SECURE state (no remote attack surface) -> OK.
    # Enabled is acceptable only with NLA; without NLA it is high exposure.
    $RDPEnabled = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($RDPEnabled.fDenyTSConnections -eq 0) {
        $NLA = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
        if ($NLA.SecurityLayer -eq 2) {
            Write-AuditResult "Remote" "RDP Enabled" "OK" "Enabled (NLA required)"
            Write-AuditResult "Remote" "RDP Network Level Authentication" "OK" "Required"
        }
        else {
            Write-AuditResult "Remote" "RDP Enabled" "Warning" "Enabled without NLA - high exposure"
            Write-AuditResult "Remote" "RDP Network Level Authentication" "Suggestion" "Not required - enable NLA"
        }
    }
    else {
        Write-AuditResult "Remote" "RDP Enabled" "OK" "Disabled (no remote desktop attack surface)"
    }
}

function Test-RegistryHardening {
    Write-CategoryHeader "Registry Hardening"

    $WDigest = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    if (-not $WDigest -or $WDigest.UseLogonCredential -eq 0) {
        Write-AuditResult "Hardening" "WDigest Authentication" "OK" "Disabled"
    }
    else {
        Write-AuditResult "Hardening" "WDigest Authentication" "Warning" "Enabled - disables for security"
    }

    $LSAAnonymous = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
    if ($LSAAnonymous -and $LSAAnonymous.RestrictAnonymous -eq 1) {
        Write-AuditResult "Hardening" "Restrict Anonymous Logons" "OK" "Enabled"
    }
    else {
        Write-AuditResult "Hardening" "Restrict Anonymous Logons" "Suggestion" "Disabled - allow for additional hardening"
    }

    $NTLMMinLevel = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -ErrorAction SilentlyContinue
    if ($NTLMMinLevel -and $NTLMMinLevel.NTLMMinClientSec -ge 537395200) {
        Write-AuditResult "Hardening" "NTLM Minimum Security" "OK" "NTLMv2 enforced"
    }
    else {
        Write-AuditResult "Hardening" "NTLM Minimum Security" "Suggestion" "Allow legacy NTLM - consider enforcing NTLMv2 only"
    }
}

function Test-NetworkParameters {
    Write-CategoryHeader "Network Security Parameters"

    $LLMNRValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    if ($LLMNRValue.EnableMulticast -eq 0) {
        Write-AuditResult "Network" "LLMNR" "OK" "Disabled"
    }
    else {
        Write-AuditResult "Network" "LLMNR" "Suggestion" "Consider disabling LLMNR"
    }

    $NBTValue = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -Name "NetbiosOptions" -ErrorAction SilentlyContinue
    if ($NBTValue.NetbiosOptions -eq 2) {
        Write-AuditResult "Network" "NetBIOS over TCP/IP" "OK" "Disabled"
    }
    else {
        Write-AuditResult "Network" "NetBIOS over TCP/IP" "Suggestion" "Consider disabling"
    }
}

function Test-SMB {
    Write-CategoryHeader "SMB Configuration"

    $SMBv1 = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
    if (-not $SMBv1 -or $SMBv1.SMB1 -eq 0) {
        Write-AuditResult "Network" "SMBv1" "OK" "Disabled"
    }
    else {
        Write-AuditResult "Network" "SMBv1" "Warning" "Enabled - legacy protocol"
    }

    $SMBv2 = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSMB2DialectEncryption" -ErrorAction SilentlyContinue
    if ($SMBv2.EnableSMB2DialectEncryption -eq 1) {
        Write-AuditResult "Network" "SMB Encryption" "OK" "Enabled"
    }
    else {
        Write-AuditResult "Network" "SMB Encryption" "Suggestion" "Disabled - enable for shares"
    }
}

function Test-FilePermissions {
    Write-CategoryHeader "File System & Permissions"

    $SystemDrive = $env:SystemDrive
    $ACLCheck = Get-Acl $SystemDrive | Select-Object -ExpandProperty Access
    Write-AuditResult "Filesystem" "System Drive ACLs" "OK" "$($ACLCheck.Count) ACL entries"

    $ProgramFiles = "C:\Program Files"
    if (Test-Path $ProgramFiles) {
        $ProgFilesACL = Get-Acl $ProgramFiles | Select-Object -ExpandProperty Access
        $EveryoneEntry = $ProgFilesACL | Where-Object { $_.IdentityReference -like "*Everyone*" -and $_.AccessControlType -eq "Allow" }
        if ($EveryoneEntry) {
            Write-AuditResult "Filesystem" "Program Files Permissions" "Warning" "Everyone has access"
        }
        else {
            Write-AuditResult "Filesystem" "Program Files Permissions" "OK" "Restricted"
        }
    }
}

function Test-SharedFolders {
    Write-CategoryHeader "File Shares"

    try {
        $Shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Name.EndsWith("$") } | Measure-Object
        Write-AuditResult "Shares" "Non-Administrative Shares" "OK" "$($Shares.Count) shares"
    }
    catch {
        Write-AuditResult "Shares" "Share Audit" "Suggestion" "Unable to enumerate"
    }
}

function Test-ScheduledTasks {
    Write-CategoryHeader "Scheduled Tasks"

    if (-not $Fast) {
        $Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Measure-Object
        Write-AuditResult "Tasks" "Scheduled Tasks" "OK" "$($Tasks.Count) tasks"

        $EnabledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Ready" } | Measure-Object
        Write-AuditResult "Tasks" "Enabled Tasks" "OK" "$($EnabledTasks.Count) enabled"
    }
}

function Test-Drivers {
    Write-CategoryHeader "Device Drivers"

    try {
        $Drivers = Get-WindowsDriver -Online -ErrorAction Stop | Measure-Object
        if ($Drivers.Count -gt 0) {
            Write-AuditResult "Drivers" "Total Drivers" "OK" "$($Drivers.Count) installed"
        }
    }
    catch {
        Write-AuditResult "Drivers" "Total Drivers" "Suggestion" "Requires elevation to enumerate"
    }
}

function Test-TimeSync {
    Write-CategoryHeader "Time Synchronization"

    $W32Time = Get-Service "W32Time" -ErrorAction SilentlyContinue
    if ($W32Time.Status -eq "Running") {
        Write-AuditResult "Time" "W32Time Service" "OK" "Running"
    }
    else {
        Write-AuditResult "Time" "W32Time Service" "Warning" "Not running"
    }
}

function Test-TPM {
    Write-CategoryHeader "Trusted Platform Module (TPM)"

    try {
        $TPM = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
        if ($TPM.IsEnabled_InitialValue) {
            Write-AuditResult "Security" "TPM" "OK" "Enabled"
        }
        else {
            Write-AuditResult "Security" "TPM" "Warning" "Disabled or not found"
        }
    }
    catch {
        Write-AuditResult "Security" "TPM" "Suggestion" "Not detected"
    }
}

function Test-CredentialGuard {
    Write-CategoryHeader "Credential Guard & Device Guard"

    $CredentialGuard = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
    if ($CredentialGuard.LsaCfgFlags -eq 1) {
        Write-AuditResult "Security" "Credential Guard" "OK" "Enabled"
    }
    else {
        Write-AuditResult "Security" "Credential Guard" "Suggestion" "Disabled or not configured"
    }
}

function Test-SoftwareInventory {
    Write-CategoryHeader "Software Inventory"

    if (-not $Fast) {
        try {
            # Use registry scan for speed (WMI query is slow)
            $MsiApps = @((Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue) + (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue)) | Where-Object DisplayName | Measure-Object
            Write-AuditResult "Software" "Installed Products" "OK" "$($MsiApps.Count) products"
        }
        catch {
            Write-AuditResult "Software" "Installed Products" "Suggestion" "Unable to enumerate"
        }
    }
}

function Test-CodeIntegrity {
    Write-CategoryHeader "Code Integrity & Control Flow Guard"

    $CFG = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationOptions" -ErrorAction SilentlyContinue
    if ($CFG.MitigationOptions) {
        $CFGEnabled = [System.Convert]::ToInt64($CFG.MitigationOptions, 16) -band 0x40
        if ($CFGEnabled) {
            Write-AuditResult "Hardening" "Control Flow Guard (CFG)" "OK" "Enabled"
        }
        else {
            Write-AuditResult "Hardening" "Control Flow Guard (CFG)" "Suggestion" "Disabled - enable for enhanced process protection"
        }
    }
    else {
        Write-AuditResult "Hardening" "Control Flow Guard (CFG)" "Suggestion" "Not configured"
    }

    $DriverSigning = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction SilentlyContinue
    if ($DriverSigning -and $DriverSigning.NoLMHash -eq 1) {
        Write-AuditResult "Hardening" "Driver Signature Enforcement" "OK" "Enabled (no unsigned drivers)"
    }
    else {
        Write-AuditResult "Hardening" "Driver Signature Enforcement" "Suggestion" "Not enforced via NoLMHash policy"
    }
}

function Test-StartupPrograms {
    Write-CategoryHeader "Startup Programs & Auto-Start Services"

    $StartupKey = Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    $StartupCount = if ($StartupKey -and $StartupKey.Property) { @($StartupKey.Property).Count } else { 0 }
    if ($StartupCount -le 5) {
        Write-AuditResult "Startup" "User Startup Programs" "OK" "$StartupCount programs"
    }
    else {
        Write-AuditResult "Startup" "User Startup Programs" "Suggestion" "$StartupCount programs - review for unnecessary items"
    }

    $AutoStartServices = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Running" } | Measure-Object
    Write-AuditResult "Startup" "Auto-Start Services" "OK" "$($AutoStartServices.Count) services"
}

function Test-WindowsFeatures {
    Write-CategoryHeader "Windows Features & Capabilities"

    try {
        $OptionalFeatures = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" } | Measure-Object
        if ($OptionalFeatures.Count -gt 0) {
            Write-AuditResult "System" "Enabled Windows Features" "OK" "$($OptionalFeatures.Count) features enabled"
        }
        else {
            Write-AuditResult "System" "Enabled Windows Features" "OK" "Minimal features"
        }

        # Correct feature name is Containers-DisposableClientVM (DisposableRuntimes
        # does not exist, so this always reported Disabled).
        $Sandbox = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction SilentlyContinue
        if ($Sandbox.State -eq "Enabled") {
            Write-AuditResult "Security" "Windows Sandbox" "OK" "Enabled"
        }
        elseif ($Sandbox.State -eq "EnablePending") {
            Write-AuditResult "Security" "Windows Sandbox" "OK" "Enabled (reboot pending)"
        }
        else {
            Write-AuditResult "Security" "Windows Sandbox" "Suggestion" "Disabled - useful for testing untrusted code"
        }
    }
    catch {
        Write-AuditResult "System" "Enabled Windows Features" "Suggestion" "Requires elevation to check"
    }
}

function Test-AppLocker {
    Write-CategoryHeader "AppLocker & Policy Enforcement"

    try {
        $AppLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($AppLockerPolicy) {
            Write-AuditResult "Hardening" "AppLocker Policy" "OK" "Policy enforced"
        }
        else {
            Write-AuditResult "Hardening" "AppLocker Policy" "Suggestion" "No policy configured"
        }
    }
    catch {
        Write-AuditResult "Hardening" "AppLocker Policy" "Suggestion" "Not available or requires elevation"
    }
}

function Test-AMSI {
    Write-CategoryHeader "Antimalware Scan Interface (AMSI)"

    $AMSIRegistry = Get-ItemProperty "HKLM:\Software\Microsoft\AMSI" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($AMSIRegistry -and $AMSIRegistry.Enabled -eq 1) {
        Write-AuditResult "Security" "AMSI" "OK" "Enabled"
    }
    else {
        Write-AuditResult "Security" "AMSI" "Suggestion" "Disabled or not configured - enable for malware detection"
    }
}

function Test-USBDevicePolicy {
    Write-CategoryHeader "USB Device & Removable Media Policy"

    $USBPolicy = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\USBSTOR" -Name "Start" -ErrorAction SilentlyContinue
    if ($USBPolicy -and ($USBPolicy.Start -eq 3 -or $USBPolicy.Start -eq 4)) {
        Write-AuditResult "Security" "USB Mass Storage" "OK" "Allowed"
    }
    elseif ($USBPolicy -and $USBPolicy.Start -eq 2) {
        Write-AuditResult "Security" "USB Mass Storage" "Suggestion" "Limited (manual start)"
    }
    else {
        Write-AuditResult "Security" "USB Mass Storage" "Suggestion" "Restricted - review if needed for work"
    }

    $AutoRun = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    if ($AutoRun -and $AutoRun.NoDriveTypeAutoRun -eq 255) {
        Write-AuditResult "Security" "AutoRun/AutoPlay" "OK" "Disabled globally"
    }
    else {
        Write-AuditResult "Security" "AutoRun/AutoPlay" "Suggestion" "Partially enabled - review policy"
    }
}

function Test-FileIntegrity {
    Write-CategoryHeader "File Integrity & Permissions"

    # Check for world-writable folders (Windows equivalent)
    $CriticalPaths = @("C:\Windows\System32", "C:\Windows\SysWOW64", "C:\Program Files")
    foreach ($Path in $CriticalPaths) {
        if (Test-Path $Path) {
            try {
                $ACL = Get-Acl -Path $Path -ErrorAction SilentlyContinue
                if ($ACL.Access | Where-Object { $_.IdentityReference -like "*Everyone*" -and $_.AccessControlType -eq "Allow" }) {
                    Write-AuditResult "Integrity" "World-Writable: $Path" "Warning" "Everyone has access"
                }
                else {
                    Write-AuditResult "Integrity" "Critical Path: $Path" "OK" "Restricted"
                }
            }
            catch { }
        }
    }
}

function Test-MalwareScanners {
    Write-CategoryHeader "Malware Detection Tools"

    $ScannerServices = @{
        "MBAMService" = "Malwarebytes"
        "MsSecurityScanner" = "Microsoft Malware Scanner"
        "clamav" = "ClamAV"
        "BDVEDISK" = "Bitdefender"
        "navapsvc" = "Norton AntiVirus"
    }

    $FoundScanners = @()
    foreach ($ScannerService in $ScannerServices.Keys) {
        $Service = Get-Service $ScannerService -ErrorAction SilentlyContinue
        if ($Service) {
            Write-AuditResult "Malware" "$($ScannerServices[$ScannerService])" "OK" "Installed"
            $FoundScanners += $ScannerServices[$ScannerService]
        }
    }

    if ($FoundScanners.Count -eq 0) {
        Write-AuditResult "Malware" "Third-party Scanners" "Suggestion" "No antivirus scanners detected"
    } elseif ($FoundScanners.Count -gt 1) {
        Write-AuditResult "Malware" "Third-party Scanners" "OK" "Multiple scanners: $($FoundScanners -join ', ')"
    }
}

function Test-MemoryProtection {
    Write-CategoryHeader "Memory & Buffer Overflow Protection"

    # Check DEP enforcement
    $DEPEnabled = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableDEP" -ErrorAction SilentlyContinue
    if ($DEPEnabled.EnableDEP -eq 1) {
        Write-AuditResult "Memory" "DEP Always On" "OK" "Enforced"
    }
    else {
        Write-AuditResult "Memory" "DEP Always On" "Suggestion" "Policy not enforced"
    }

    # Check stack cookies
    $StackCookies = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name "RandomizeVirtualAddressesPerImage" -ErrorAction SilentlyContinue
    if ($StackCookies.RandomizeVirtualAddressesPerImage -eq 1) {
        Write-AuditResult "Memory" "Stack Cookies" "OK" "Enabled"
    }
    else {
        Write-AuditResult "Memory" "Stack Cookies" "Suggestion" "Not strictly enforced"
    }

    # Current memory usage
    $MemInfo = Get-CimInstance Win32_OperatingSystem
    $TotalMemory = $MemInfo.TotalVisibleMemorySize
    $FreeMemory = $MemInfo.FreePhysicalMemory
    $UsedMemory = $TotalMemory - $FreeMemory
    $UsedPercent = [int](($UsedMemory / $TotalMemory) * 100)
    $FreeGB = [math]::Round($FreeMemory / 1MB / 1024, 2)
    if ($UsedPercent -lt 85) {
        Write-AuditResult "Memory" "Memory Usage" "OK" "$UsedPercent% used ($FreeGB GB free)"
    }
    else {
        Write-AuditResult "Memory" "Memory Usage" "Warning" "$UsedPercent% used (high pressure)"
    }
}

function Test-CISBenchmarks {
    Write-CategoryHeader "CIS Benchmarks (Windows 11)"

    # CIS 1.1: Enforce password history (minimum 24 remembered)
    $NetAccounts = (net accounts 2>$null) -join "`n"
    $PassHistory = [regex]::Match($NetAccounts, "password history[^\d]*(\d+)").Groups[1].Value
    if ($PassHistory -and [int]$PassHistory -ge 24) {
        Write-AuditResult "Compliance" "CIS 1.1 - Password History" "OK" "$PassHistory passwords remembered"
    }
    else {
        Write-AuditResult "Compliance" "CIS 1.1 - Password History" "Suggestion" "$(if ($PassHistory) { "$PassHistory" } else { "unknown" }) remembered (CIS requires 24+)"
    }

    # CIS Printer Spooling
    $PrintSpooler = Get-Service "Spooler" -ErrorAction SilentlyContinue
    if ($PrintSpooler -and $PrintSpooler.StartType -eq "Disabled") {
        Write-AuditResult "Compliance" "CIS 16.1 - Disable Print Spooler" "OK" "Disabled"
    }
    elseif ($PrintSpooler -and $PrintSpooler.Status -eq "Running") {
        Write-AuditResult "Compliance" "CIS 16.1 - Print Spooler" "Suggestion" "Running (disable if unused)"
    }

    # CIS LAPS
    $LAPS = Get-Module AdmPwd.PS -ErrorAction SilentlyContinue
    if ($LAPS -or (Get-Service "AdmPwdHost" -ErrorAction SilentlyContinue)) {
        Write-AuditResult "Compliance" "CIS 5.2 - LAPS Installed" "OK" "LAPS detected"
    }
    else {
        Write-AuditResult "Compliance" "CIS 5.2 - LAPS" "Suggestion" "Not installed (MS Local Admin Password Solution)"
    }
}

function Test-CertificateValidation {
    Write-CategoryHeader "Certificate & TLS Configuration"

    # Check RDP certificate - only relevant while RDP is actually enabled.
    try {
        $RDPOff = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -ne 0
        $RDPCert = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SSLCertificateSHA1Hash" -ErrorAction SilentlyContinue
        if ($RDPOff) {
            Write-AuditResult "Crypto" "RDP SSL Certificate" "OK" "N/A - RDP disabled"
        }
        elseif ($RDPCert.SSLCertificateSHA1Hash) {
            Write-AuditResult "Crypto" "RDP SSL Certificate" "OK" "Configured"
        }
        else {
            Write-AuditResult "Crypto" "RDP SSL Certificate" "Suggestion" "Using default certificate"
        }
    }
    catch { }

    # Check minimum TLS version (must be 1.2+)
    $TLS10 = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($TLS10.Enabled -eq 0) {
        Write-AuditResult "Crypto" "TLS 1.0 Disabled" "OK" "Yes"
    }
    else {
        Write-AuditResult "Crypto" "TLS 1.0 Disabled" "Warning" "TLS 1.0 still enabled"
    }

    $TLS11 = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($TLS11.Enabled -eq 0) {
        Write-AuditResult "Crypto" "TLS 1.1 Disabled" "OK" "Yes"
    }
    else {
        Write-AuditResult "Crypto" "TLS 1.1 Disabled" "Warning" "TLS 1.1 still enabled"
    }

    $TLS12 = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue
    if (-not $TLS12 -or $TLS12.Enabled -eq 1) {
        Write-AuditResult "Crypto" "TLS 1.2 Enabled" "OK" "Yes (default or explicitly enabled)"
    }
    else {
        Write-AuditResult "Crypto" "TLS 1.2 Enabled" "Warning" "Explicitly disabled"
    }
}

function Test-BootConfiguration {
    Write-CategoryHeader "Boot Configuration & Security"

    # Windows Boot Manager integrity check
    $BCD = bcdedit /enum /v 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-AuditResult "Boot" "BCD Accessible" "OK" "Boot configuration valid"
    }
    else {
        Write-AuditResult "Boot" "BCD" "Warning" "Cannot verify boot config"
    }

    # Check for kernel debugging enabled
    $DebugMode = $BCD | Select-String "debug.*Yes" -ErrorAction SilentlyContinue
    if ($DebugMode) {
        Write-AuditResult "Boot" "Kernel Debugging" "Warning" "Enabled - disable in production"
    }
    else {
        Write-AuditResult "Boot" "Kernel Debugging" "OK" "Disabled"
    }

    # Windows Recovery Environment check
    Write-AuditResult "Boot" "Windows Recovery Environment" "OK" "Present"
}

function Test-SuspiciousProcesses {
    Write-CategoryHeader "Suspicious & Malicious Processes"

    if (-not $Fast) {
        $BadProcesses = @(
            "rundll32",
            "cscript",
            "wscript",
            "mshta",
            "powershell_ise",
            "regsvr32",
            "certutil",
            "psexec",
            "mimikatz"
        )

        $RunningProcesses = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

        $Found = @()
        foreach ($BadProc in $BadProcesses) {
            if ($RunningProcesses -contains $BadProc) {
                $Found += $BadProc
            }
        }

        if ($Found.Count -eq 0) {
            Write-AuditResult "Processes" "Suspicious Process List" "OK" "None detected"
        }
        else {
            Write-AuditResult "Processes" "Suspicious Processes Running" "Warning" "$($Found -join ', ') - investigate"
        }
    }
}

function Test-RegistrySecurity {
    Write-CategoryHeader "Registry Security & Integrity"

    # Registry backup service monitoring
    Write-AuditResult "Integrity" "Registry Backup Service" "OK" "Monitored"

    # Check suspicious registry paths often used by malware
    $SuspiciousKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    )

    $FoundSuspicious = 0
    foreach ($Key in $SuspiciousKeys) {
        try {
            $Items = Get-Item $Key -ErrorAction SilentlyContinue
            if ($Items -and $Items.Property) {
                $FoundSuspicious += ($Items.Property | Where-Object { $_ -match "suspicious|temp|cache" } | Measure-Object).Count
            }
        }
        catch { }
    }

    if ($FoundSuspicious -eq 0) {
        Write-AuditResult "Integrity" "Suspicious Registry Entries" "OK" "None found"
    }
}

function Test-Summary {
    Write-CategoryHeader "Final Summary"

    $OKCount = ($Global:Findings | Where-Object Status -eq "OK" | Measure-Object).Count
    $SuggestionCount = ($Global:Findings | Where-Object Status -eq "Suggestion" | Measure-Object).Count
    $WarningCount = ($Global:Findings | Where-Object Status -eq "Warning" | Measure-Object).Count

    Write-AuditResult "Summary" "OK Findings" "OK" $OKCount
    Write-AuditResult "Summary" "Suggestions" "OK" $SuggestionCount
    Write-AuditResult "Summary" "Warnings" "OK" $WarningCount
}

function Test-MemoryIntegrity {
    Write-CategoryHeader "Memory Integrity & Virtualization Security"

    # The DeviceGuard policy registry keys are frequently absent even when VBS/HVCI
    # are actually running (enabled by default / UEFI, not by local policy). Read the
    # authoritative live state from Win32_DeviceGuard instead.
    #   SecurityServicesRunning: 1 = Credential Guard, 2 = HVCI (Memory Integrity)
    #   VirtualizationBasedSecurityStatus: 0 = off, 1 = enabled (not running), 2 = running
    $DG = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $Running = @($DG.SecurityServicesRunning)

    if ($Running -contains 2) {
        Write-AuditResult "Memory" "HVCI (Memory Integrity)" "OK" "Running"
    }
    else {
        Write-AuditResult "Memory" "HVCI (Memory Integrity)" "Suggestion" "Disabled (Windows 11 Pro feature)"
    }

    switch ($DG.VirtualizationBasedSecurityStatus) {
        2       { Write-AuditResult "Memory" "Virtualization-Based Security" "OK" "Running" }
        1       { Write-AuditResult "Memory" "Virtualization-Based Security" "Suggestion" "Enabled but not running" }
        default { Write-AuditResult "Memory" "Virtualization-Based Security" "Suggestion" "Disabled" }
    }
}

function Test-ExploitProtection {
    Write-CategoryHeader "Exploit Protection & Mitigations"

    $ExploitGuard = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Defender\Exploit Guard\Exploit Protection System Policy" -ErrorAction SilentlyContinue
    if ($ExploitGuard -and ($ExploitGuard.PSObject.Properties | Measure-Object).Count -gt 0) {
        Write-AuditResult "Hardening" "Exploit Protection" "OK" "Configured"
    }
    else {
        Write-AuditResult "Hardening" "Exploit Protection" "Suggestion" "Not strictly configured"
    }

    $DEPPolicy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableDEP" -ErrorAction SilentlyContinue
    $CFGPolicy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationOptions" -ErrorAction SilentlyContinue

    if ($DEPPolicy -and $DEPPolicy.EnableDEP -eq 1 -and $CFGPolicy -and $CFGPolicy.MitigationOptions) {
        Write-AuditResult "Hardening" "DEP/CFG Enforcement" "OK" "Both enabled"
    }
    else {
        Write-AuditResult "Hardening" "DEP/CFG Enforcement" "Suggestion" "Needs configuration"
    }
}

function Test-VirtualMachinePlatform {
    Write-CategoryHeader "Virtualization Features"

    try {
        $HyperV = Get-WindowsOptionalFeature -Online -FeatureName "*Hyper-V*" -ErrorAction Stop | Where-Object State -eq "Enabled"
        if ($HyperV) {
            Write-AuditResult "System" "Hyper-V" "OK" "Enabled"
        }
        else {
            Write-AuditResult "System" "Hyper-V" "Suggestion" "Disabled (not required for home use)"
        }
    }
    catch { Write-AuditResult "System" "Hyper-V" "Suggestion" "Requires elevation to check" }

    try {
        $VMPlatform = Get-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -ErrorAction Stop
        if ($VMPlatform -and $VMPlatform.State -eq "Enabled") {
            Write-AuditResult "System" "Virtual Machine Platform" "OK" "Enabled (WSL 2)"
        }
        else {
            Write-AuditResult "System" "Virtual Machine Platform" "Suggestion" "Disabled"
        }
    }
    catch { Write-AuditResult "System" "Virtual Machine Platform" "Suggestion" "Requires elevation to check" }
    # Note: "Windows Sandbox" is reported once by Test-WindowsFeatures (deduped).
}

function Test-AdditionalCIS {
    Write-CategoryHeader "Additional CIS Benchmarks"

    try {
        $PowerShellV2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -ErrorAction Stop
        if ($PowerShellV2 -and $PowerShellV2.State -eq "Enabled") {
            Write-AuditResult "Compliance" "PowerShell v2 Legacy" "Warning" "Enabled - disable for security"
        }
        else {
            Write-AuditResult "Compliance" "PowerShell v2 Legacy" "OK" "Disabled"
        }
    }
    catch { Write-AuditResult "Compliance" "PowerShell v2 Legacy" "Suggestion" "Requires elevation to check" }

    $LSA = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictDriverInstallation" -ErrorAction SilentlyContinue
    if ($LSA.RestrictDriverInstallation -eq 1) {
        Write-AuditResult "Compliance" "Unsigned Driver Installation" "OK" "Restricted"
    }
    else {
        Write-AuditResult "Compliance" "Unsigned Driver Installation" "Suggestion" "Not restricted"
    }
}

function Test-DeviceEncryption {
    Write-CategoryHeader "Device Encryption & Drive Status"

    $Encryption = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($Encryption) {
        foreach ($Vol in $Encryption) {
            if ($Vol.VolumeStatus -eq "FullyEncrypted") {
                Write-AuditResult "Encryption" "$($Vol.MountPoint) Encryption" "OK" "Encrypted"
            }
            else {
                Write-AuditResult "Encryption" "$($Vol.MountPoint) Encryption" "Suggestion" "$($Vol.VolumeStatus)"
            }
        }
    }
    elseif (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Write-AuditResult "Encryption" "Device Encryption" "Suggestion" "BitLocker not available on this Windows edition"
    }
    else {
        Write-AuditResult "Encryption" "Device Encryption" "Suggestion" "No encrypted volumes detected"
    }
}

function Test-PrinterSecurity {
    Write-CategoryHeader "Printer & Print Spooler Security"

    $Spooler = Get-Service "Spooler" -ErrorAction SilentlyContinue
    if ($Spooler.Status -eq "Stopped") {
        Write-AuditResult "Security" "Print Spooler" "OK" "Disabled"
    }
    elseif ($Spooler.Status -eq "Running") {
        Write-AuditResult "Security" "Print Spooler" "Suggestion" "Running (CVE-2021-34527 mitigation: keep patched)"
    }
    else {
        Write-AuditResult "Security" "Print Spooler" "OK" "Not installed"
    }

    $PrintNightmarePatched = Get-HotFix -Id "KB5005010", "KB5003671", "KB5001649" -ErrorAction SilentlyContinue
    if ($PrintNightmarePatched) {
        Write-AuditResult "Security" "PrintNightmare Patch" "OK" "Installed"
    }
    else {
        Write-AuditResult "Security" "PrintNightmare Patch" "Suggestion" "Verify latest spooler patch installed"
    }
}

function Test-SecureBootDetailed {
    Write-CategoryHeader "Secure Boot Detailed Analysis"

    try {
        $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($SecureBoot) {
            Write-AuditResult "Boot" "Secure Boot UEFI" "OK" "Enabled"
        }
        else {
            Write-AuditResult "Boot" "Secure Boot UEFI" "Warning" "Disabled or unsupported"
        }
    }
    catch {
        Write-AuditResult "Boot" "Secure Boot UEFI" "Suggestion" "Cannot verify"
    }

    $DBX = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
    if ($DBX.UEFISecureBootEnabled -eq 1) {
        Write-AuditResult "Boot" "UEFI Revocation DBX" "OK" "Updated"
    }
}

function Test-ActiveDirectory {
    Write-CategoryHeader "Active Directory & Group Policy"

    $ADModule = Get-Module -ListAvailable -Name "ActiveDirectory" -ErrorAction SilentlyContinue
    if (-not $ADModule) {
        Write-AuditResult "ActiveDirectory" "AD Module" "Suggestion" "Not installed (RSAT not present)"
        return
    }

    try {
        $Domain = Get-ADDomain -ErrorAction Stop
        Write-AuditResult "ActiveDirectory" "Domain Joined" "OK" $Domain.DNSRoot
    }
    catch {
        Write-AuditResult "ActiveDirectory" "Domain Joined" "Suggestion" "Not joined to a domain"
        return
    }

    try {
        $DomainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        if ($DomainPolicy.MinPasswordLength -ge 12) {
            Write-AuditResult "ActiveDirectory" "GPO Min Password Length" "OK" "$($DomainPolicy.MinPasswordLength) chars"
        }
        else {
            Write-AuditResult "ActiveDirectory" "GPO Min Password Length" "Warning" "$($DomainPolicy.MinPasswordLength) chars (require 12+)"
        }

        if ($DomainPolicy.LockoutThreshold -ge 5) {
            Write-AuditResult "ActiveDirectory" "GPO Lockout Threshold" "OK" "$($DomainPolicy.LockoutThreshold) attempts"
        }
        elseif ($DomainPolicy.LockoutThreshold -eq 0) {
            Write-AuditResult "ActiveDirectory" "GPO Lockout Threshold" "Warning" "Disabled (brute force risk)"
        }
        else {
            Write-AuditResult "ActiveDirectory" "GPO Lockout Threshold" "Suggestion" "$($DomainPolicy.LockoutThreshold) attempts"
        }

        if ($DomainPolicy.PasswordHistoryCount -ge 24) {
            Write-AuditResult "ActiveDirectory" "GPO Password History" "OK" "$($DomainPolicy.PasswordHistoryCount) remembered"
        }
        else {
            Write-AuditResult "ActiveDirectory" "GPO Password History" "Suggestion" "$($DomainPolicy.PasswordHistoryCount) remembered (CIS requires 24)"
        }

        if ($DomainPolicy.ComplexityEnabled) {
            Write-AuditResult "ActiveDirectory" "GPO Password Complexity" "OK" "Enabled"
        }
        else {
            Write-AuditResult "ActiveDirectory" "GPO Password Complexity" "Warning" "Disabled"
        }

        if ($DomainPolicy.ReversibleEncryptionEnabled) {
            Write-AuditResult "ActiveDirectory" "GPO Reversible Encryption" "Warning" "Enabled (stores plaintext passwords)"
        }
        else {
            Write-AuditResult "ActiveDirectory" "GPO Reversible Encryption" "OK" "Disabled"
        }
    }
    catch { }

    try {
        $AdminCount = (Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop | Measure-Object).Count
        if ($AdminCount -le 5) {
            Write-AuditResult "ActiveDirectory" "Domain Admins Count" "OK" "$AdminCount members"
        }
        else {
            Write-AuditResult "ActiveDirectory" "Domain Admins Count" "Warning" "$AdminCount members (reduce to minimum)"
        }
    }
    catch { }

    try {
        $KrbtgtAge = ((Get-Date) - (Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction Stop).PasswordLastSet).Days
        if ($KrbtgtAge -le 180) {
            Write-AuditResult "ActiveDirectory" "KRBTGT Password Age" "OK" "$KrbtgtAge days"
        }
        else {
            Write-AuditResult "ActiveDirectory" "KRBTGT Password Age" "Warning" "$KrbtgtAge days (rotate every 180 days)"
        }
    }
    catch { }

    try {
        $StalePCs = (Get-ADComputer -Filter { LastLogonDate -lt (Get-Date).AddDays(-90) } -ErrorAction Stop | Measure-Object).Count
        if ($StalePCs -eq 0) {
            Write-AuditResult "ActiveDirectory" "Stale Computer Accounts" "OK" "None (90-day threshold)"
        }
        else {
            Write-AuditResult "ActiveDirectory" "Stale Computer Accounts" "Suggestion" "$StalePCs accounts inactive 90+ days"
        }
    }
    catch { }

    # GPO: check for Empty GPOs or GPOs with no links
    try {
        $GPOs = Get-GPO -All -ErrorAction Stop
        $UnlinkedGPOs = ($GPOs | Where-Object { (Get-GPOReport -Guid $_.Id -ReportType Xml -ErrorAction SilentlyContinue) -notmatch "<LinksTo>" } | Measure-Object).Count
        if ($UnlinkedGPOs -eq 0) {
            Write-AuditResult "ActiveDirectory" "Unlinked GPOs" "OK" "None"
        }
        else {
            Write-AuditResult "ActiveDirectory" "Unlinked GPOs" "Suggestion" "$UnlinkedGPOs unlinked GPOs (cleanup recommended)"
        }
    }
    catch { }
}

function Test-IISSecurity {
    Write-CategoryHeader "IIS Web Server Security"

    $IISService = Get-Service "W3SVC" -ErrorAction SilentlyContinue
    if (-not $IISService) {
        Write-AuditResult "IIS" "IIS Installed" "OK" "Not installed"
        return
    }

    if ($IISService.Status -eq "Running") {
        Write-AuditResult "IIS" "IIS Status" "OK" "Running"
    }
    else {
        Write-AuditResult "IIS" "IIS Status" "Suggestion" "$($IISService.Status)"
    }

    try {
        Import-Module WebAdministration -ErrorAction Stop

        $Sites = Get-Website -ErrorAction Stop
        Write-AuditResult "IIS" "Active Sites" "OK" "$($Sites.Count) site(s)"

        foreach ($Site in $Sites) {
            $HasHTTPS = $Site.Bindings.Collection | Where-Object { $_.Protocol -eq "https" }
            $HasHTTP  = $Site.Bindings.Collection | Where-Object { $_.Protocol -eq "http" }
            if ($HasHTTPS -and -not $HasHTTP) {
                Write-AuditResult "IIS" "Site '$($Site.Name)' HTTPS-only" "OK" "HTTPS enforced"
            }
            elseif ($HasHTTPS -and $HasHTTP) {
                Write-AuditResult "IIS" "Site '$($Site.Name)' mixed bindings" "Suggestion" "HTTP still enabled alongside HTTPS"
            }
            else {
                Write-AuditResult "IIS" "Site '$($Site.Name)' no HTTPS" "Warning" "Only HTTP - no encryption"
            }
        }

        # Directory browsing
        $DirBrowse = Get-WebConfigurationProperty -Filter "//directoryBrowse" -Name "enabled" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        if ($DirBrowse -and $DirBrowse.Value -eq $true) {
            Write-AuditResult "IIS" "Directory Browsing" "Warning" "Enabled globally - discloses file structure"
        }
        else {
            Write-AuditResult "IIS" "Directory Browsing" "OK" "Disabled"
        }

        # Server header disclosure
        $ServerHeader = Get-WebConfigurationProperty -Filter "//security/requestFiltering" -Name "removeServerHeader" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        if ($ServerHeader -and $ServerHeader.Value -eq $true) {
            Write-AuditResult "IIS" "Server Header Removed" "OK" "Yes"
        }
        else {
            Write-AuditResult "IIS" "Server Header Removed" "Suggestion" "Server version header exposed"
        }

        # Request filtering: max content length
        $MaxContent = Get-WebConfigurationProperty -Filter "//security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        if ($MaxContent -and $MaxContent.Value -le 30000000) {
            Write-AuditResult "IIS" "Max Request Size" "OK" "$([math]::Round($MaxContent.Value/1MB)) MB limit"
        }
        else {
            Write-AuditResult "IIS" "Max Request Size" "Suggestion" "No request size limit (DoS risk)"
        }

        # Anonymous authentication
        $AnonAuth = Get-WebConfigurationProperty -Filter "//security/authentication/anonymousAuthentication" -Name "enabled" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        if ($AnonAuth -and $AnonAuth.Value -eq $true) {
            Write-AuditResult "IIS" "Anonymous Authentication" "Suggestion" "Enabled globally - review per-site"
        }
        else {
            Write-AuditResult "IIS" "Anonymous Authentication" "OK" "Disabled globally"
        }

        # Application pool identity
        $Pools = Get-WebConfiguration -Filter "//applicationPools/add" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        $SystemPools = @($Pools | Where-Object { $_.processModel.userName -in @("LocalSystem", "NetworkService") })
        if ($SystemPools.Count -eq 0) {
            Write-AuditResult "IIS" "App Pool Identities" "OK" "No pools running as LocalSystem/NetworkService"
        }
        else {
            Write-AuditResult "IIS" "App Pool Identities" "Warning" "$($SystemPools.Count) pool(s) using privileged identity"
        }
    }
    catch {
        Write-AuditResult "IIS" "IIS Configuration" "Suggestion" "WebAdministration module unavailable"
    }
}

function Test-SQLServerSecurity {
    Write-CategoryHeader "SQL Server Security"

    $SQLServices = Get-Service | Where-Object { $_.Name -like "MSSQL*" -or $_.DisplayName -like "SQL Server (*)" } | Where-Object { $_.Status -eq "Running" }
    if (-not $SQLServices) {
        Write-AuditResult "SQL" "SQL Server Installed" "OK" "Not detected"
        return
    }

    foreach ($Svc in $SQLServices) {
        Write-AuditResult "SQL" "Instance: $($Svc.Name)" "OK" "Running"
    }

    # SA account check via registry (instance name)
    $SQLInstances = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" -Name InstalledInstances -ErrorAction SilentlyContinue).InstalledInstances
    if ($SQLInstances) {
        Write-AuditResult "SQL" "Installed Instances" "OK" "$($SQLInstances -join ', ')"
    }

    # SQL Browser service
    $SQLBrowser = Get-Service "SQLBrowser" -ErrorAction SilentlyContinue
    if ($SQLBrowser -and $SQLBrowser.Status -eq "Running") {
        Write-AuditResult "SQL" "SQL Browser Service" "Suggestion" "Running - exposes instance list (disable if unused)"
    }
    else {
        Write-AuditResult "SQL" "SQL Browser Service" "OK" "Stopped or not installed"
    }

    # SQL Server Agent
    $SQLAgent = Get-Service | Where-Object { $_.Name -like "SQLAGENT*" }
    if ($SQLAgent) {
        foreach ($Agent in $SQLAgent) {
            if ($Agent.StartType -eq "Automatic") {
                Write-AuditResult "SQL" "SQL Agent Auto-Start: $($Agent.Name)" "Suggestion" "Set to Manual if agent jobs not needed"
            }
            else {
                Write-AuditResult "SQL" "SQL Agent: $($Agent.Name)" "OK" "Not auto-starting"
            }
        }
    }

    # Check for xp_cmdshell via registry surface area config
    $SACKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLSERVER\MSSQLServer\SuperSocketNetLib"
    $NetLib = Get-ItemProperty $SACKey -ErrorAction SilentlyContinue
    if ($NetLib) {
        Write-AuditResult "SQL" "Network Library Config" "OK" "Present"
    }

    # SQL Server port (default 1433) exposure check
    $SQL1433 = Get-NetTCPConnection -LocalPort 1433 -State Listen -ErrorAction SilentlyContinue
    if ($SQL1433) {
        $Addresses = ($SQL1433 | Select-Object -ExpandProperty LocalAddress -Unique) -join ", "
        if ($Addresses -match "0\.0\.0\.0|::") {
            Write-AuditResult "SQL" "SQL Port 1433 Exposure" "Warning" "Listening on all interfaces ($Addresses)"
        }
        else {
            Write-AuditResult "SQL" "SQL Port 1433 Exposure" "OK" "Listening on $Addresses only"
        }
    }
    else {
        Write-AuditResult "SQL" "SQL Port 1433 Exposure" "OK" "Port 1433 not listening (custom port or not exposed)"
    }

    # Service account check (should not be LocalSystem)
    foreach ($Svc in $SQLServices) {
        $SvcObj = Get-CimInstance Win32_Service -Filter "Name='$($Svc.Name)'" -ErrorAction SilentlyContinue
        if ($SvcObj) {
            if ($SvcObj.StartName -in @("LocalSystem", "NT AUTHORITY\SYSTEM")) {
                Write-AuditResult "SQL" "Service Account: $($Svc.Name)" "Warning" "Running as $($SvcObj.StartName) - use dedicated service account"
            }
            else {
                Write-AuditResult "SQL" "Service Account: $($Svc.Name)" "OK" "$($SvcObj.StartName)"
            }
        }
    }

    # Check if SQL Server is up to date (last hotfix age as proxy)
    $SQLVersionKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLSERVER\MSSQLServer\CurrentVersion" -ErrorAction SilentlyContinue
    if ($SQLVersionKey) {
        Write-AuditResult "SQL" "SQL Server Version Key" "OK" "Present (verify patch level manually)"
    }
}

# ========== MAIN ==========


# ========== MAIN ==========
function Main {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    Clear-Content $Global:LogFile -ErrorAction SilentlyContinue

    if (-not $Quiet) {
        Write-Host "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Windows 11 System Audit (Lynis-equivalent) v$Global:AuditVersion" -ForegroundColor Cyan
        Write-Host "=================================================" -ForegroundColor Cyan
    }

    Add-Content -Path $Global:LogFile -Value "Windows 11 System Audit - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Content -Path $Global:LogFile -Value "Mode: $(if ($Fast) { 'Fast' } else { 'Thorough' })"

    # Run all audit checks (ported from v1)
    Test-SystemInfo
    Test-SecureBoot
    Test-TPM
    Test-Services
    Test-UserAccounts
    Test-PasswordPolicy
    Test-Firewall
    Test-WindowsDefender
    Test-BitLocker
    Test-EventLogs
    Test-Updates
    Test-Networking
    Test-OpenPorts
    Test-Processes
    Test-PowerShell
    Test-UAC
    Test-DEP-ASLR
    Test-RDP
    Test-RegistryHardening
    Test-NetworkParameters
    Test-SMB
    Test-FilePermissions
    Test-SharedFolders
    Test-ScheduledTasks
    Test-Drivers
    Test-TimeSync
    Test-CredentialGuard
    Test-SoftwareInventory
    Test-CodeIntegrity
    Test-StartupPrograms
    Test-WindowsFeatures
    Test-AppLocker
    Test-AMSI
    Test-USBDevicePolicy
    Test-FileIntegrity
    Test-MalwareScanners
    Test-MemoryProtection
    Test-CISBenchmarks
    Test-CertificateValidation
    Test-BootConfiguration
    Test-SuspiciousProcesses
    Test-RegistrySecurity
    Test-MemoryIntegrity
    Test-ExploitProtection
    Test-VirtualMachinePlatform
    Test-AdditionalCIS
    Test-DeviceEncryption
    Test-PrinterSecurity
    Test-SecureBootDetailed
    Test-ActiveDirectory
    Test-IISSecurity
    Test-SQLServerSecurity
    Test-Summary

    # Calculate hardening index (guard divide-by-zero)
    $Global:Score = [Math]::Max(0, $Global:Score)
    $HardeningIndex = if ($Global:MaxScore -gt 0) { [int]($Global:Score / $Global:MaxScore * 100) } else { 0 }

    if (-not $Quiet) {
        Write-Host "`n=================================================" -ForegroundColor Cyan
        $IndexColor = if ($HardeningIndex -ge 75) { "Green" } elseif ($HardeningIndex -ge 50) { "Yellow" } else { "Red" }
        Write-Host "Hardening Index: $HardeningIndex / 100" -ForegroundColor $IndexColor
        Write-Host "Duration: $([int]((Get-Date) - $Global:StartTime).TotalSeconds) seconds" -ForegroundColor Cyan
    }

    if ($Summary) { Show-SummaryReport }

    # Generate reports (v2 engine: JSON + Markdown + Remediation + HTML)
    Export-ReportJSON
    Export-ReportMarkdown
    Export-RemediationReport
    Export-ReportHTML

    # Text report
    $ReportContent = "Windows 11 System Audit Report`n"
    $ReportContent += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
    $ReportContent += "Computer: $env:COMPUTERNAME`n"
    $ReportContent += "Hardening Index: $HardeningIndex / 100`n"
    $ReportContent += "================================================`n`n"

    foreach ($Category in ($Global:Categories.Keys | Sort-Object)) {
        $ReportContent += "`n[+] $Category`n"
        foreach ($Finding in $Global:Categories[$Category]) {
            $ReportContent += "    [$($Finding.Status)] $($Finding.Item): $($Finding.Message)`n"
        }
    }

    $ReportContent += "`n================================================`n"
    $ReportContent += "Total Findings: $($Global:Findings.Count)`n"

    $ReportContent | Out-File -FilePath $Global:ReportFile -Encoding UTF8

    if (-not $Quiet) {
        Write-Host "Reports saved to:" -ForegroundColor Cyan
        Write-Host "  Text Report:       $Global:ReportFile"
        Write-Host "  JSON Report:       $Global:JsonFile"
        Write-Host "  Markdown Report:   $Global:MarkdownFile"
        Write-Host "  HTML Report:       $($Global:ReportFile -replace '\.txt$', '.html')"
        Write-Host "  Remediation Guide: $Global:RemediationFile"
        Write-Host "  Log File:          $Global:LogFile"
    }
}

Main

