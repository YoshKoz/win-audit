<#
.SYNOPSIS
    Guided, safety-tiered remediation companion for Win-Audit.ps1 (v2).
.DESCRIPTION
    Reads the latest Win-Audit-Report.json and applies fixes for findings that
    have a VETTED remediation action registered below. Fixes are gated by the
    RemediationSafety tier recorded in the audit:

        SafeAuto      - low-risk, reversible; applied with -FixSafeOnly
        ConfirmFirst  - needs a deliberate yes; applied with -FixConfirmFirst
        ManualOnly    - never automated here; listed for the operator
        DoNotAutomate - never automated here

    Nothing is changed unless you pass -FixSafeOnly and/or -FixConfirmFirst.
    Always preview first:  -FixSafeOnly -WhatIf
.PARAMETER ListOnly
    Show actionable findings and whether each has a registered fix. No changes.
.PARAMETER FixSafeOnly
    Apply registered SafeAuto fixes.
.PARAMETER FixConfirmFirst
    Apply registered ConfirmFirst fixes (each prompts unless -Confirm:$false).
.PARAMETER ReportJson
    Path to a specific Win-Audit-Report.json. Default: newest in -OutputDir.
.PARAMETER OutputDir
    Folder to search for the report. Default: script directory.
.EXAMPLE
    .\Invoke-WinAuditRemediation.ps1 -ListOnly
.EXAMPLE
    .\Invoke-WinAuditRemediation.ps1 -FixSafeOnly -WhatIf
.EXAMPLE
    .\Invoke-WinAuditRemediation.ps1 -FixSafeOnly
.NOTES
    Pairs with Win-Audit.ps1 v2. FindingIds below match its CheckCatalog.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$ListOnly,
    [switch]$FixSafeOnly,
    [switch]$FixConfirmFirst,
    [string]$ReportJson,
    [string]$OutputDir = $PSScriptRoot,
    [switch]$NoElevate
)

$ApplyMode = $FixSafeOnly -or $FixConfirmFirst

# Elevate only when we intend to actually change something (not for list/preview).
if ($ApplyMode -and -not $WhatIfPreference -and -not $NoElevate -and
    -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    $Engine = if ($PSVersionTable.PSVersion.Major -ge 6) { "pwsh.exe" } else { "powershell.exe" }
    $PassArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -OutputDir `"$OutputDir`" -NoElevate"
    if ($FixSafeOnly)     { $PassArgs += " -FixSafeOnly" }
    if ($FixConfirmFirst) { $PassArgs += " -FixConfirmFirst" }
    if ($ReportJson)      { $PassArgs += " -ReportJson `"$ReportJson`"" }
    Start-Process $Engine $PassArgs -Verb RunAs
    exit
}

# ========== VETTED FIX REGISTRY (keyed by FindingId) ==========
# Action  : scriptblock that performs the fix.
# Validate: scriptblock returning $true when the system is already compliant.
# Only findings present here can be auto-applied; everything else is manual.
$FixRegistry = @{
    "LOG-001" = @{
        Title    = "Security event log size -> 200 MB"
        Safety   = "SafeAuto"
        Validate = { (Get-WinEvent -ListLog Security).MaximumSizeInBytes -ge 196608KB }
        Action   = { wevtutil sl Security /ms:209715200 }
    }
    "LOG-002" = @{
        Title    = "System event log size -> 100 MB"
        Safety   = "SafeAuto"
        Validate = { (Get-WinEvent -ListLog System).MaximumSizeInBytes -ge 32768KB }
        Action   = { wevtutil sl System /ms:104857600 }
    }
    "LOG-003" = @{
        Title    = "Application event log size -> 100 MB"
        Safety   = "SafeAuto"
        Validate = { (Get-WinEvent -ListLog Application).MaximumSizeInBytes -ge 32768KB }
        Action   = { wevtutil sl Application /ms:104857600 }
    }
    "PS-001" = @{
        Title    = "Enable PowerShell transcription policy"
        Safety   = "SafeAuto"
        Validate = { (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting -eq 1 }
        Action   = {
            $key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            $dir = Join-Path $env:ProgramData 'PSTranscripts'
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            New-ItemProperty -Path $key -Name EnableTranscripting -PropertyType DWord -Value 1 -Force | Out-Null
            New-ItemProperty -Path $key -Name OutputDirectory -PropertyType String -Value $dir -Force | Out-Null
            New-ItemProperty -Path $key -Name EnableInvocationHeader -PropertyType DWord -Value 1 -Force | Out-Null
        }
    }
    "AI-002" = @{
        Title    = "Add inbound firewall block for Ollama port 11434"
        Safety   = "SafeAuto"
        Validate = { @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Action -eq 'Block' -and $_.Direction -eq 'Inbound' -and $_.Enabled -and ($_ | Get-NetFirewallPortFilter).LocalPort -contains '11434' }).Count -ge 1 }
        Action   = { New-NetFirewallRule -DisplayName 'WinAudit - Block Ollama 11434 inbound' -Direction Inbound -Action Block -Protocol TCP -LocalPort 11434 | Out-Null }
    }
    "PS-002" = @{
        Title    = "Set LocalMachine execution policy to RemoteSigned"
        Safety   = "ConfirmFirst"
        Validate = { (Get-ExecutionPolicy -Scope LocalMachine) -in @('Restricted', 'RemoteSigned', 'AllSigned') }
        Action   = { Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force }
    }
    "AUTH-001" = @{
        Title    = "Set account lockout threshold to 5"
        Safety   = "ConfirmFirst"
        Validate = { $t = [int]([regex]::Match((net accounts | Out-String), 'Lockout threshold[^\d]*(\d+)').Groups[1].Value); $t -ge 5 -and $t -le 10 }
        Action   = { net accounts /lockoutthreshold:5 | Out-Null }
    }
    "UAC-001" = @{
        Title    = "UAC: always prompt admins for elevation"
        Safety   = "ConfirmFirst"
        Validate = { (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin -eq 2 }
        Action   = { Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2 }
    }
    "AI-001" = @{
        Title    = "Bind Ollama to loopback (OLLAMA_HOST=127.0.0.1:11434)"
        Safety   = "ConfirmFirst"
        Validate = { [System.Environment]::GetEnvironmentVariable('OLLAMA_HOST', 'Machine') -match '^127\.0\.0\.1' }
        Action   = {
            [System.Environment]::SetEnvironmentVariable('OLLAMA_HOST', '127.0.0.1:11434', 'Machine')
            Write-Host "    Note: restart the Ollama service/app for this to take effect." -ForegroundColor DarkYellow
        }
    }
    "SVC-001" = @{
        Title    = "Stop and disable Print Spooler"
        Safety   = "ConfirmFirst"
        Validate = { (Get-Service Spooler -ErrorAction SilentlyContinue).Status -ne 'Running' }
        Action   = { Stop-Service Spooler -Force -ErrorAction SilentlyContinue; Set-Service Spooler -StartupType Disabled }
    }
}

# ========== LOAD REPORT ==========
if (-not $ReportJson) {
    $candidate = Get-ChildItem -Path $OutputDir -Filter 'Win-Audit-Report.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $candidate) {
        Write-Host "No Win-Audit-Report.json found in $OutputDir. Run Win-Audit.ps1 first." -ForegroundColor Red
        exit 1
    }
    $ReportJson = $candidate.FullName
}
if (-not (Test-Path $ReportJson)) {
    Write-Host "Report not found: $ReportJson" -ForegroundColor Red
    exit 1
}

$Report = Get-Content $ReportJson -Raw | ConvertFrom-Json
Write-Host "`nRemediation source: $ReportJson" -ForegroundColor Cyan
Write-Host "Audited: $($Report.Generated) on $($Report.ComputerName) | Hardening Index: $($Report.HardeningIndex)/100`n" -ForegroundColor Cyan

$Actionable = @($Report.Findings | Where-Object { $_.Status -ne 'OK' })
if ($Actionable.Count -eq 0) {
    Write-Host "No open findings. Nothing to remediate." -ForegroundColor Green
    exit 0
}

# ========== LIST MODE (default when no fix flag) ==========
if ($ListOnly -or -not $ApplyMode) {
    Write-Host "Actionable findings ($($Actionable.Count)):" -ForegroundColor White
    foreach ($F in ($Actionable | Sort-Object RemediationSafety, FindingId)) {
        $reg = $FixRegistry[$F.FindingId]
        $tag = if ($reg) { "[auto-fix available]" } else { "[manual]" }
        $color = switch ($F.RemediationSafety) {
            "SafeAuto"     { "Green" }
            "ConfirmFirst" { "Yellow" }
            default        { "Gray" }
        }
        Write-Host ("  {0,-9} {1,-13} {2} {3}" -f $F.FindingId, $F.RemediationSafety, $F.Item, $tag) -ForegroundColor $color
    }
    Write-Host "`nApply:  -FixSafeOnly [-WhatIf]   |   -FixConfirmFirst [-WhatIf]" -ForegroundColor DarkGray
    if (-not $ListOnly) { Write-Host "(no fix flag given - showing list only)" -ForegroundColor DarkGray }
    exit 0
}

# ========== APPLY MODE ==========
$Applied = 0; $Skipped = 0; $Failed = 0; $AlreadyOk = 0

foreach ($F in ($Actionable | Sort-Object RemediationSafety, FindingId)) {
    $reg = $FixRegistry[$F.FindingId]
    if (-not $reg) { continue }

    $tierWanted = ($reg.Safety -eq 'SafeAuto' -and $FixSafeOnly) -or
                  ($reg.Safety -eq 'ConfirmFirst' -and $FixConfirmFirst)
    if (-not $tierWanted) { continue }

    # Skip if the system already satisfies the check.
    try { if (& $reg.Validate) { Write-Host "[already ok] $($F.FindingId) $($reg.Title)" -ForegroundColor DarkGreen; $AlreadyOk++; continue } } catch { }

    $target = "$($F.FindingId) - $($reg.Title)"
    if ($PSCmdlet.ShouldProcess($target, "Apply fix")) {
        try {
            & $reg.Action
            $ok = $true
            try { $ok = [bool](& $reg.Validate) } catch { $ok = $true }  # validate is best-effort
            if ($ok) { Write-Host "[applied]    $target" -ForegroundColor Green; $Applied++ }
            else     { Write-Host "[applied?]   $target (post-validate did not confirm)" -ForegroundColor Yellow; $Applied++ }
        }
        catch {
            Write-Host "[failed]     $target -> $($_.Exception.Message)" -ForegroundColor Red
            $Failed++
        }
    }
    else { $Skipped++ }
}

Write-Host "`nSummary: applied $Applied | already-ok $AlreadyOk | skipped $Skipped | failed $Failed" -ForegroundColor Cyan
Write-Host "Re-run Win-Audit.ps1 to confirm the new hardening index." -ForegroundColor DarkGray
