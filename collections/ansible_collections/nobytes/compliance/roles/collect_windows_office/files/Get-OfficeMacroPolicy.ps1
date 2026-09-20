<#
.SYNOPSIS
    Emit RAW Office macro policy values. No interpretation, no verdicts.

.DESCRIPTION
    Walks machine scope and every loaded user policy hive for each Office
    version and application, and emits the values verbatim.

    This script deliberately contains no logic about what a "good" value is.
    All interpretation lives in the Python evaluator, which means roughly all
    of the decision logic is unit-testable on Linux with no Windows host --
    the strongest practical argument for the collect/evaluate split.

    Profile hives that are not loaded are REPORTED as unloaded rather than
    skipped silently. The evaluator needs to know the picture is incomplete;
    a hive it could not read might be the failing one.
#>
[CmdletBinding()]
param(
    [string[]] $OfficeVersions = @('14.0', '15.0', '16.0'),
    [string[]] $Apps = @('word', 'excel', 'powerpoint', 'access', 'publisher', 'visio', 'project')
)

$ErrorActionPreference = 'Stop'
$rows = New-Object System.Collections.Generic.List[object]

function Read-MacroValues {
    param([string]$Path, [string]$Scope, [string]$Sid, [string]$Version, [string]$App)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $key) { return $null }

    [pscustomobject]@{
        scope                             = $Scope
        sid                               = $Sid
        office_version                    = $Version
        app                               = $App
        key                               = $Path
        blockcontentexecutionfrominternet = $key.GetValue('blockcontentexecutionfrominternet', $null)
        vbawarnings                       = $key.GetValue('vbawarnings', $null)
        macroruntimescanscope             = $key.GetValue('macroruntimescanscope', $null)
        # Values under the Policies hive are GPO-delivered and therefore not
        # writable by a standard user. Recorded as an observation, not a verdict.
        gpo_delivered                     = $Path -like '*\Policies\*'
    }
}

foreach ($version in $OfficeVersions) {
    foreach ($app in $Apps) {
        $machine = "HKLM:\SOFTWARE\Policies\Microsoft\office\$version\$app\security"
        $row = Read-MacroValues -Path $machine -Scope 'machine' -Sid $null -Version $version -App $app
        if ($row) { $rows.Add($row) }
    }
}

$profilesTotal = 0
$profilesLoaded = 0
$unloaded = New-Object System.Collections.Generic.List[string]

$profileList = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue
if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script | Out-Null
}

foreach ($profileKey in $profileList) {
    $sid = Split-Path $profileKey.Name -Leaf
    if ($sid -notmatch '^S-1-5-21-') { continue }   # skip built-in service SIDs
    $profilesTotal++

    if (-not (Test-Path -LiteralPath "HKU:\$sid")) {
        # The hive is not loaded; the user is not signed in. Report it rather
        # than load it -- loading a hive is a mutating action and this role is
        # strictly read-only.
        $unloaded.Add($sid)
        continue
    }
    $profilesLoaded++

    foreach ($version in $OfficeVersions) {
        foreach ($app in $Apps) {
            $userPath = "HKU:\$sid\SOFTWARE\Policies\Microsoft\office\$version\$app\security"
            $row = Read-MacroValues -Path $userPath -Scope 'user' -Sid $sid -Version $version -App $app
            if ($row) { $rows.Add($row) }
        }
    }
}

[pscustomobject]@{
    rows = $rows
    meta = [pscustomobject]@{
        profiles_total    = $profilesTotal
        profiles_loaded   = $profilesLoaded
        profiles_unloaded = $unloaded
    }
} | ConvertTo-Json -Depth 6 -Compress
