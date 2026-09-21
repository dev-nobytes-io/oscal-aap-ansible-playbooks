<#
.SYNOPSIS
    Emit RAW web browser policy values. No interpretation, no verdicts.

.DESCRIPTION
    Walks machine scope and every loaded user policy hive for each supported
    browser and emits the values verbatim. All interpretation lives in the
    Python evaluator.

    THE DISTINCTION THIS SCRIPT EXISTS TO MAKE. Chromium browsers publish every
    policy at TWO registry paths:

        SOFTWARE\Policies\Microsoft\Edge              mandatory -- user cannot change it
        SOFTWARE\Policies\Microsoft\Edge\Recommended  a default the user MAY override

    The Office collector classifies a value as GPO-delivered with
    `$Path -like '*\Policies\*'`. Copying that here would match the
    \Recommended subkey and report every user-overridable setting as locked --
    the exact inverse of what ism-1585 asks. `Get-PolicyLevel` makes the
    three-way distinction instead, and it is a pure string function so it can
    be executed and tested off-Windows.

    Profile hives that are not loaded are REPORTED rather than loaded. Loading
    a hive is a mutating action and this role is strictly read-only.
#>
[CmdletBinding()]
param(
    [string[]] $Browsers = @('edge', 'chrome', 'firefox')
)

$ErrorActionPreference = 'Stop'

#: Policy roots, relative to a hive. Chromium browsers take the same shape;
#: Firefox has no \Recommended equivalent -- its only locking mechanism is the
#: Status field inside the Preferences JSON blob, which the evaluator parses.
$BrowserRoots = @{
    edge    = 'SOFTWARE\Policies\Microsoft\Edge'
    chrome  = 'SOFTWARE\Policies\Google\Chrome'
    firefox = 'SOFTWARE\Policies\Mozilla\Firefox'
}

#: Value names read per browser family. Deliberately a fixed list rather than
#: "everything in the key": a policy surface of several hundred values would
#: bloat every bundle, and the evidence store is a crown-jewel dataset.
$ChromiumValues = @(
    'AdsSettingForIntrusiveAdsSites',
    'SafeBrowsingEnabled',
    'SmartScreenEnabled',
    'DeveloperToolsAvailability',
    'PasswordManagerEnabled',
    'DownloadRestrictions',
    'InternetExplorerIntegrationLevel',
    'InternetExplorerIntegrationSiteList'
)
$FirefoxValues = @(
    'BlockAboutConfig',
    'DisableSafeMode',
    'DisableDeveloperTools',
    'Preferences',
    'ExtensionSettings'
)

function Get-PolicyLevel {
    <#
        mandatory   -- under the vendor Policies key; the user cannot change it
        recommended -- under \Recommended; a default the user MAY override
        preference  -- anywhere else; the browser's own settings store

        Pure string logic, no registry access, so tests/test_powershell_collectors.py
        can execute it on Linux. Trap 2 in the plan, and the single highest-risk
        copy-paste in this chunk.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalised = $Path.TrimEnd('\').ToUpperInvariant()
    if ($normalised -match '\\POLICIES\\.*\\RECOMMENDED$') { return 'recommended' }
    if ($normalised -match '\\POLICIES\\') { return 'mandatory' }
    return 'preference'
}

function Get-ForcedExtensions {
    <#
        ExtensionInstallForcelist is a SUBKEY holding numbered values, not a
        value. Reading it as a value returns nothing and would make a correctly
        hardened host look unhardened.
    #>
    param([string]$KeyPath)

    $listPath = Join-Path $KeyPath 'ExtensionInstallForcelist'
    if (-not (Test-Path -LiteralPath $listPath)) { return @() }
    $key = Get-Item -LiteralPath $listPath -ErrorAction SilentlyContinue
    if ($null -eq $key) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($name in $key.GetValueNames()) {
        $value = [string]$key.GetValue($name, '')
        if (-not [string]::IsNullOrWhiteSpace($value)) { $out.Add($value) }
    }
    return @($out)
}

function Read-BrowserKey {
    param([string]$Path, [string]$Browser, [string]$Scope, [string]$Sid)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $key) { return $null }

    $wanted = if ($Browser -eq 'firefox') { $FirefoxValues } else { $ChromiumValues }
    $values = [ordered]@{}
    foreach ($name in $wanted) {
        $raw = $key.GetValue($name, $null)
        if ($null -eq $raw) { continue }
        # REG_MULTI_SZ arrives as a string array. Joined with newlines so the
        # evaluator receives one document to json.loads -- Firefox's Preferences
        # policy is a single JSON blob split across lines.
        if ($raw -is [array]) { $raw = ($raw -join "`n") }
        $values[$name] = $raw
    }

    $level = Get-PolicyLevel -Path $Path
    [pscustomobject]@{
        browser       = $Browser
        scope         = $Scope
        sid           = $Sid
        key           = $Path
        policy_level  = $level
        # Emitted alongside policy_level so the Office evaluator's existing
        # logic transfers unchanged. It is NOT computed from the path glob.
        gpo_delivered = ($level -eq 'mandatory')
        values        = $values
        forced_extensions = @(Get-ForcedExtensions -KeyPath $Path)
    }
}

$rows = New-Object System.Collections.Generic.List[object]

function Add-BrowserRows {
    param([string]$HivePrefix, [string]$Scope, [string]$Sid)

    foreach ($browser in $Browsers) {
        $root = $BrowserRoots[$browser]
        if (-not $root) { continue }
        foreach ($suffix in @('', '\Recommended')) {
            # Firefox has no \Recommended concept; probing it would emit a row
            # that means nothing.
            if ($browser -eq 'firefox' -and $suffix) { continue }
            $path = "${HivePrefix}\${root}${suffix}"
            $row = Read-BrowserKey -Path $path -Browser $browser -Scope $Scope -Sid $Sid
            if ($row) { $rows.Add($row) }
        }
    }
}

$profilesTotal = 0
$profilesLoaded = 0
$unloaded = New-Object System.Collections.Generic.List[string]
$collectionError = ''

# Wrapped so the script emits well-formed JSON with an explicit error on a host
# where the registry is unreachable, rather than throwing and producing no
# bundle at all. It also lets the parsing functions above be dot-sourced and
# executed off-Windows, which is how Get-PolicyLevel gets a real test.
try {
    Add-BrowserRows -HivePrefix 'HKLM:' -Scope 'machine' -Sid $null

    $profileList = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script | Out-Null
    }

    foreach ($profileKey in $profileList) {
        $sid = Split-Path $profileKey.Name -Leaf
        if ($sid -notmatch '^S-1-5-21-') { continue }
        $profilesTotal++
        if (-not (Test-Path -LiteralPath "HKU:\$sid")) {
            $unloaded.Add($sid)
            continue
        }
        $profilesLoaded++
        Add-BrowserRows -HivePrefix "HKU:\$sid" -Scope 'user' -Sid $sid
    }
} catch {
    $collectionError = $_.Exception.Message
}

# --- the Java surface, for ism-1486 -----------------------------------------
# Edge IE mode runs Trident and supports ActiveX controls, and the Java plug-in
# in Internet Explorer was ALWAYS an ActiveX control rather than NPAPI. So the
# one live path by which a modern browser processes Java is Edge + IE mode + a
# Java runtime. win-ie11-disabled deliberately records edge_ie_mode without
# judging it, because that control is about IE11 as a browser rather than the
# MSHTML engine. This is where it gets judged.
#
# Whatever is under JavaSoft is emitted VERBATIM. Matching on a plug-in CLSID
# was considered and rejected: the constant could not be verified against a
# current Oracle document, and a collector that matches an unverified constant
# reports "absent" for something it simply failed to look for correctly.
$java = [ordered]@{
    ie_integration_level = $null
    ie_site_list         = $null
    javasoft             = [ordered]@{}
    error                = ''
}
try {
    $edgePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    if (Test-Path -LiteralPath $edgePolicy) {
        $key = Get-Item -LiteralPath $edgePolicy
        $java.ie_integration_level = $key.GetValue('InternetExplorerIntegrationLevel', $null)
        $java.ie_site_list = $key.GetValue('InternetExplorerIntegrationSiteList', $null)
    }
    foreach ($path in @('HKLM:\SOFTWARE\JavaSoft', 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft')) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($child in Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue) {
            $name = Split-Path $child.Name -Leaf
            $java.javasoft["$path\$name"] = @(
                foreach ($sub in Get-ChildItem -LiteralPath $child.PSPath -ErrorAction SilentlyContinue) {
                    Split-Path $sub.Name -Leaf
                }
            )
        }
    }
} catch {
    $java.error = $_.Exception.Message
}

[pscustomobject]@{
    rows = $rows
    java = $java
    meta = [pscustomobject]@{
        profiles_total    = $profilesTotal
        profiles_loaded   = $profilesLoaded
        profiles_unloaded = $unloaded
        collection_error  = $collectionError
    }
} | ConvertTo-Json -Depth 8 -Compress
