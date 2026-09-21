<#
    Emits the RAW installed-application inventory. Contains no notion of
    supported or unsupported -- that judgement needs the end-of-life dataset
    and a collection date, and belongs in the evaluator.

    Reads the Uninstall keys under all three scopes, because a package
    installed per-user appears in none of the machine-wide ones and missing it
    would under-report the estate's exposure:

      HKLM 64-bit, HKLM 32-bit (WOW6432Node), and each loaded HKU hive.

    Profile hives that are NOT loaded are reported rather than loaded. Loading
    a hive is a mutating action on the host, and a collector that mutates to
    read has stopped being read-only. The evaluator treats the gap as a
    partial population instead of pretending the inventory is complete.
#>
$ErrorActionPreference = 'Stop'

$machineKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$apps = @()
$scanned = @()

foreach ($key in $machineKeys) {
    $scanned += $key
    foreach ($item in (Get-ItemProperty $key -ErrorAction SilentlyContinue)) {
        if (-not $item.DisplayName) { continue }
        $apps += [pscustomobject]@{
            name      = [string]$item.DisplayName
            version   = [string]$item.DisplayVersion
            publisher = [string]$item.Publisher
            scope     = 'machine'
        }
    }
}

# Per-user installs, from hives that are already loaded.
$loaded = @()
$unloaded = @()
foreach ($profile in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue)) {
    $sid = Split-Path $profile.Name -Leaf
    if ($sid -notmatch '^S-1-5-21-') { continue }
    if (Test-Path "Registry::HKEY_USERS\$sid") {
        $loaded += $sid
        $userKey = "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $scanned += $userKey
        foreach ($item in (Get-ItemProperty $userKey -ErrorAction SilentlyContinue)) {
            if (-not $item.DisplayName) { continue }
            $apps += [pscustomobject]@{
                name      = [string]$item.DisplayName
                version   = [string]$item.DisplayVersion
                publisher = [string]$item.Publisher
                scope     = 'user'
            }
        }
    } else {
        $unloaded += $sid
    }
}

,@([ordered]@{
    applications = @($apps | Sort-Object name, version -Unique)
    meta         = [ordered]@{
        scanned_keys   = $scanned
        loaded_hives   = $loaded
        unloaded_hives = $unloaded
    }
}) | ConvertTo-Json -Depth 6 -Compress
