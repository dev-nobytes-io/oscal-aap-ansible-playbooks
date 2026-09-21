<#
    Emits RAW filesystem evidence for ism-1870 -- "Application control is
    applied to user profiles and temporary folders used by operating systems,
    web browsers and email clients."

    Why this exists at all. Microsoft's own path-rule documentation states the
    problem in the control's exact terms:

        "Because path rules specify locations within the file system, you
         should ensure that there are no subdirectories that are writable by
         nonadministrators. For example, if you create a path rule using the
         allow action for C:\, any file under that location can run, including
         file within users' profiles."

    So answering ism-1870 needs two things that must BOTH be observed, never
    assumed: which paths the policy allows (collected separately, by
    Get-ApplicationControlState.ps1) and which of the control's locations are
    actually writable by a non-administrator on THIS host. An estate that has
    hardened C:\Windows\Temp is in a different position from one that has not,
    and a hardcoded list of "known writable directories" would report both the
    same way.

    Nothing here judges anything. It reports what exists, what the DACL says,
    and -- importantly -- what could not be read.

    Two honest limits, recorded in the output rather than hidden:

      * The DACL is read, not an access check. Deny aces are reported
        separately and subtracted, but ace ordering, inheritance and group
        nesting are not simulated. This over-reports rather than under-reports,
        which is the right direction for a finding a human then confirms.

      * The %WINDIR% walk is depth-bounded and count-capped. When it truncates
        it says so, and the evaluator must not read "no writable directory
        found" from a truncated walk as "there is none".
#>
param(
    [int]$MaxWindowsDepth = 3,
    [int]$MaxDirectories = 4000,
    [int]$MaxProfiles = 10
)

$ErrorActionPreference = 'Stop'

# Administrative principals. This is an ALLOW-list and the inversion is
# deliberate: anything not named here counts as non-administrative, so an
# unrecognised SID is treated as a standard user rather than waved through.
# Failing closed matters more here than precision -- a false flag gets checked
# by a human, a missed one does not.
$AdminSids = @(
    'S-1-5-18',      # LOCAL SYSTEM
    'S-1-5-19',      # LOCAL SERVICE
    'S-1-5-20',      # NETWORK SERVICE
    'S-1-5-32-544',  # BUILTIN\Administrators
    'S-1-5-32-549',  # BUILTIN\Server Operators
    'S-1-5-32-550',  # BUILTIN\Print Operators
    'S-1-5-32-551',  # BUILTIN\Backup Operators
    'S-1-16-12288',  # High mandatory level
    'S-1-16-16384'   # System mandatory level
)
# Administrative RIDs on a domain or machine SID: Administrator, Domain Admins,
# Schema Admins, Enterprise Admins, Group Policy Creator Owners.
$AdminRids = @('500', '512', '518', '519', '520')

# FileSystemRights bits that let a principal place a file: WriteData/CreateFiles
# (2) and AppendData/CreateDirectories (4). Modify and FullControl include both.
$WriteMask = 6

function Test-AdminSid {
    param([string]$Sid)
    if ($AdminSids -contains $Sid) { return $true }
    if ($Sid -match '^S-1-5-21-[\d-]+-(\d+)$') {
        if ($AdminRids -contains $Matches[1]) { return $true }
    }
    return $false
}

function Get-PathWritability {
    param([string]$Path, [string]$Role)

    $record = [ordered]@{
        path              = $Path
        role              = $Role
        exists            = $false
        access            = 'unknown'
        allow_write_sids  = @()
        deny_write_sids   = @()
        non_admin_writable = $null
        error             = ''
    }

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            $record.exists = $false
            $record.access = 'missing'
            return [pscustomobject]$record
        }
        $record.exists = $true

        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        # SIDs, not NTAccounts: translating to names needs a directory lookup
        # that is slow at scale and fails outright on an air-gapped host, and
        # the SID is what the evidence should carry anyway.
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        $allow = New-Object System.Collections.Generic.List[string]
        $deny = New-Object System.Collections.Generic.List[string]
        foreach ($rule in $rules) {
            if ((([int]$rule.FileSystemRights.value__) -band $WriteMask) -eq 0) { continue }
            $sid = [string]$rule.IdentityReference.Value
            if (Test-AdminSid -Sid $sid) { continue }
            if ($rule.AccessControlType -eq 'Allow') {
                if (-not $allow.Contains($sid)) { $allow.Add($sid) }
            } else {
                if (-not $deny.Contains($sid)) { $deny.Add($sid) }
            }
        }

        # .ToArray(), not @(...): an array subexpression around a generic
        # List fails inside an [ordered] literal with "Argument types do not
        # match", and the same form is used below where it would.
        $record.allow_write_sids = $allow.ToArray()
        $record.deny_write_sids = $deny.ToArray()
        $effective = @($allow | Where-Object { $deny -notcontains $_ })
        $record.non_admin_writable = ($effective.Count -gt 0)
        $record.access = 'ok'
    } catch {
        # Unreadable is NOT "not writable". The evaluator is told `unknown` so
        # it can decline to conclude rather than score a directory it could
        # not inspect.
        $record.access = 'denied'
        $record.non_admin_writable = $null
        $record.error = $_.Exception.Message
    }

    return [pscustomobject]$record
}

function Get-SubdirectoryWalk {
    param([string]$Root, [int]$Depth, [ref]$Budget)
    # Breadth-first and hand-rolled on purpose. `Get-ChildItem -Depth` arrived
    # in PowerShell 5.0 and the legacy estate tier runs Server 2012 on
    # PowerShell 3.0, where it would throw -- on exactly the hosts most likely
    # to be carrying default AppLocker rules.
    $found = New-Object System.Collections.Generic.List[string]
    $frontier = @($Root)
    for ($level = 0; $level -lt $Depth; $level++) {
        $next = New-Object System.Collections.Generic.List[string]
        foreach ($dir in $frontier) {
            if ($Budget.Value -le 0) { return $found }
            try {
                $children = Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction Stop
            } catch {
                continue
            }
            foreach ($child in $children) {
                if ($Budget.Value -le 0) { return $found }
                # Reparse points lead outside the tree and back into it.
                if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                $Budget.Value = $Budget.Value - 1
                $found.Add($child.FullName)
                $next.Add($child.FullName)
            }
        }
        $frontier = @($next)
        if ($frontier.Count -eq 0) { break }
    }
    return $found
}

# A service account can be handed a stripped environment block, so this is a
# condition to report rather than to crash on. Everything below is written to
# produce well-formed output with an explicit error -- an evaluator can decline
# to conclude from that, but it cannot do anything with a stack trace.
$windir = $env:SystemRoot
$environmentError = ''
if ([string]::IsNullOrWhiteSpace($windir)) {
    $environmentError = 'SystemRoot is not set in this process environment'
    $windir = ''
}

$probes = New-Object System.Collections.Generic.List[object]

# --- temporary folders used by the operating system ------------------------
$osTemp = ''
if (-not [string]::IsNullOrWhiteSpace($windir)) {
    $osTemp = Join-Path $windir 'Temp'
    $probes.Add((Get-PathWritability -Path $osTemp -Role 'os-temp'))
}
foreach ($name in @('TEMP', 'TMP')) {
    $value = [System.Environment]::GetEnvironmentVariable($name, 'Machine')
    if ([string]::IsNullOrWhiteSpace($value)) { continue }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($value)
    if ($osTemp -and $expanded -ieq $osTemp) { continue }
    $probes.Add((Get-PathWritability -Path $expanded -Role 'os-temp'))
}

# --- user profiles ---------------------------------------------------------
$profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$profilesRoot = ''
$profilePaths = @()
$profilesTotal = 0
$profileError = ''
try {
    $profilesRoot = [System.Environment]::ExpandEnvironmentVariables(
        (Get-ItemProperty -LiteralPath $profileList -ErrorAction Stop).ProfilesDirectory)
    foreach ($key in Get-ChildItem -LiteralPath $profileList -ErrorAction Stop) {
        # S-1-5-21-* is a real account on this machine or its domain. The
        # service profiles (S-1-5-18/19/20) are not user profiles and are not
        # what the control is about.
        if ($key.PSChildName -notmatch '^S-1-5-21-') { continue }
        $image = (Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop).ProfileImagePath
        if ([string]::IsNullOrWhiteSpace($image)) { continue }
        $profilesTotal++
        if ($profilePaths.Count -lt $MaxProfiles) {
            $profilePaths += [System.Environment]::ExpandEnvironmentVariables($image)
        }
    }
} catch {
    $profileError = $_.Exception.Message
}

if (-not [string]::IsNullOrWhiteSpace($profilesRoot)) {
    $probes.Add((Get-PathWritability -Path $profilesRoot -Role 'profile-root'))
}

# Temporary folders used by web browsers and email clients live inside the
# profile, which is why the control names profiles and those folders together.
# Only paths that EXIST are meaningful, and a browser that is not installed is
# reported as missing rather than silently dropped.
$ProfileSubPaths = @(
    @{ rel = ''; role = 'user-profile' },
    @{ rel = 'AppData\Local\Temp'; role = 'user-temp' },
    @{ rel = 'Downloads'; role = 'user-downloads' },
    @{ rel = 'AppData\Local\Microsoft\Edge\User Data'; role = 'browser-temp' },
    @{ rel = 'AppData\Local\Google\Chrome\User Data'; role = 'browser-temp' },
    @{ rel = 'AppData\Local\Mozilla\Firefox'; role = 'browser-temp' },
    @{ rel = 'AppData\Roaming\Mozilla\Firefox\Profiles'; role = 'browser-temp' },
    @{ rel = 'AppData\Local\Microsoft\Windows\INetCache\Content.Outlook'; role = 'email-temp' },
    @{ rel = 'AppData\Local\Thunderbird\Profiles'; role = 'email-temp' }
)

foreach ($profilePath in $profilePaths) {
    foreach ($sub in $ProfileSubPaths) {
        $target = if ([string]::IsNullOrEmpty($sub.rel)) { $profilePath } else { Join-Path $profilePath $sub.rel }
        $probes.Add((Get-PathWritability -Path $target -Role $sub.role))
    }
}

# --- writable subdirectories of %WINDIR% -----------------------------------
# The generalisation of the C:\Windows\Temp case: an allow rule over
# %WINDIR%\* covers every one of these.
$budget = $MaxDirectories
$walkError = $environmentError
$windowsWritable = New-Object System.Collections.Generic.List[object]
if (-not [string]::IsNullOrWhiteSpace($windir)) {
    try {
        $subdirs = Get-SubdirectoryWalk -Root $windir -Depth $MaxWindowsDepth -Budget ([ref]$budget)
        foreach ($dir in $subdirs) {
            $record = Get-PathWritability -Path $dir -Role 'windows-subdirectory'
            if ($record.non_admin_writable -eq $true) { $windowsWritable.Add($record) }
        }
    } catch {
        $walkError = $_.Exception.Message
    }
}

$result = [ordered]@{
    windows_root       = $windir
    profiles_root      = $profilesRoot
    profiles_total     = $profilesTotal
    profiles_probed    = $profilePaths.Count
    profile_error      = $profileError
    environment_error  = $environmentError
    # See the note in Get-PathWritability: @($list) does not survive an
    # [ordered] literal. Found by running this script, not by parsing it.
    probes             = $probes.ToArray()
    windows_writable   = $windowsWritable.ToArray()
    windows_walk = [ordered]@{
        depth     = $MaxWindowsDepth
        budget    = $MaxDirectories
        remaining = $budget
        # `truncated` is load-bearing. A walk that ran out of budget cannot
        # support "no writable directory exists"; the evaluator degrades a
        # would-be pass to unassessed on it, while a directory it DID find
        # stays a finding either way. A walk that could not start at all is
        # truncated in the same sense, and says so here.
        truncated = (($budget -le 0) -or [string]::IsNullOrWhiteSpace($windir))
        error     = $walkError
    }
}

,@($result) | ConvertTo-Json -Depth 6 -Compress
