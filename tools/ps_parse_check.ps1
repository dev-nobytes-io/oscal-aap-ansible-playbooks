<#
    Parse every collector script with PowerShell's own parser.

    This repository's Windows collectors have never run against a Windows
    host, so until now their PowerShell was reviewed and never executed by
    anything. Parsing is a long way short of running, and it is not offered as
    a substitute -- but "this file is syntactically a PowerShell script" is a
    claim that was previously made by nobody, and a missing brace would
    otherwise be discovered by a customer.

    It fails when it finds NO scripts, for the reason every guard in this
    repository does: a check that passes because it could not see its target
    is worse than no check.
#>
param([string]$Path = 'collections/ansible_collections/nobytes')

$ErrorActionPreference = 'Stop'

$scripts = @(Get-ChildItem -Path $Path -Recurse -Filter *.ps1 -File -ErrorAction Stop)
if ($scripts.Count -eq 0) {
    Write-Host "FAIL no PowerShell scripts found under $Path -- nothing was checked"
    exit 1
}

$failed = 0
foreach ($script in $scripts) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $script.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    $relative = Resolve-Path -Relative $script.FullName
    if ($errors.Count -gt 0) {
        $failed++
        foreach ($problem in $errors) {
            Write-Host "FAIL $relative`:$($problem.Extent.StartLineNumber) $($problem.Message)"
        }
    } else {
        Write-Host "ok   $relative ($($tokens.Count) tokens)"
    }
}

if ($failed -gt 0) {
    Write-Host "`n$failed of $($scripts.Count) script(s) failed to parse"
    exit 1
}
Write-Host "`n$($scripts.Count) PowerShell script(s) parse"
