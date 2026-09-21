<#
    Emits RAW application control state. Contains no notion of a good value --
    every judgement lives in the evaluator, off-host and unit-testable.

    Two sources, because either alone gives a wrong answer:

      AppLocker  Get-AppLockerPolicy -Effective returns the policy actually in
                 force, merging local and domain GPO. Its five rule
                 collections are Exe, Dll, Script, Msi and Appx, and each
                 carries its own EnforcementMode -- NotConfigured, AuditOnly
                 or Enabled. A collection in AuditOnly logs and blocks
                 nothing, which is the single most likely way a host looks
                 protected and is not.

      WDAC       App Control for Business enforces through code integrity
                 policies rather than AppLocker rules. Win32_DeviceGuard
                 reports which are configured and running. A host running WDAC
                 may fully satisfy application control while having no
                 AppLocker policy at all, so reading AppLocker alone would
                 report a false failure.
#>
$ErrorActionPreference = 'Stop'

$result = [ordered]@{
    applocker = [ordered]@{ available = $false; collections = @(); rule_count = 0; error = '' }
    wdac      = [ordered]@{ available = $false; configured = @(); running = @(); error = '' }
}

try {
    $xml = Get-AppLockerPolicy -Effective -Xml
    $result.applocker.available = $true
    $doc = [xml]$xml
    $collections = @()
    foreach ($node in $doc.AppLockerPolicy.RuleCollection) {
        $rules = 0
        foreach ($child in $node.ChildNodes) {
            if ($child.NodeType -eq 'Element') { $rules++ }
        }
        $collections += [pscustomobject]@{
            type             = [string]$node.Type
            enforcement_mode = [string]$node.EnforcementMode
            rule_count       = $rules
        }
        $result.applocker.rule_count += $rules
    }
    $result.applocker.collections = $collections
} catch {
    # Not an error condition: a host with no AppLocker policy is a normal
    # state the evaluator must judge, not a collection failure.
    $result.applocker.error = $_.Exception.Message
}

try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $result.wdac.available = $true
    $result.wdac.configured = @($dg.SecurityServicesConfigured)
    $result.wdac.running = @($dg.SecurityServicesRunning)
    $result.wdac.code_integrity_policy_enforcement_status = `
        [int]$dg.CodeIntegrityPolicyEnforcementStatus
    $result.wdac.usermode_code_integrity_policy_enforcement_status = `
        [int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus
} catch {
    $result.wdac.error = $_.Exception.Message
}

,@($result) | ConvertTo-Json -Depth 6 -Compress
