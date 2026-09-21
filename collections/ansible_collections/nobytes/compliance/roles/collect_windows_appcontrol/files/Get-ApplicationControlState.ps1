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

    Rule PATHS are emitted as well as rule counts, because ism-1870 asks
    whether application control reaches user profiles and temporary folders --
    a question a count cannot answer. A host can enforce all five collections
    and still permit execution from every user profile, which is precisely
    what AppLocker's default rules do.

    Rules are walked by element LocalName rather than by XPath. The AppLocker
    schema is namespace-free today, but an XPath that stops matching returns
    an EMPTY node set rather than an error -- and an allow rule that appears
    to carry no paths would read as harmless. A parser that cannot see its
    target must fail loudly, so extraction is namespace-agnostic and the
    evaluator is told how many path conditions it got.
#>
$ErrorActionPreference = 'Stop'

$result = [ordered]@{
    applocker = [ordered]@{
        available   = $false
        collections = @()
        rule_count  = 0
        error       = ''
    }
    wdac      = [ordered]@{ available = $false; configured = @(); running = @(); error = '' }
}

function Get-ConditionPaths {
    param($Parent, [string]$GroupName)
    # Returns @{ paths = @(); other = <count> } for a Conditions or Exceptions
    # group. `other` counts publisher and hash conditions: they narrow a rule
    # but never by directory, so they can never carve a writable folder out of
    # a broad allow. Counting them lets the evaluator say so instead of
    # pretending it saw nothing.
    $paths = @()
    $other = 0
    if ($null -eq $Parent) { return @{ paths = @(); other = 0 } }
    foreach ($group in $Parent.ChildNodes) {
        if ($group.NodeType -ne 'Element' -or $group.LocalName -ne $GroupName) { continue }
        foreach ($cond in $group.ChildNodes) {
            if ($cond.NodeType -ne 'Element') { continue }
            if ($cond.LocalName -eq 'FilePathCondition') {
                $paths += [string]$cond.Path
            } else {
                $other++
            }
        }
    }
    return @{ paths = @($paths); other = $other }
}

function ConvertFrom-AppLockerPolicyXml {
    <#
        The whole of the parsing, in one function taking a string.

        Pulled out of the collection path deliberately. `Get-AppLockerPolicy`
        exists only on Windows, so as long as this logic sat inside the same
        try block it could not be executed anywhere a test runs -- and the part
        most likely to be wrong was the part nothing could exercise.
        `tests/test_powershell_applocker_parsing.py` now runs it against a real
        policy document on Linux.
    #>
    param([Parameter(Mandatory = $true)][string]$Xml)

    $doc = [xml]$Xml
    $collections = @()
    foreach ($node in $doc.DocumentElement.ChildNodes) {
        if ($node.NodeType -ne 'Element' -or $node.LocalName -ne 'RuleCollection') { continue }

        $rules = 0
        $pathRules = @()
        $byType = [ordered]@{ FilePathRule = 0; FilePublisherRule = 0; FileHashRule = 0; other = 0 }

        foreach ($child in $node.ChildNodes) {
            if ($child.NodeType -ne 'Element') { continue }
            # `RuleCollectionExtensions` is a sibling of the rules, not a rule.
            # Counting it would let a collection holding NO rules report
            # rule_count 1, and an empty enforcing collection restricts
            # nothing while reading as implemented.
            if ($child.LocalName -notmatch 'Rule$') { continue }
            $rules++
            if ($byType.Contains($child.LocalName)) {
                $byType[$child.LocalName]++
            } else {
                $byType['other']++
            }
            if ($child.LocalName -ne 'FilePathRule') { continue }

            $conditions = Get-ConditionPaths -Parent $child -GroupName 'Conditions'
            $exceptions = Get-ConditionPaths -Parent $child -GroupName 'Exceptions'
            $pathRules += [pscustomobject]@{
                name                  = [string]$child.Name
                action                = [string]$child.Action
                sid                   = [string]$child.UserOrGroupSid
                paths                 = @($conditions.paths)
                exceptions            = @($exceptions.paths)
                non_path_conditions   = $conditions.other
                non_path_exceptions   = $exceptions.other
            }
        }

        $collections += [pscustomobject]@{
            type             = [string]$node.Type
            enforcement_mode = [string]$node.EnforcementMode
            rule_count       = $rules
            rule_types       = $byType
            path_rules       = @($pathRules)
        }
    }
    return ,@($collections)
}

try {
    $result.applocker.available = $false
    $xml = Get-AppLockerPolicy -Effective -Xml
    $result.applocker.available = $true
    $collections = ConvertFrom-AppLockerPolicyXml -Xml $xml
    foreach ($collection in $collections) { $result.applocker.rule_count += $collection.rule_count }
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

,@($result) | ConvertTo-Json -Depth 8 -Compress
