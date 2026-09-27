# ADR 0017: Parse what `win_powershell` returns, and make the guards fail closed

## Context

Every Windows collector in this repository ends its script with
`| ConvertTo-Json -Compress`, so its only pipeline output is a single
`[string]`. `ansible.windows.win_powershell` then runs `Convert-OutputObject`
over that output, and that function returns a string **unchanged**:

```powershell
elseif ($InputObject -is [string]) {
    # Get the BaseObject to strip out any ETS properties
    $InputObject.PSObject.BaseObject
}
```
— `ansible/windows/plugins/modules/win_powershell.ps1:528-531`

So `register.output[0]` is the collector's JSON **text**, not a mapping. Every
role read it as a mapping:

```yaml
_cca_browsers: "{{ (collect_windows_browsers_policy.output | default([{}]))[0] | default({}) }}"
```

and then indexed `.rows`, `.meta`, `.java`, `.applications`, `.probes` into it.
A repo-wide grep for `from_json` returned **zero hits**. On a real Windows host
every one of those lookups resolved to undefined and was swallowed by
`| default({})`.

Eight `win_powershell` call sites across five roles. Therefore all twelve
Windows controls — 80% of the automated baseline.

### Why nothing caught it

`partial` — the flag the evaluators use to tell "could not read" from "read, and
found nothing" — was derived from `output | length`. That is **1**, because
there is exactly one element: the unparsed string. So every collector reported
a *successful* collection of nothing.

And all 261 tests passed, because every fixture bundle under
`tests/fixtures/bundles/` is a hand-written mapping that never travelled through
`win_powershell`. `make assess-self` runs against Linux, so the Windows path is
never executed. Two artefacts agreeing with each other while both being wrong is
the same defect that produced the `display_name`/`name` bug in PR 17.

**Tenth instance of the shape this repository keeps finding in itself**: a guard
structurally unable to see the thing it guards.

### What it produced downstream

Three different wrong outcomes, in increasing order of severity.

**A wrong class.** `windows.office.install` became a one-element list holding the
string `"[]"`. `office.py` tests `if not install.value:` — a non-empty list is
truthy — so Office was treated as installed on **every** Windows host. Hosts
with no Office reported `unassessed / partial-population` instead of
`not_applicable`, quietly removing them from the population rather than from the
denominator. Separately, the role's `when:` guard on the macro-policy scan tested
`output | length > 0`, which is 1 on every host, so the scan always ran.

**A false red.** `appcontrol.py:_guard` degraded only on `fact is None` or
`fact.partial`. With `partial` false and the value `{}`, `applocker_available`
and `wdac_enforcing` both resolved to `False` and control fell through to:

> `not_satisfied` — *"No enforcing application control was found: AppLocker has
> no enforced rule collection and WDAC is not enforcing a code integrity
> policy."*

A confident failure verdict for `ism-0843` and `ism-1657`, in the OSCAL document
an IRAP assessor reads, about a host from which nothing had been read.

**A false green, at `direct` confidence.** `os_state.py:ie11_disabled_or_removed`
reads an empty optional-feature list as proof of absence:

```python
if not ie_features:
    return CheckResult.satisfied(
        detail="No Internet Explorer 11 optional feature is present on this system.",
        confidence=Confidence.DIRECT,
    )
```

`Get-WindowsOptionalFeature -Online` requires elevation and is absent on Server
SKUs without the DISM cmdlets; the collector caught both and emitted `@()`. So a
host that could not be asked was reported as a host without Internet Explorer —
`satisfied`, at the **highest confidence this project assigns anywhere**, and
`ism-1654` is the registry's only `direct` check.

In a compliance tool a false green is worse than a false red: a red gets
investigated, a green closes the item.

## Decision

**1. One place parses the wire form.**
`nobytes.compliance.ps_object` takes a `win_powershell` `output` list and returns
`{ok, error, value}`. It accepts the `,@($result)` one-element-array form three
collectors still use, accepts an already-parsed mapping so a future collector
change is not punished, and **refuses** an empty list, an empty string, invalid
JSON, a multi-element array (never silently drop a tail), and being handed the
register instead of `.output`.

It returns a *status*, not just a value, because a collector that could not be
read and a host with nothing to find are different outcomes and the caller must
be able to tell them apart.

**2. Every role sets `partial` from that status**, and records the reason in the
fact's `meta.collection_error`.

**3. Every evaluator fails closed independently.** A guard that relies on the
collector setting one flag correctly is the same defect waiting to recur, so:

- `appcontrol.py:_guard` refuses a fact carrying neither an `applocker` nor a
  `wdac` observation, **before** any verdict logic.
- `office.py` checks `install.partial` **before** `not install.value`, so a
  failed inventory is `unassessed` rather than `not_applicable`.
- `os_state.py` refuses an empty optional-feature list outright. Every supported
  Windows build enumerates optional features, so empty is a failed read, never an
  estate fact.

**4. The Windows optional-feature collector records why it failed.** Its `catch`
previously set `$features = @()`, making "not elevated" and "no features"
identical. It now emits `{features, collection_error}`.

## Consequences

Coverage is unchanged at **15 of 46 (32.6%)** and no verdict moves in the golden
documents, because every fixture was already a correct mapping. That is the
point: the defect was invisible to the fixtures and only ever affected real
hosts.

**Every Windows fact bundle collected before this change is void** — not merely
incomplete. Bundles from real hosts recorded `partial: false` over empty values,
so anything derived from them understates or misstates the estate. There are no
such bundles in this repository, and any produced in a deployment should be
discarded rather than re-evaluated.

`tests/test_collector_output_contract.py` operates on the **wire form** rather
than on fixtures, and each of its three load-bearing assertions was verified to
fail against the code as it shipped:

| Assertion | Against shipped code |
|---|---|
| no role indexes `output[0]` as a mapping | 15 failures across all five roles |
| an empty appcontrol fact is not a failure verdict | `Status.NOT_SATISFIED` |
| an empty feature list is not proof IE11 is absent | `Status.SATISFIED` |

**Still not proven**: none of this has run against a Windows host. The contract
is now enforced in both directions on the wire form, and the collectors' own
PowerShell parses and executes under `pwsh`, but those are different claims from
"this works on Windows" and `docs/platforms/windows.md` keeps them apart.

## Status

Accepted.
