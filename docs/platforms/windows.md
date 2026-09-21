# Windows

The platform where Essential Eight ML1 actually bites. Of the 46 ML1 controls,
the largest cluster of host-testable ones are Windows/Office policy states.

## What can be evidenced here

| Control | Check | Confidence | What it does *not* prove |
|---|---|---|---|
| `ism-1488` | `win-office-macro-internet-blocked` | `proxy` | Runtime blocking; Mark-of-the-Web stripped upstream; unloaded profile hives |
| `ism-1489` | `win-office-macro-settings-locked` | `proxy` | That a local administrator cannot still change the value |
| `ism-1671` | `win-office-macros-disabled` | `partial` | The "demonstrated business requirement" half — not observable on a host |
| `ism-1672` | `win-office-macro-av-scanning` | `proxy` | That an AMSI provider is registered, healthy and current |
| `ism-1654` | `win-ie11-disabled` | `direct` | Nothing material — the control is a binary, directly observable state |

`ism-1654` is the only one of these at `direct` confidence, and that is not an
accident: it is one of very few ML1 controls that is genuinely a binary state
rather than something inferred from a configuration value.

`ism-1671` is the clearest illustration of why confidence exists. The registry
tells you macros are disabled; it cannot tell you whether a user who has them
enabled is authorised to. That is held in an approval register, not on the host.
So a failure may be a legitimately approved exemption, and a pass says nothing
about whether the exemption process is sound. Confidence is `partial` and the
finding says so.

## Transport and least privilege

- **WinRM** (HTTPS, Kerberos preferred over NTLM).
- Managed nodes need **PowerShell 3.0+ and .NET 4.0+**. Bare Server 2012 images
  may need bootstrapping before they can be *assessed at all*.
- The collect credential should be a **domain account with remote-read rights**,
  not a local administrator. Read-only is enforced by the credential, not by
  our roles being well-behaved — see [`../13-security-model.md`](../13-security-model.md).

## Estate tiers

| Tier | Windows | Execution environment |
|---|---|---|
| `legacy` | Server 2012 / 2012 R2 / 2016, Windows 10 | `ee-legacy` (ansible-core 2.16) |
| `current` | Server 2019 / 2022 / 2025, Windows 11 | `ee-current` (ansible-core 2.19) |

ansible-core **dropped Windows Server 2012/2012 R2 after 2.16**. A current
execution environment cannot manage those hosts at all, which is why two images
exist. Tier comes from CMDB/AD/Intune OS data, not from gathered facts — the
right image has to be chosen before anything can be gathered.

Worth stating plainly: an estate running Server 2012 or Windows 10 **fails
`ism-1501`, `ism-1704` and `ism-1905` by definition**, and all three are ML1
controls. Detecting that is a feature, not an embarrassment.

## Why the PowerShell is so dull

`Get-OfficeMacroPolicy.ps1` emits raw registry values and nothing else. It
contains no notion of what a "good" value is.

That is deliberate. All interpretation lives in the Python evaluator, so roughly
**all of the Windows decision logic is unit-testable on Linux with no Windows
host and no container**. It is the strongest practical argument for the
collect/evaluate split, over and above the audit argument.

One consequence worth knowing: profile hives that are **not loaded** are
reported as unloaded rather than loaded on the fly. Loading a hive is a mutating
action, and collection is strictly read-only. The evaluator then returns
`unassessed / partial-population` rather than `satisfied` — the hive it could
not read might be the failing one.

## Running it

```bash
ansible-playbook playbooks/collect.yml -i inventory/example.yml --limit windows_current
CCA_SYSTEM_ID=SYSTEM-GOVDESK ansible-playbook playbooks/evaluate.yml
```

## Application control: AppLocker cannot satisfy `ism-1657`

Worth stating plainly, because it contradicts a common assumption.

`ism-1657` requires application control to restrict **executables, libraries,
scripts, installers, compiled HTML, HTML applications and control panel
applets** — seven file types. AppLocker has five rule collections, and
[Microsoft documents exactly what each covers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-applocker-rule-collections):

| Collection | Extensions | ISM wording it satisfies |
|---|---|---|
| Executable | `.exe` `.com` | executables |
| DLLs | `.dll` `.ocx` | libraries |
| Scripts | `.ps1` `.bat` `.cmd` `.vbs` `.js` | scripts |
| Windows Installer | `.msi` `.mst` `.msp` | installers |
| Packaged apps | `.appx` | *(not in the control's list)* |

**Compiled HTML (`.chm`), HTML applications (`.hta`) and control panel applets
(`.cpl`) appear in no AppLocker rule collection.** A fully enforced AppLocker
policy is therefore still short of this control, and no amount of configuration
closes the gap. App Control for Business (WDAC) enforces through code integrity
policies instead and covers more.

So `win-application-control-file-types` reports **not-satisfied at `partial`
confidence even when every mappable collection is enforced**, and separates two
kinds of gap in the evidence:

- `not_covered_configurable` — file types AppLocker *could* restrict but is not
  configured to. Fixable by configuration.
- `not_coverable_by_applocker` — `.chm`, `.hta`, `.cpl`. Not fixable by
  configuration at all.

Reporting `satisfied` because five collections are enforced would hide the one
thing this check exists to surface.

Where WDAC is enforcing, its code integrity rules are not readable from the
state this collector gathers, so the result is `unassessed` rather than a guess
in either direction.

### AuditOnly is not implemented

An AppLocker collection in `AuditOnly` writes an event and permits execution.
It is counted as **not** implemented, for the same reason a report-only
conditional access policy is not counted as requiring MFA: it is the most
likely way a workstation looks protected and is not.

## Verification status

| Path | Status |
|---|---|
| Evaluator logic | **Tested** — fixture bundles, no host needed |
| Read-only guarantee (static) | **Tested** — no mutating module surface in collect roles |
| `ansible-lint` production profile | **Passing** |
| PowerShell against a real registry | **Not verified** — needs a Windows host |
| AppLocker / WDAC state collection | **Not verified** — needs a Windows host; evaluators tested against fixtures (14 cases) |
| WinRM/Kerberos transport | **Not verified** — needs a domain |
| Legacy tier (Server 2012, Win 10) | **Not verified** — no such CI runners exist; needs a documented lab |

Legacy-tier checks stay marked unverified in the coverage ledger until a lab run
signs them off. This repository will not claim a path is tested when it is not.
