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
| `ism-0843` | `win-application-control-implemented` | `proxy` | That an enforcing policy actually restricts anything — see below |
| `ism-1657` | `win-application-control-file-types` | `partial` | Nothing: AppLocker *cannot* satisfy this control — see below |
| `ism-1870` | `win-application-control-user-writable-paths` | `partial` | Temporary folders belonging to applications outside the probed set |
| `ism-1704` | `win-unsupported-applications-removed` | `partial` | PDF applications, email clients and security products — not in the dataset |
| `ism-1485` | `win-browser-ads-blocked` | `partial` | Gateway/proxy filtering, which ASD also names; whether a forced extension is enabled |
| `ism-1486` | `win-browser-java-blocked` | `proxy` | Whether a Java ActiveX control is actually registered |
| `ism-1585` | `win-browser-settings-locked` | `partial` | That the running browser honours each policy name; Firefox managed by policies.json |

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

## Application control: the default rules fail `ism-1870`

`ism-1870` asks whether application control is **applied to user profiles and
temporary folders used by operating systems, web browsers and email clients**.
It is the control AppLocker's default rules fail, and they fail it quietly.

The default rules allow `Everyone` to execute anything under `%PROGRAMFILES%`
and `%WINDIR%`. `C:\Windows\Temp` is inside `%WINDIR%`, is the operating
system's temporary folder, and is writable by standard users on a default
install. So a workstation can enforce every rule collection, report thousands
of rules, pass a rule-count checklist — and still let a standard user drop an
executable into a temporary folder and run it.

Microsoft states the problem in the control's own terms, on the page the check
cites:

> Because path rules specify locations within the file system, you should
> ensure that there are no subdirectories that are writable by
> nonadministrators. For example, if you create a path rule using the allow
> action for `C:\`, any file under that location can run, including file
> within users' profiles.

Answering it needs **two** observations, and neither substitutes for the other:

1. **The rule paths the policy allows.** `Get-ApplicationControlState.ps1` now
   emits each `FilePathRule`'s paths, action, principal SID and exceptions, not
   just a rule count. A count cannot answer a question about *where*.
2. **Which of those locations this host reports as writable by a
   non-administrator.** `Get-UserWritableExecutionPaths.ps1` reads the DACL of
   the operating system temp folder, the profile root, each probed profile and
   its browser and email-client temporary folders, plus the writable
   subdirectories of `%WINDIR%` to a bounded depth.

The second half is the reason there is no hardcoded list of "directories
everyone knows are writable". An estate that hardened `C:\Windows\Temp` is in
a different position from one that has not, and a fixed list would report both
identically — reporting a false failure against a control someone had actually
fixed.

### Three deliberate asymmetries

| Situation | Result | Why |
|---|---|---|
| Walk truncated or a path unreadable, **nothing found** | `unassessed` | An incomplete search finding nothing is not evidence that there is nothing |
| Walk truncated, **something found** | `not-satisfied` | A writable directory that was found is writable whether or not the walk finished |
| Allow rule carries no readable path condition | `unassessed` | A rule whose scope could not be determined is not a rule that allows nothing |

A collection left `NotConfigured` restricts nothing anywhere, which is
`ism-0843` and `ism-1657`'s finding. Repeating it under every control it
touches would turn one problem into five and bury the specific gap this check
exists to surface, so only **enforcing** collections are judged here.

An allow rule scoped to `BUILTIN\Administrators` is recorded but not counted
as a failure, because this control is about locations rather than about whether
privileged accounts are themselves subject to application control. A deployment
that reads it more strictly — and at ML2/ML3 it probably should — sets
`fail_on_administrator_allow`.

### AppLocker path variables are not environment variables

The AppLocker engine interprets exactly six: `%WINDIR%`, `%SYSTEM32%`,
`%OSDRIVE%`, `%PROGRAMFILES%`, `%REMOVABLE%` and `%HOT%`. `%TEMP%` in a rule is
literal text matching no real directory. `%SYSTEM32%` and `%PROGRAMFILES%` each
expand to **two** directories on a 64-bit host, and the evaluator expands both —
collapsing them to one would silently drop half the paths a rule covers.

### One collector bug this chunk fixed

`RuleCollectionExtensions` is a sibling of the rules inside a `RuleCollection`,
not a rule. The previous collector counted every element child, so a collection
holding **no rules** could report `rule_count: 1` — and `rule_count > 0` is what
`ism-0843` uses to decide a collection is enforcing. An empty enforcing
collection restricts nothing while reading as implemented. Rules are now counted
by element name.

## Unsupported applications — `ism-1704`, and what it cannot see

The control names six families: *Office productivity suites, web browsers and
their extensions, email clients, PDF applications, Adobe Flash Player, and
security products.*

The vendored end-of-life dataset covers three and a half of them. Searching
endoflife.date's 477-product index confirms there is **no entry** for Microsoft
Edge, any PDF reader, email clients or security products — and browser
extensions are not an installed-application concept at all.

| Family | Covered | How |
|---|---|---|
| Office productivity suites | yes | `office`, `libreoffice` |
| Web browsers | partly | `chrome`, `firefox` — **not Edge** |
| Java | yes | `oracle-jdk` |
| Adobe Flash Player | yes | public record, no feed needed |
| PDF applications | **no** | not in the dataset |
| Email clients | **no** | not in the dataset |
| Security products | **no** | not in the dataset |
| Browser extensions | **no** | not an installed application |

Those gaps are named in **every** result, satisfied or not. Silence would imply
coverage.

### Three ways this check refuses to flatter

- **Nothing mappable is `unassessed`, not a pass.** A workstation full of
  line-of-business software that maps to no support timeline has not been
  shown to satisfy the control. Reporting `satisfied` because nothing was
  recognised would put a green tick against a control that was never evaluated.
- **Unmapped applications are never counted as supported.** They are reported
  separately and are neither passed nor failed.
- **An unreadable profile hive makes the whole result partial.** The hive that
  could not be read may hold the unsupported application.

### Adobe Flash is judged from public record

The control names Flash explicitly, endoflife.date does not carry it, and its
end of life is not a judgement: Adobe ended support on **2020-12-31** and began
**blocking Flash content from running on 2021-01-12**. Any installation found
is unsupported, with no feed consulted and no room for argument.

### A mapping bug worth recording

Office's end-of-life cycles are **release years** (`2016`, `2019`, `2021`,
`2024`) while every modern Office reports a version of `16.0.x`. Deriving the
cycle from the version yields `16`, which matches nothing — so the check
silently learned nothing about the first product family the control names. The
year comes from the display name instead. An Office with no year in its name is
a subscription build, which is evergreen and correctly reports as unknown
rather than as supported.

## Web browsers: three controls, three traps

Each of `ism-1485`, `ism-1486` and `ism-1585` has an obvious implementation,
and each obvious implementation is wrong in a documented way.

### ASD says the obvious `ism-1485` evidence is not a mitigation

The natural check reads Chromium's `AdsSettingForIntrusiveAdsSites`. ASD's own
Blueprint says otherwise, in writing:

> Microsoft Edge's native web advertisement capability is limited and **does not
> provide an effective mitigation** against the risk of malicious web
> advertisement.

And `BlockAds` is Edge's **default**. A check resting on it would report every
unmanaged Edge installation in an estate as satisfying a control ASD states it
does not meet. Two further wrinkles: Chrome's unset default is the *opposite*
(allow advertisements everywhere), and Chromium documents that the blocking
value does nothing when `SafeBrowsingEnabled` is false.

So the verdict rests on a **force-installed ad-blocking extension**, which ASD
names as the effective mechanism. The native setting and Safe Browsing state
are recorded as supporting facts and neither is decisive.

**The accepted false red**: ASD also names *proxy-level* filtering as part of
this control, and that is invisible from a host. An estate blocking
advertisements at the gateway reads here as a failure it has in fact mitigated.
That is stated in the finding itself rather than hidden.

### `\Recommended` is not locked, and it matches the Office glob

Chromium publishes every policy at **two** registry paths:

| Path | Meaning |
|---|---|
| `SOFTWARE\Policies\Microsoft\Edge` | **mandatory** — the user cannot change it |
| `SOFTWARE\Policies\Microsoft\Edge\Recommended` | a default the user **may override** |

`Get-OfficeMacroPolicy.ps1` derives `gpo_delivered` as
`$Path -like '*\Policies\*'`. **Both paths match it.** Copying that line onto
browsers would report every user-overridable default as locked — the precise
inverse of what `ism-1585` asks.

`Get-BrowserPolicy.ps1` classifies into `mandatory` / `recommended` /
`preference` instead, via `Get-PolicyLevel`, which is a pure string function so
that it can be **executed** in the test suite rather than reviewed. Firefox has
no `\Recommended` concept at all: its only locking mechanism is a `Status`
field inside the `Preferences` policy, one JSON document in one `REG_MULTI_SZ`
value, which the collector emits raw and the evaluator parses.

The control says browsers, plural, so the semantics are **every installed
browser**. A hardened Edge beside a developer's per-user Chrome with no policy
does not meet it.

### `ism-1486`: NPAPI is gone, and the hole it left is in Edge

No browser policy value answers this control. NPAPI — the interface Java
applets required — was removed from Chrome in **45** and Firefox in **53**.
Note 53, not 52: plug-ins kept working in ESR 52, which is exactly the build a
conservative government SOE is most likely to have pinned. Chromium's
`DefaultPluginsSetting` and `PluginsBlockedForUrls` are documented **obsolete**
and concerned Flash; reading either would be reading a dead key.

So the control is answered from which browsers are installed and at what
version — satisfied by construction, with the evidence of the construction
recorded rather than asserted.

**With one live exception, and it is why this check exists.** Internet Explorer
never used NPAPI: its Java plug-in was an **ActiveX control**. Edge Internet
Explorer mode runs the Trident engine and supports ActiveX.
[`win-ie11-disabled`](../../checks/windows/win-ie11-disabled.yml) deliberately
records `edge_ie_mode` **without judging it**, because `ism-1654` speaks to
Internet Explorer 11 as a browser rather than to the MSHTML engine.

That leaves **Edge + IE mode + a registered Java runtime** as a current,
exploitable configuration that every other check in this repository passes. It
is reported `not-satisfied` here.

What the collector does *not* do is match a Java plug-in CLSID. The constant
could not be verified against a current vendor document, and a collector
matching an unverified constant reports "absent" for something it merely failed
to look for correctly. Whatever is under `HKLM\SOFTWARE\JavaSoft` is emitted
verbatim instead.

### Why none of the three can be `direct`

A registry value is an administrator's **intent**, not the running browser's
**behaviour**. The only thing that would show the latter is `edge://policy` or
`chrome://policy` reporting *Status: OK* — per-user, per-profile, and not
readable from a read-only remote query. Chromium also deprecates policy names
on a six-week cadence, so a value in the registry may name a policy the
installed build no longer honours.

## Verification status

| Path | Status |
|---|---|
| Evaluator logic | **Tested** — fixture bundles, no host needed |
| Read-only guarantee (static) | **Tested** — no mutating module surface in collect roles |
| `ansible-lint` production profile | **Passing** |
| PowerShell syntax, every collector | **Tested** — `make ps-lint` parses each script with PowerShell's own parser; CI job `powershell` |
| AppLocker XML parsing | **Tested by execution** — the collector's own `ConvertFrom-AppLockerPolicyXml` runs against a real policy document on Linux and its output is fed to the evaluators |
| PowerShell against a real registry | **Not verified** — needs a Windows host |
| AppLocker / WDAC state collection | **Not verified** — needs a Windows host; evaluators tested against fixtures (14 cases) |
| AppLocker rule-path and DACL collection | **Not verified** — needs a Windows host; evaluator tested against fixtures (34 cases) |
| Browser policy collection | **Not verified** — needs a Windows host; evaluator tested against fixtures (21 cases) |
| Browser `policy_level` classification | **Tested by execution** — `Get-PolicyLevel` runs under PowerShell in CI, including the `\Recommended` case the Office glob gets wrong |
| WinRM/Kerberos transport | **Not verified** — needs a domain |
| Legacy tier (Server 2012, Win 10) | **Not verified** — no such CI runners exist; needs a documented lab |

Legacy-tier checks stay marked unverified in the coverage ledger until a lab run
signs them off. This repository will not claim a path is tested when it is not.

Two of those rows are new and deliberately narrow. Parsing is a long way short
of running, and running `ConvertFrom-AppLockerPolicyXml` on Linux says nothing
about `Get-AppLockerPolicy`, `Get-Acl` or `Win32_DeviceGuard`. What it does say
is that the collector's output shape and the evaluator's expectations agree —
which was previously asserted by a hand-written fixture agreeing with itself.
The test that closes that loop is
[`tests/test_powershell_collectors.py`](../../tests/test_powershell_collectors.py).
