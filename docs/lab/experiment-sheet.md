# Lab experiment sheet

**Written before the run, and committed, so a result cannot be fitted to
whatever the run happened to produce.**

That ordering is the whole point. Three of the fifteen automated controls sit
behind collectors that a domain controller cannot meaningfully exercise, and a
shape diff over an empty fact yields zero differences — which reads as
agreement. Deciding afterwards what the run "showed" is how a null result gets
promoted.

## The lab

One Windows domain controller, `estate_tier: current`. No member workstation, no
member server, no legacy host, no Entra tenant.

## Per collector, decided in advance

| Collector | Expected on a DC | Promotable? |
|---|---|---|
| `collect_windows_base` | `os.release` full. `optional_features` enumerates, but a Server SKU's feature set, not an SOE's. `ie_policy` empty — the policy key does not exist unless a GPO created it | **Partly.** `os.release` yes; `ie_policy` **no** |
| `collect_windows_applications` | HKLM Uninstall is never empty on a real Windows install | **Yes** |
| `collect_windows_appcontrol` | `Get-AppLockerPolicy -Effective` returns a real five-collection `NotConfigured` policy; `Win32_DeviceGuard` returns a real instance; the `%WINDIR%` DACL walk produces dozens of real probes | **Yes** — and this is the collector behind the false red in ADR 0017, so it is the most valuable single result available |
| `collect_windows_office` | **Empty by construction.** Office is not installed on a DC | **No** |
| `collect_windows_browsers` | **Empty on a stock DC.** The collector reads `SOFTWARE\Policies\…` keys that do not exist until an Edge GPO is applied | **No** |

So **three of five can be promoted and two cannot**, and the two that cannot are
the ones whose floors in [`floors.yml`](floors.yml) are written knowing they will
fail. They are declared rather than omitted precisely so the run reports them as
*unmet floors* instead of as silent agreement.

## Hard exclusions — not promotable by this lab under any result

- **The `ee-legacy` tier.** dc01 is `estate_tier: current`. Server 2012 R2 and
  Windows 10 remain entirely unverified, and
  [`docs/platforms/windows.md`](../platforms/windows.md) must keep saying so.
- **Anything Entra.** The Graph collectors have never touched a tenant and this
  run does not change that.
- **The five Active Directory controls refused in
  [ADR 0015](../adr/0015-refuse-five-active-directory-privileged-access-checks.md).**
  Their refusals rest on estates where each design returns a confidently wrong
  verdict — ESAE and admin-forest topologies for `ism-0445`, the **empty forest
  root** for `ism-1689`, the irreversible Exchange schema extension for
  `ism-1175`, type-9 logon telemetry for `ism-1380`, the LSA access mask for
  `ism-1688`. One lab domain does not contain those topologies, so it cannot
  test them. A green run here overturns none of it.
- **Whether a browser or Office policy is *honoured* by the running application.**
  Only `edge://policy` reporting `Status: OK` would show that, and it is
  per-user, per-profile and not readable from a remote query. This is why none of
  those checks can ever be `direct`.

## One experiment worth running that is not about the collectors

**The ACL-denied subtree.** ADR 0015 rests partly on the claim that an
ACL-denied LDAP subtree returns *zero entries and no error* — wire-identical to
a genuinely empty result, so a directory read cannot tell "no privileged
accounts" from "not allowed to see them".

That claim is **already settled by primary documentation**, so a lab run is
confirmatory rather than decisive: MS-ADTS 5.1.3.3.6 states that without
`RIGHT_DS_LIST_CONTENTS` on a container "no child object of that container is
visible to the user", and RFC 4511 §4.5 defines the search result set as already
subject to access controls with no mechanism to signal suppression — Appendix A
explicitly licenses substituting `noSuchObject` for `insufficientAccessRights`.

Worth running anyway, for the one thing the documents do not settle: whether a
specific DC deviates from the documented model. Deny `RIGHT_DS_LIST_CONTENTS` on
a throwaway test OU, run a subtree search, observe the result code, then remove
the ACE. Minutes, reversible, and it either confirms the refusal or overturns a
published ADR.

One precision correction to record either way: ADR 0015's line 186 says "a
denial that returns zero entries and no error", which is right for the subtree
case but **overbroad** — a denial on the search *base* does return a code.

## What a green run would actually mean

That three collectors execute against a real Windows host and return structured
data matching what the fixtures and evaluators expect. That is genuinely more
than this project has ever been able to say. It is **not**:

- that the Windows surface is verified — two collectors stay untested
- that any control's verdict is correct on a real estate
- that the read-only credential suffices, unless the run used one and recorded it
- that anything about the legacy tier, Entra, or ADR 0015's refusals has changed
