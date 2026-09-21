# ADR 0015: Refuse five Active Directory privileged-access checks, with reasons

## Context

Six Essential Eight ML1 controls concern privileged access: `ism-0445`,
`ism-1175`, `ism-1380`, `ism-1688`, `ism-1689` and `ism-1883`. Together they
are **13% of the default baseline**, and none had a check.

They were the obvious next chunk — the largest single coverage gain available.
Each was designed in full, then attacked by two independent adversarial
reviews: one constructing an Australian government estate in which the design
returns a confidently wrong verdict, the other attacking whether the named
attributes, modules and access rights actually exist and are genuinely
read-only.

**Five of the six did not survive.** One was refused outright (`must-not-ship`)
and four were withdrawn on the strength of falsifying estates the reviews
built. Only `ism-1883` ships, and it ships as `attested`.

This ADR exists because the analysis is worth more than the code would have
been. Without it, the five look identical to the twenty-three ML1 controls
nobody has examined, and the next attempt repeats the work — including an
access-mask error that would have shipped a check incapable of performing its
own read.

## Decision

**The five stay `not-implemented` and earn no credit.** They are recorded here
and on [`docs/platforms/active-directory.md`](../platforms/active-directory.md)
with the specific estate that falsifies each and what must exist first.

**None is declared `attested`**, and that is deliberate. All five are
observable in principle — by a PAM vault, a SIEM, a proxy, or logon telemetry.
ADR 0013 defines `attested` as *structurally unobservable by any tool*, not
*unobservable by us yet*. Declaring them would move the attested count from 5
to 10 and drop `controls_unaccounted` from 29 to 23 while nothing had been
learned about any estate. That is using the attestation model to launder a
backlog, and it is the exact incentive ADR 0013 was written to remove.

Equally, none ships as a check that would almost always return `unassessed`.
`coverage_summary` counts **intent, not outcome**, so such an entry moves a
control out of `uncovered` on the strength of an evaluator that can never
determine anything. That is the same error running the other way — buying
headline coverage with a check that cannot answer.

## The five refusals

### `ism-1688` — unprivileged accounts cannot log on to privileged environments

Refused `must-not-ship`. Four independent defects, each verified:

- **The proposed access mask cannot perform the read.** `POLICY_READ`
  (`0x20006`) contains neither `POLICY_LOOKUP_NAMES` (`0x800`) nor
  `POLICY_VIEW_LOCAL_INFORMATION` (`0x1`), both of which
  `LsaEnumerateAccountsWithUserRight` documents as required. Every enumeration
  returns `STATUS_ACCESS_DENIED` — so the design's entire read-only safety
  argument rested on the one mask that cannot do the read.
- **The failure rule fires on the documented Windows default.** Microsoft's
  effective default for `SeInteractiveLogonRight` is Administrators, Backup
  Operators, Users — and `BUILTIN\Users` is on the design's own
  structurally-unprivileged list. So the check returns `not-satisfied` on every
  correctly hardened Tier-0 host in its out-of-box state.
- **SID-set subtraction cannot model Windows deny semantics.** Deny supersedes
  allow *per access token*, transitively. The standard correct implementation
  denies a tiering group while leaving the `BUILTIN\Users` grant in place, and
  subtraction never removes it.
- **Constrained Language Mode refuses the technique.** `ansible.windows` 3.8.0
  forces CLM whenever `GetSystemLockdownPolicy() != 'None'`, audit mode
  included, which refuses `Add-Type`, P/Invoke and the `[ADSI]` WinNT fallback.
  This repository ships `collect_windows_appcontrol` *because* the target
  estate runs WDAC — so domain controllers and privileged access workstations,
  the two host classes that most define a privileged operating environment, are
  structurally unassessable.

**Before a future attempt:** a working access mask, a rule that does not fire
on the Windows default, per-token deny evaluation rather than set subtraction,
and a technique that survives Constrained Language Mode.

### `ism-1689` — privileged accounts cannot log on to unprivileged environments

Shares the refused collector, so there is no version that ships while
`ism-1688` does not. It also carries a defect fatal **in both directions**: the
design derives well-known privileged SIDs arithmetically from the machine's
account-domain SID, but Schema Admins (518), Enterprise Admins (519) and Key
Admins (526) are `S-1-5-<ROOT DOMAIN>-N` and exist **only in the forest root**.

In the empty-forest-root topology common across large Australian government AD,
that produces a **false satisfied**: the GPO denies `STAFF-518/519/526`, which
name no object anywhere in the forest, so three inert placeholders are counted
as proof while `CORP\Enterprise Admins` is undenied and logs on daily. In a
correctly configured estate it produces a **false not-satisfied** naming a
nonexistent SID, which no remediation can ever clear. RIDs 526/527 also arrived
with the Server 2016 schema and are absent from a 2012 R2-schema forest —
squarely inside this project's declared legacy tier.

A further unresolved item: LSA account enumeration most likely requires local
Administrators, which would mean shipping a local-admin-everywhere credential
in order to assess a control about privileged access.

### `ism-0445` — privileged users have a dedicated privileged account

The transport cannot produce the facts the design's safety gates depend on.
Verified against the vendored source: `community.general.ldap_search`'s
`perform_search` returns `ldap_entries` alone and exits
`exit_json(changed=False, results=results)` — **no result code, no paging
cookie, no truncation flag**. The design gated every `not-satisfied` on exactly
those. Additionally `page_size` defaults to `0` so no paged-results control is
sent against AD's `MaxPageSize` of 1000; `scope` has no `subtree` value
(`base`/`onelevel`/`subordinate`/`children`, default `base`); and
`_normalize_string` runs `to_text(..., errors='replace')` on any attribute
absent from `base64_attributes`, lossily mangling `objectSid` and `objectGUID`
— which breaks the design's foundational "privileged groups by SID, not name"
claim and the `asset_id` that drives POA&M continuity.

Beyond the transport, both reviews built false reds against **exemplary**
estates. Linkage coverage is asymmetric in practice (`employeeID` ~100%
populated on admin accounts, ~21% on staff), and
`population_read_complete` means "I read what I was pointed at", not "no
counterpart exists anywhere" — which fires hardest on ESAE and separate
administrative forest estates, the best implementations of this very control.
Both reviews' first required change was to drop the absence-form failures,
which removes the only verdicts the check had.

### `ism-1175` — privileged accounts prevented from internet, email and web

Falsified by one extremely common estate fact the design cannot see. **Exchange
schema extensions are irreversible** — AD schema objects can be deactivated but
never removed — so `exchange_schema_present` is permanently true in any forest
that ever ran Exchange, and the guard written for the "mailboxes live in
Exchange Online now" case is structurally incapable of firing in the
post-migration estate it exists for. Uninstalling Exchange does not touch user
objects: accounts keep `homeMDB`, `msExchMailboxGuid` and
`msExchRecipientTypeDetails` pointing at a database that no longer exists. The
result is `not-satisfied` naming identifiable Commonwealth employees on an
estate meeting the email limb by the strongest mechanism available.

Two cheaper false reds sit alongside it: `userAccountControl` is never read, so
a disabled departed employee whose mailbox is retained under a records
authority is reported as a live failure; and `protocolSettings` /
`msExchOmaAdminWirelessEnable`, which record whether every client protocol is
disabled, sit on the same object in the same LDAP result and are simply not
requested.

### `ism-1380` — privileged users use separate operating environments

The only verdict-bearing evidence is **interactive logon telemetry** — 4624
types 2/10/11 and 4648 explicit-credential events — and this repository has no
collector for it. The design made `identity.logon_activity` the only
verdict-bearing fact and declared it optional, so every run would return
`unassessed / requires-external-system` while `coverage_summary` counted the
control as covered.

The reviews also showed the design unsafe even given the telemetry. An
object-level List-Contents denial on a Tier-0 OU makes its members structurally
invisible — visibility is decided at the parent container and
matching-rule-in-chain enumerates nothing — so `unresolved_members` stays empty
and every gate passes. `runas /netonly` and `Enter-PSSession` produce 4624
type 9 carrying the **unprivileged** name, so months of privileged credential
use at an unprivileged keyboard contribute zero evidence while one compliant
monthly logon satisfies the pass limb. A one-hop RD Gateway launders a
reach-back into a clean pass, because the gateway is itself correctly in the
privileged set.

## Consequences

- **Headline coverage does not move: 12 of 46, 26.0870%, before and after.**
  `controls_attested` goes 5 → 6 and `controls_unaccounted` 29 → 28; by
  ADR 0013's design the attested control earns no coverage credit. After this
  chunk **28 of 46 ML1 controls still have nothing, and five of those 28 are
  ones we examined in detail and declined to automate.** That is a worse-looking
  number than the chunk was expected to produce and it is the honest one.
- None of the six could ever have reached `direct` confidence, so even the most
  optimistic version would have added nothing to the headline compliance figure
  while adding five new ways to be confidently wrong.
- **The transport question is reopened.** `community.general.ldap_search` is
  unsuitable on its own terms and is not importable in either execution
  environment (`python3-ldap` installs to the 3.9 `site-packages` while
  ansible-core runs on 3.11 via `PYCMD`, and PyPI ships `python-ldap` as an
  sdist requiring a compiler both `bindep.txt` files deliberately exclude).
  `microsoft.ad`'s LDAP stack needs no compiler — `pyspnego` plus the
  pure-Python `sansldap`, with `krb5-workstation` already present — but exposes
  LDAP only as an inventory plugin and a diagnostic module, neither of which
  can feed a fact bundle from a collect role.
- **A recurring shape, named again.** Every one of these five fails by being
  unable to see the thing it judges: a mask that cannot read, a guard that
  cannot fire, a denial that returns zero entries and no error, telemetry that
  carries the wrong name. This repository has now found that shape six times.
  It is the reason the reviews were run before the code was written rather
  than after.

## Alternatives considered

**Ship the weakest honest versions.** Checks that almost always return
`unassessed` with a precise reason. Rejected: `coverage_summary` counts intent,
so they would move five controls out of `uncovered` on the strength of
evaluators that can never determine anything.

**Declare all six attested.** Rejected as above — they are observable, just not
by us.

**Ship nothing and record nothing.** Rejected: the next attempt would rebuild
the same designs and rediscover the same defects, and the access-mask error in
particular would probably have shipped.
