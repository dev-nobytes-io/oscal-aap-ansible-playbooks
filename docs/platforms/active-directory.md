# Active Directory

The platform where six Essential Eight ML1 controls live — and where, so far,
**five of them are deliberately not implemented**.

That is the unusual thing about this page. Every other platform page lists what
can be evidenced. This one leads with what cannot, because the analysis is the
deliverable: each refusal names the estate that falsifies the design and what
must exist before a future attempt. The reasoning is in
[ADR 0015](../adr/0015-refuse-five-active-directory-privileged-access-checks.md).

## What can be evidenced here

| Control | Check | Assessability | Notes |
|---|---|---|---|
| `ism-1883` | `org-privileged-online-service-access-limited` | `attested` | Both sides of the control's comparison are approval artefacts |

## What is deliberately not implemented

| Control | Why not, in one line |
|---|---|
| `ism-0445` | The LDAP transport returns no result code, no paging cookie and no truncation flag — the facts every safety gate was built on |
| `ism-1175` | Exchange schema extensions are irreversible, so the check cannot tell a live mailbox from years-old directory residue |
| `ism-1380` | The only verdict-bearing evidence is logon telemetry this repository has no collector for |
| `ism-1688` | The proposed LSA access mask cannot perform its own read, and the failure rule fires on the documented Windows default |
| `ism-1689` | Shares that collector; also derives forest-root SIDs arithmetically, which is false-satisfied in the common empty-root topology |

**None of these is `attested`.** All five are observable in principle — by a
privileged access management vault, a SIEM, a proxy, or logon telemetry.
[ADR 0013](../adr/0013-declare-unobservable-controls-as-attested.md) reserves
`attested` for what no tool can ever see, not for what this project cannot see
yet. Declaring them would have moved the attested count from 5 to 10 while
nothing had been learned about any estate.

## Why `ism-1883` is different

It is the only one of the six whose predicate contains no system state at all.

*"Privileged user accounts explicitly authorised to access online services are
strictly limited to only what is required for users to undertake their duties
or functions."*

**"Explicitly authorised"** is an approval. A security group, a proxy rule or
an Entra group is the *implementation* of an authorisation decision, never the
decision — the substitution this project already refused for `ism-1507`. Here
it cuts deeper: for `ism-1507` the approval merely produces a membership the
control is about, while here the approval **defines the population the control
is a statement about**. A directory read cannot even compute the denominator.

**"Only what is required"** is a proportionality judgement about a person's
job. No directory, PAM vault, identity governance platform, proxy or CASB holds
an attribute meaning "what this person's duties require".

And decisively: no product implements "strictly limited to what is required"
the way a conditional access policy implements "MFA is required". Where such a
mechanism exists this project automates at `proxy` or `partial` and accepts the
ceiling. Here there is nothing to read, which makes it structure rather than
effort.

## Transport: read the directory, not the host

The decision that shapes any future collector, and it is a security decision
before it is a technical one.

`microsoft.ad.object_info` runs over **WinRM against a domain controller**.
WinRM's default `RootSDDL` grants remote execute only to
`BUILTIN\Administrators`, which on a DC contains Domain Admins. So that path
costs **Domain Admin on every domain controller** — to assess controls that say
privileged access must be rare, and which the vendored ISM catalogue states
verbatim: *"Access to Microsoft AD DS domain controllers … is limited to
privileged users that require access."*

A collector that needs Domain Admin on every DC in order to prove Domain Admin
is rare is self-defeating.

**An LDAP bind with no write ACEs literally cannot write**, which is the only
option that composes with [`../13-security-model.md`](../13-security-model.md).
It needs a domain account with no host logon anywhere and works identically
against a Server 2012 R2 domain controller.

### The transport is not yet available

| Route | Blocker |
|---|---|
| `community.general.ldap_search` | Returns no result code, no paging cookie, no truncation flag. `page_size` defaults to `0`, so no paged-results control is sent against AD's `MaxPageSize` of 1000. `scope` has no `subtree` value. `_normalize_string` lossily mangles `objectSid` and `objectGUID`. |
| `python-ldap` (its dependency) | Installs to the 3.9 `site-packages` while ansible-core runs on 3.11 via `PYCMD`; PyPI ships it as an sdist needing a compiler both `bindep.txt` files deliberately exclude. |
| `microsoft.ad` LDAP | Needs **no compiler** (`pyspnego` + pure-Python `sansldap`; `krb5-workstation` already present) — but exposes LDAP only as an **inventory plugin and a diagnostic module**, neither of which can feed a fact bundle from a collect role. |

## Least privilege, when a collector does exist

Plain **Domain Users** is sufficient for most of the ISM's AD surface —
`userAccountControl`, `pwdLastSet`, `adminCount`, `member`/`memberOf`,
`servicePrincipalName`, `msDS-SupportedEncryptionTypes`, `groupType`,
`primaryGroupID`, `lastLogonTimestamp`, and privileged group membership. No
delegated account is needed for those.

Two exceptions matter, and one is a trap:

- **LAPS and gMSA passwords are confidential attributes** requiring
  `CONTROL_ACCESS`. A compliance collector must read an expiry *timestamp* and
  never the secret. `microsoft.ad`'s optional `dpapi-ng` dependency exists
  precisely to decrypt them — **do not install it.** Pulling estate-wide local
  administrator passwords into a fact bundle would be a Principle 10
  catastrophe.
- **SACL (audit configuration) needs `SeSecurityPrivilege`**, so "is AD
  auditing configured" is not answerable from a read account — while "does
  Domain Computers have write permissions to any AD object" is, because DACLs
  are readable with `READ_CONTROL`. Anything hitting this must return
  `unassessed / insufficient-privilege`, never `not-satisfied`.

### One upstream documentation error to know about

`microsoft.ad`'s `port` option and its LDAP connection guide both state that
*"port 686 is used for LDAPS"*. **686 is a typo for 636** — the same option's
own default line is correct. Never rely on port→`tls_mode` inference; set
`tls_mode` explicitly. Getting it wrong means a simple bind's password crosses
the wire in cleartext while the collector believes it is on LDAPS.

## The silent failure mode that shapes everything here

LDAP's failure modes are **success-shaped**. An ACL-denied subtree returns zero
entries and no error. An ACL-denied attribute is simply absent from the
returned entry, indistinguishable at the wire level from empty.

A Tier-0 OU with inheritance blocked and an explicit Deny-Read for
Authenticated Users — which is correct hardening — returns nothing, and a naive
collector reports a clean population. Worse, the estates that hide the most
from a read-only bind are the ones implementing these controls best. Any future
AD check must treat "I read what I was pointed at" as strictly weaker than "no
counterpart exists anywhere", and must fail closed on the difference.

## Verification status

| Path | Status |
|---|---|
| `ism-1883` attestation model | **Tested** — registry schema, attestation invariants, report rendering |
| Every other control here | **Not implemented** — deliberately, see ADR 0015 |
| LDAP transport | **Not selected** — no available route can feed a fact bundle read-only today |
| Against a real domain controller | **Not verified** — needs a lab with a forest, a child domain and a 2012 R2 DC |

There is no collector on this page to be unverified. That is the honest state,
and it is recorded rather than left as an empty table someone might read as
"coming soon".
