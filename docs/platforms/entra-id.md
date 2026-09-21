# Microsoft Entra ID

The first non-host platform. Everything here is read from **Microsoft Graph**
against a tenant, not executed on a machine, and that difference changes more
than the transport.

## Why this platform exists at all

Seven of the 46 Essential Eight ML1 controls concern multi-factor
authentication, and **no host can answer any of them**. They are properties of
an identity system. Without this platform the project's ceiling is the roughly
20 host-testable ML1 controls, and the MFA family stays permanently dark.

Enumerating those nine identity-related controls against the vendored catalog
rather than assuming, only three or four are observable from an organisation's
own tenant. The rest concern third-party services, customer identity estates or
approval records, and are declared `attested` — see
[ADR 0013](../adr/0013-declare-unobservable-controls-as-attested.md).

## What is collected

| Fact | Graph endpoint | Answers |
|---|---|---|
| `entra.tenant` | `GET /organization` | Which tenant this is |
| `entra.authentication_methods_policy` | `GET /policies/authenticationMethodsPolicy` | `ism-1401` |
| `entra.conditional_access_policies` | `GET /identity/conditionalAccess/policies` | `ism-1504` |
| `entra.authentication_strength_policies` | `GET /identity/conditionalAccess/authenticationStrength/policies` | `ism-1504` at ML2/ML3 |

## Read-only, enforced at the argument

`azure.azcollection` covers only directory objects — it has no
conditional-access or authentication-methods-policy modules — so Graph is
reached with `ansible.builtin.uri`.

That makes `uri` **the first collector module which is not inherently
read-only.** Every module in the mutating list is mutating by nature and every
other module used here is safe by nature. `uri` is neither: it reads with `GET`
and rewrites a conditional access policy with `PATCH`. A test matching on
module *names* would have passed a Graph collector able to edit the tenant.

So `tests/test_collectors_are_read_only.py` asserts the **argument**:

- a `uri` task in any `collect_*` role must declare `method: GET` explicitly.
  Omitting it defaults to GET, but inheriting the guarantee means a later edit
  adding `method: PATCH` reads as a small change rather than as breaking the
  read-only promise
- the **only** exception is the OAuth token request, pinned both to
  `authenticate.yml` and to the identity platform's host, because *"it's only
  authentication"* is exactly the reasoning that would later excuse a second
  POST
- URLs are templated, so the test resolves the role's own defaults before
  checking the destination. A rule that cannot see its target is not a rule.

The credential remains the real control. The app registration holds **read-only
application permissions**:

| Permission | For |
|---|---|
| `Policy.Read.All` | authentication methods policy, conditional access |
| `Directory.Read.All` | tenant organisation record |
| `UserAuthenticationMethod.Read.All` | registration state (future work) |

The token itself is `no_log: true` at every step — it is a bearer credential for
the whole tenant and must not reach a job log or an artefact.

## The bar is the baseline's, not the Blueprint's

ASD's Blueprint specifies an as-built posture of phishing-resistant
authentication: FIDO2 and Microsoft Authenticator enabled, SMS, voice, email OTP
and OATH disabled, and a conditional access policy granting via the
"Phishing-resistant MFA and TAP" strength.

**That is an ML2/ML3 target.** ASD's own Essential Eight mapping places *"Any"*
MFA at ML1, with phishing-resistance appearing only at Maturity Levels Two and
Three. Adopting the Blueprint's configuration wholesale as the pass condition
would fail an ML1 tenant for missing a bar ML1 does not set — measuring the
wrong control, confidently.

So `require_phishing_resistant` is a **parameter, defaulting to false**, and a
deployment assessing against ML2 or ML3 sets it true. The Blueprint is cited as
the source of the values; it is not treated as the objective.

Likewise `ism-1401` asks about the *shape* of factors — "something you have and
something you know", or "something you have unlocked by something you know or
are" — not their strength. SMS is weak, and its weakness is a different
control's business. Only Email OTP genuinely fails the shape test: a code sent
to another mailbox is a second account, usually reachable with the same
password.

## Report-only policies enforce nothing

A conditional access policy in `enabledForReportingButNotEnforced` appears in
the policy list, reads like a configured control, and blocks nobody. Counting it
would report a tenant as requiring MFA when it requires none — the most
expensive false pass available here, because it is the one somebody acts on by
doing nothing.

The evaluator counts only `state: enabled`, and **names** any report-only
policies in the evidence, since that is the single most likely reason a tenant
believes it is protected when it is not.

## Confidence ceiling: `proxy`, and why it stays there

A conditional access policy states what the tenant **will require**. It is not
evidence that any particular sign-in presented a second factor, and it says
nothing about which accounts have registered an acceptable method. Sign-in logs
would move this closer to `direct`; that is the evidence-provider work, not a
claim to make from policy alone.

Two further gaps are stated in each check's rationale rather than hidden:

- The control scopes to services processing **sensitive** data. A tenant does
  not record which of its services those are, so "all resources" is used as the
  conservative proxy — a correctly-scoped narrower policy reads here as a near
  miss.
- Every real tenant excludes break-glass accounts, so exclusions are counted
  against a threshold rather than forbidden. The threshold is a judgement, not
  an observation.

## Partial reads are never failures

Graph pages its collections. Where a response still carries `@odata.nextLink`
the fact is marked `partial`, and the evaluator returns
`unassessed / partial-population`. The page that could not be read may hold the
policy that changes the answer.

## Verification status

| Path | Status |
|---|---|
| Evaluators against fixture Graph responses | **Tested** — 13 cases |
| Read-only argument enforcement | **Tested**, including that it rejects a Graph `PATCH` |
| Blueprint citations pinned and checksummed | **Verified** offline |
| Collector against a real Entra tenant | **Not verified** — no tenant available here |

The last row is the honest one. The collector's Graph calls, permission scoping
and paging behaviour have not been exercised against a live tenant, and will not
be until a lab run signs them off.
