# Security model

This project is read-only tooling that nonetheless holds credentials to an
entire estate and accumulates a detailed map of that estate's security posture.
Its risk profile is therefore about **privilege, evidence integrity and data
aggregation** — not about the usual application attack surface.

## Least privilege

> **Read-only is enforced by the credential, not by our roles.**

Collect roles carry no mutating module surface, which makes the intent visible
in review. But "our code is well behaved" is not a control that survives
adversarial review, and it is not what you want to put in front of an assessor.
Bind collect job templates to credentials that **physically cannot write**:

| Target | Credential |
|---|---|
| Windows | Domain account with remote-read rights; no local admin where avoidable |
| Linux | Unprivileged SSH account with a narrow, explicit sudoers allowlist — never blanket `NOPASSWD: ALL` |
| Entra ID / M365 | App registration with `Policy.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `DeviceManagementConfiguration.Read.All` — application permissions, no write scopes |
| vSphere / Aria | Built-in read-only role scoped to the assessed objects |
| Kubernetes | A `ClusterRole` with `get`/`list`/`watch` only |
| Network devices | Privilege level permitting `show` commands only |
| CyberArk, Splunk, NetApp, Exchange | Read/query-only service accounts |

Remediation uses **separate, write-capable credentials**, bound only to
remediation job templates. The two credential sets never appear on the same
template.

### Active probes are the exception, and are treated as one

An `evidence_tier: active` probe may need network or write rights. That shifts
the read-only guarantee onto credential scoping alone, so probes: live in a
separate `probe_*` role namespace, require explicit opt-in, carry their own
credential, and in a government environment need change approval. Their results
are marked `reproducible: false`.

## The evidence store is the crown jewel

Fact bundles are a durable, cross-fleet aggregation of usernames, SIDs, email
addresses, group memberships, policy state and known control failures. It is a
map of where the estate is weak.

**Treat the evidence store as holding data at the highest classification of any
system it assesses.** Encrypt at rest. Restrict read access more tightly than
the assessed systems themselves — aggregation makes the whole considerably more
sensitive than any individual record.

Every bundle and every OSCAL document carries a classification marking
(core-namespace `marking` prop, `class: pspf`).

### Redaction is policy-driven per deployment

There is no single correct answer here, and it is not this project's call to
make. Full identifiers give precise remediation targeting; redacted bundles are
far safer to retain and share. That trade-off belongs to the risk owner in each
organisation.

So redaction is a **configurable policy with a conservative default**, applied
**between collection and persistence** — never after. You cannot retroactively
un-collect.

Each fact key declares how its sensitive elements are handled:

| Mode | Behaviour |
|---|---|
| `retain` | Stored as collected |
| `hash` | Replaced by a salted hash — correlation across runs survives, the identifier does not |
| `truncate` | Structure kept, identifying portion removed (e.g. a SID's RID) |
| `drop` | Removed entirely |

The default policy hashes user identifiers and drops free-text fields that
commonly carry incidental data. Findings still report *"137 endpoints fail"*;
whether an operator can pivot to *which user* is the deployment's decision.

Two consequences to accept openly: hashing costs remediation targeting, and a
salt is itself a secret whose rotation breaks longitudinal correlation. Choose
deliberately, and record the choice — the active policy version is recorded in
every bundle so results remain interpretable later.

### Retention

Evidence retention is a records-management decision, not a technical default.
Bundles referenced by a *published* assessment result must be pinned regardless
of age — otherwise a published result cannot be substantiated. Beyond that,
retain to the organisation's schedule.

## Evidence integrity

If someone can alter a fact bundle undetected, every downstream claim is void.

- Bundles are content-addressed; observations carry `fact-bundle-sha256`.
- OSCAL back-matter resources reference evidence with `hashes`.
- Component-definitions reference the **released, hashed** tooling artefact that
  produced the verdict, pinning the exact code version.
- Deterministic UUIDv5 derivation means the same facts re-produce byte-identical
  OSCAL, so an auditor can independently re-derive a published document and
  compare.
- Evaluator purity (no network, no subprocess) is what makes that re-derivation
  meaningful, and is enforced in CI rather than assumed.

## Credential handling

- Credentials live in AAP credentials or a vault. Never in this repository, never
  in inventory, never in a fact bundle.
- `no_log` on any task that could echo a secret; the PR checklist asks about it.
- `.gitignore` excludes `*.pem`, `*.key`, `*.vault`, `credentials.yml`, `.env`;
  pre-commit runs `detect-private-key`. Both are backstops, not the control.
- Execution environment images are pinned **by digest** and served from a private
  Automation Hub in restricted environments.

## Air-gapped operation

The assess → evaluate → report path runs with **zero internet egress**: OSCAL
data, JSON schemas and reference datasets are vendored. Ingest is the only online
step and happens in CI, never on the estate.

The evaluator is restricted to the standard library and Python 3.9 syntax so
that it runs under whatever `python3` an environment hands it — on RHEL 9 and
CentOS Stream 9 that is 3.9, and in an enclave you do not get to choose. See
ADR 0007, which records why this floor is *not* about `ee-legacy`'s
`ansible-core` version.

## Threat cases worth stating

| Threat | Mitigation |
|---|---|
| Compromised controller reaches the whole estate | Read-only credentials; remediation creds separate and on separate templates; assessment cannot mutate even if the controller is owned |
| Evidence store exfiltrated | Encryption at rest; access control tighter than assessed systems; redaction policy limits blast radius |
| Tampered results hide a failure | Content-addressed evidence, hashed tooling references, deterministic re-derivation |
| Supply chain compromise of an EE | Digest-pinned images, private hub, pinned dependencies |
| Assessment output leaks estate weaknesses | Classification markings carried end to end; results treated as sensitive, not as a dashboard to share widely |

## Reporting

See [`../SECURITY.md`](../SECURITY.md). Do not attach real fact bundles to
reports — synthetic reproductions are always preferred.
