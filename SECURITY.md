# Security policy

## Reporting a vulnerability

**Do not open a public issue.** Report privately via
[GitHub security advisories](https://github.com/dev-nobytes-io/oscal-aap-ansible-playbooks/security/advisories/new).

Please include the affected version or commit, reproduction steps, and what an
attacker gains. We will acknowledge receipt and keep you updated on remediation.

## What counts as a vulnerability here

This project is unusual: it is read-only tooling, but it holds credentials to an
entire estate and accumulates a detailed map of that estate's security posture.
The interesting attack surface is not memory safety — it is **privilege,
evidence integrity and data aggregation**.

In scope, and treated seriously:

- **Privilege escalation via collectors.** Anything that lets a collect path
  write to, execute on, or laterally reach a target. Assessment must never
  mutate; a way to make it mutate is a vulnerability, not a bug.
- **Credential exposure.** Credentials appearing in fact bundles, logs, OSCAL
  output, `no_log` bypasses, error messages or job artefacts.
- **Evidence tampering.** Any way to make the system report `satisfied` for a
  control that is not met, without that being visible. This includes forging or
  altering fact bundles, defeating the checksum chain, or bypassing expiry.
- **Data leakage from the evidence store.** Fact bundles are a
  cross-fleet aggregation of usernames, SIDs, email addresses and security
  posture. Unauthorised read access is a serious finding on its own, and
  aggregation makes it worse than any single record suggests.
- **Redaction bypass.** Sensitive values surviving into a store or report that
  the deployment's redaction policy says they should not reach.
- **Supply chain.** Dependency confusion, an unpinned artefact, a compromised
  execution environment image.

## What is not a vulnerability

- **An incorrect assessment verdict.** That is a correctness defect and matters
  a great deal — but report it via the
  [incorrect assessment result](https://github.com/dev-nobytes-io/oscal-aap-ansible-playbooks/issues/new?template=incorrect-assessment.yml)
  issue template, in public, where it can be discussed and fixed.
- **A control with no automated check.** Coverage gaps are expected, tracked and
  published in the coverage ledger.
- Findings in the ISM itself. Those belong with ASD.

## Handling evidence in reports

When reporting, **redact estate data**. Hostnames, IP addresses, account names,
SIDs, domain names and organisational posture are exactly the data this project
is designed to protect. A synthetic reproduction is always preferred over a real
fact bundle.

If a real bundle is genuinely necessary to demonstrate the issue, say so and we
will arrange a channel for it — do not attach it to an advisory unprompted.

## Operating this project securely

Deployment guidance lives in [`docs/13-security-model.md`](docs/13-security-model.md).
The short version:

- Bind collect job templates to credentials that **cannot write**. The read-only
  guarantee should not depend on this project's roles being well behaved.
- Treat the evidence store as holding data at the highest classification of any
  system it assesses.
- Pin execution environment images by digest and serve them from a private
  Automation Hub.
