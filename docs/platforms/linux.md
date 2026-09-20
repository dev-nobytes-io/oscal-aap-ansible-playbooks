# Linux

RHEL / Rocky / AlmaLinux / Ubuntu / Debian. Collectors are native and read-only.

## Why not reuse ansible-lockdown

Reusing the mature open-source STIG/CIS content was an explicit goal, so it was
evaluated against the real repositories rather than from reputation. The full
reasoning is in
[ADR 0012](../adr/0012-mine-ansible-lockdown-tags-do-not-execute-its-roles.md);
the short version:

**They are remediation roles, not assessment roles.** In `RHEL9-STIG` 2.8.0:

```
tasks marked | PATCH | : 629
tasks marked | AUDIT | : 110
```

with PATCH tasks using `lineinfile` (119), `file` (71), `command` (62),
`template` (52), `package` (38), `shell` (37). Running them changes the host,
by design. The separate audit path **downloads and copies a Goss binary onto the
target**, which is installing software in order to assess — a much bigger ask in
a government change process than the assessment itself.

So there is no mode in which they can serve as collectors without breaking the
read-only guarantee.

What *is* valuable is their **tags**, which carry the whole identifier chain
machine-readably — 858 `CCI-*`, 449 STIG IDs, 446 Vuln IDs and ~400
`NIST800-53R4_*` references in RHEL9-STIG alone. That is the STIG → CCI →
800-53 half of a crosswalk, already maintained by someone else. The ISM carries
**zero links**, so the ISM → 800-53 half is ours regardless.

Where an organisation already runs ansible-lockdown, the two fit together
cleanly: they remediate, we assess, and neither needs to trust the other's
verdicts.

## Vendor support — `ism-1501`

The first Linux control implemented, because it is where a legacy estate gets
immediate, quantified value.

Support is judged **as of the fact's collection date**, not "now". Evaluators
cannot read a clock, and here that constraint is correct rather than tolerated:
re-running an assessment over archived evidence must reproduce the verdict that
was true when the evidence was gathered.

### Extended support is an interpretation, not a fact

Under paid extended support — Microsoft ESU, Red Hat ELS, Ubuntu Pro ESM — the
vendor *is* still issuing patches, so the control's literal wording ("no longer
supported by vendors") is met. That is defensible but lawyerly, and some
organisations treat ESU as a finding in its own right.

So it is a **parameter**, `extended_support_counts_as_supported`, defaulting to
`true`. Either way the ESU end date appears in the evidence and the finding
detail says so explicitly, so an ESU pass cannot be read as a healthy system:

> `rhel 7` is PAST mainstream support and relies on paid extended support:
> mainstream support ended 2024-06-30; extended support runs to 2029-05-31. The
> vendor is still issuing patches, so the control's wording is met, but this is
> a degraded state with a hard end date.

### The dataset

[endoflife.date](https://endoflife.date), MIT, vendored and checksummed under
`data/eol/` so assessment runs air-gapped.

It is **community-maintained, not vendor-authoritative**. For a compliance
assertion the vendor's own lifecycle page is the authority, so the check reports
`proxy` confidence and never `direct`, and a deployment may override entries
with vendor-confirmed dates. That caveat is recorded in the dataset manifest and
asserted by a test, not just written here.

An unrecognised release produces `unassessed`, never `not-satisfied`. Not
knowing whether something is supported is not the same as knowing it is not.

## Transport and least privilege

- **SSH**, with an **unprivileged account** and a narrow, explicit sudoers
  allowlist — never blanket `NOPASSWD: ALL`.
- Collection uses `ansible.builtin.slurp`, which reads a file and cannot write
  one. That keeps the role free of any mutating module surface *and* works on
  legacy targets.

## Estate tiers

| Tier | Linux | Execution environment |
|---|---|---|
| `legacy` | RHEL 7 / 8 | `ee-legacy` (ansible-core 2.16) |
| `current` | RHEL 9 / 10, Rocky, Ubuntu 22.04 / 24.04 | `ee-current` (2.19) |

ansible-core 2.17 dropped managed-node Python 2.7/3.6, and **2.20 does not
support RHEL 8 as a managed node at all**. RHEL 8 is still ubiquitous, so the
legacy image is a capability rather than technical debt.

## Verification status

| Path | Status |
|---|---|
| EOL lookup and Windows cycle derivation | **Tested** — 20 tests, no host needed |
| `ism-1501` evaluator | **Tested** against RHEL 7, Windows 10 and Windows 11 fixtures |
| Read-only guarantee (static) | **Tested** — no mutating module surface |
| `ansible-lint` production profile | **Passing** |
| `/etc/os-release` parsing on a real host | **Not verified** — needs a Linux target |
| Legacy tier (RHEL 7 / 8) | **Not verified** — needs a documented lab |
