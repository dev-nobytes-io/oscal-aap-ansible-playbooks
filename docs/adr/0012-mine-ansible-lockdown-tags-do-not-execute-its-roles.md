# ADR 0012: Mine ansible-lockdown's tags; do not execute its roles

## Context

[ansible-lockdown](https://github.com/ansible-lockdown) (MindPoint Group / Tyto
Athene) is the canonical open-source Ansible hardening content: STIG and CIS
roles for RHEL, Ubuntu, Amazon Linux and Windows. Reusing it instead of
hand-writing hundreds of host checks was an explicit goal of this project, so it
was evaluated properly against the real repositories rather than from reputation.

### What it is

Actively maintained and permissively licensed — **MIT**, © MindPoint Group.
Verified tag counts:

| Repository | Tags | Latest |
|---|---|---|
| `RHEL8-STIG` | 28 | 4.3.0 |
| `RHEL9-CIS` | 18 | 2.4.0 |
| `UBUNTU22-CIS` | 14 | 3.1.0 |
| `RHEL9-STIG` | 13 | 2.8.0 |
| `UBUNTU24-CIS` | 8 | 1.7.0 |
| **`Windows-2022-STIG`** | **2** | 1.0.1 |

Linux content is mature. Windows content is thin — worth knowing, because
Essential Eight ML1 is Windows-centric, so the platform where reuse would help
most is the platform where least exists.

### The decisive finding

**These are remediation roles, not assessment roles.** In `RHEL9-STIG` 2.8.0:

```
tasks marked | PATCH | : 629
tasks marked | AUDIT | : 110
```

and the PATCH tasks use exactly the modules you would expect —
`lineinfile` (119), `file` (71), `command` (62), `template` (52),
`package` (38), `shell` (37), `replace` (29).

Running them is *by design* a mutation. A representative task:

```yaml
- name: HIGH | RHEL-09-211045 | PATCH | The systemd Ctrl-Alt-Delete burst key sequence must be disabled
  when: rhel_09_211045
  tags: [RHEL-09-211045, CAT1, CCI-002235, SV-257784r1155651_rule, V-257784, NIST800-53R4_AC-6]
  block:
    - ansible.builtin.file: {path: /etc/systemd/system.conf.d/, state: directory, ...}
    - ansible.builtin.template: {src: ..., dest: /etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction, ...}
```

The separate audit path is not a way out either: `LE_audit_setup.yml`
**downloads and copies a Goss binary onto the target** (`get_url`, then `copy`).
Installing software on a host in order to assess it is a mutation, and in a
government change process it is a far bigger ask than the assessment itself.

So there is no mode in which ansible-lockdown can serve as a collector without
breaking principle 6 — assessment never changes a host.

### What is genuinely valuable

The **tags**. Every task carries the full identifier chain, machine-readably:

| Identifier | Count in RHEL9-STIG |
|---|---|
| `CCI-NNNNNN` | 858 |
| `RHEL-09-NNNNNN` (STIG ID) | 449 |
| `V-NNNNNN` (Vuln ID) | 446 |
| `NIST800-53R4_<control>` | ~400 across families |

That is the **STIG rule → CCI → NIST 800-53** half of the crosswalk chain,
already done and maintained by someone else. The ISM carries **zero links**, so
the ISM → 800-53 half is ours to author regardless; having the other half for
free is a real saving.

## Decision

**Do not execute ansible-lockdown roles.** Collectors are written native,
read-only, and follow the pattern established for Windows in PR 05: gather raw
facts, judge nothing.

**Do mine its tags** to build a vendored STIG ↔ CCI ↔ NIST 800-53 reference
index, attributed under MIT, used as one input when authoring ISM crosswalks.

Every crosswalk entry derived this way still carries an explicit equivalence
rating (`equivalent` / `partial` / `related`) and a citation. A STIG rule is not
an ISM control; silently treating them as identical is the most likely route to
this repository becoming quietly, confidently wrong.

## Status

Accepted.

## Consequences

We write our own Linux collectors rather than getting hundreds of checks free.
That cost is real and was the point of evaluating reuse — but the alternative
was a compliance tool whose "assessment" reconfigures the estate it assesses,
which is not a trade worth making.

Their content remains genuinely useful as a **reference** for what a control
looks like in practice on a given platform, and their tag data is a maintained
asset we consume rather than duplicate. The extraction tool lands with the
crosswalk work in PR 10, not here, so this chunk stays focused.

Where an organisation already runs ansible-lockdown for remediation, the two fit
together cleanly: they remediate, we assess, and neither needs to trust the
other's verdicts.

Revisit if ansible-lockdown ever ships a genuinely agentless read-only audit
mode. The Goss path is close in spirit but not in mechanism.
