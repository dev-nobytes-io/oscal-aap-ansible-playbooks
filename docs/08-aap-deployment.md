# Deploying on Ansible Automation Platform

Targets **AAP 2.6**. Everything here has an AWX equivalent — see
[`09-awx-deployment.md`](09-awx-deployment.md).

## Two execution environments

| Image | ansible-core | Controller Python | Evaluator Python | Reaches |
|---|---|---|---|---|
| `ee-current` | 2.19.x | 3.11 | 3.9 | Server 2016+/Win 11, RHEL 9/10, Ubuntu 22.04/24.04 |
| `ee-legacy` | 2.16.x | 3.11 | 3.9 | Server 2012/2012 R2, RHEL 7/8, Python 2.7/3.6 targets |

`ee-legacy` is a **capability, not technical debt**. ansible-core dropped
Windows Server 2012/2012 R2 after 2.16, dropped managed-node Python 2.7/3.6 in
2.17, and does not support RHEL 8 as a managed node in 2.20. Government estates
run all of those. Refusing to assess a legacy host does not make it secure — it
makes it unmeasured.

**Both images carry two interpreters, and the distinction matters.**

- `/usr/bin/python3.11` runs **`ansible-core`**. Core 2.16 requires ≥ 3.10 and
  core 2.19 requires ≥ 3.11, so both tiers are on 3.11. An execution
  environment's own Python is the *controller's*; what reaches a 2012 host is
  core 2.16's **managed-node** support, which is independent of it. It is
  selected with `--build-arg PYCMD=/usr/bin/python3.11`, which is why images
  are built with `make ee-build EE=…` rather than a bare `ansible-builder`
  invocation — ansible-builder v3 does not let `PYCMD` be defaulted in the
  definition file.
- `/usr/bin/python3` stays the 3.9 system interpreter the base image ships,
  untouched. `dnf` runs on it, so repointing it would break the package
  manager; and it is what a playbook's `command: python3 …` actually invokes,
  which makes it the **evaluator** interpreter and the reason for ADR 0007's
  3.9 floor. The evaluator is vendored to `/opt/nobytes-cca` and put on
  `PYTHONPATH`, so both interpreters can import it; the image build asserts
  both imports rather than hoping.

Build them:

```bash
make ee-context EE=ee-legacy   # render + verify the context, no runtime needed
make ee-build   EE=ee-legacy   # build the image
```

Only **collection** needs the legacy image. Evaluation always runs on current
Python, so both tiers produce identical fact bundles judged by identical code.

```bash
ansible-builder build \
  -f aap/execution-environment/ee-legacy/execution-environment.yml \
  -t ee-legacy:0.1.0
```

The base image is CentOS Stream 9 so this builds without a Red Hat
subscription. For AAP, change `images.base_image.name` to
`registry.redhat.io/ansible-automation-platform-25/ee-minimal-rhel9`. The
ansible-core pin is what matters, not the base.

In restricted environments, push both to a **private Automation Hub** and
reference them **by digest**.

## Split the inventory, not the job

A job template binds exactly one execution environment, so the estate is split
by tier in the **inventory**:

```
ee_current   ee_legacy
   └─ windows   └─ windows
   └─ linux     └─ linux
```

Tier comes from **CMDB / AD / vCenter / Intune OS data, never from gathered
facts** — the right image has to be chosen before anything can be gathered. Do
not key a `constructed` inventory on `ansible_distribution_version` for this;
that needs facts you cannot collect yet.

Add an invariant: every host is in exactly one of `ee_current` / `ee_legacy`. A
host in the wrong tier should fail loudly rather than produce subtly broken
facts.

## Read-only is enforced by the credential

Collect job templates are bound to credentials that **physically cannot write**:
a Windows domain account with remote-read rights, an unprivileged SSH account
with a narrow sudoers allowlist, a read-only vSphere role, a Graph app holding
only `*.Read.All`.

Role hygiene is the first line and is statically tested. Credential scoping is
the line that survives adversarial review, and it is the one to put in front of
an assessor.

**Remediation uses separate, write-capable credentials bound only to the
remediation template.** The two credential sets never appear on the same
template, and remediation is not part of any assessment workflow.

## The workflow

```
  Collect: Windows (current) ─┐
  Collect: Windows (legacy)  ─┤
  Collect: Linux   (current) ─┼─▶ Coverage gate ──▶ Evaluate ──▶ Publish
  Collect: Linux   (legacy)  ─┘   (converge: all)
```

Two details that matter:

- Collect nodes connect on **`always`**, not `success`. One platform failing
  must not abort the assessment — but it must show up in the coverage figures.
- The **coverage gate** converges on all upstream nodes and fails the workflow
  below the threshold. This is the structural defence against the default
  failure mode of compliance automation: unreachable hosts vanishing from the
  output while a partial-fleet pass renders as green. The denominator comes
  from the inventory, never from however many bundles arrived.

Overriding the gate is allowed — estates have genuine outages — but the
override and the real figures are recorded on the assessment result.

## Surveys

`cca_baseline`, `cca_system_id` (required — results that cannot be attributed to
an authorisation boundary are not evidence), `cca_min_coverage`,
`cca_allow_partial_coverage`, `cca_scope_limit`.

One trap is called out in the survey help text: **`cca_scope_limit` narrows what
is collected, not the population denominator.** If it narrowed both, a limited
run would silently report full coverage.

## Event-Driven Ansible

`aap/eda/rulebooks/` triggers **assessment**, never remediation. The event says
"something changed, go and measure"; deciding what to do about the result stays
a human call. Automatically reconfiguring production hosts on a compliance
signal is a real operational risk and is not this project's default posture.

## Configuration as code

`aap/controller/` holds data files for
[`infra.aap_configuration`](https://github.com/redhat-cop/infra.aap_configuration)
(AAP 2.5+, superseding `redhat_cop.controller_configuration`).

**Credentials are never defined in this repository** — only the credential
*types* and the names templates expect to be bound to.

## Verification status

| Path | Status |
|---|---|
| EE definitions accepted by `ansible-builder create`, `_build/` populated | **Verified** |
| EE images build; correct ansible-core; image carries the evaluator; evaluator runs **inside each image** | **CI only** (needs a container runtime) |
| Evaluator is valid Python 3.9 and imports only stdlib + PyYAML | **Tested locally**, and run on a real 3.9 interpreter in `ee-legacy` in CI |
| Playbooks pass `ansible-lint` production profile | **Verified** |
| Controller configuration applied to a real AAP instance | **Not verified** — no controller available here |

The last row is why `aap/controller/apply.yml` does not run the dispatch role as
a side effect of being imported. A config-as-code run that has never been tested
against a real controller should be executed deliberately.
