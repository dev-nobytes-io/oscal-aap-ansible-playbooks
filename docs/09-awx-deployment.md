# Deploying on AWX

Everything in [`08-aap-deployment.md`](08-aap-deployment.md) applies. This page
covers only the differences, because maintaining two parallel sets of
instructions is how one of them silently goes stale.

## What changes

| Concern | AAP | AWX |
|---|---|---|
| Config-as-code collection | `infra.aap_configuration` | `awx.awx` |
| EE base image | `registry.redhat.io/…/ee-minimal-rhel9` | `quay.io/centos/centos:stream9` (the shipped default) |
| Image registry | Private Automation Hub | Any OCI registry |
| Support | Red Hat | Community |

Nothing in this project requires a subscription. The execution environments
build from a CentOS Stream base by default precisely so the open-source path is
the one that works out of the box, rather than the one that is documented but
untested.

## What does not change

The parts that carry the compliance guarantees are identical:

- Two execution environments, selected by splitting the **inventory** by estate
  tier rather than branching inside a job.
- **Read-only enforced by the credential**, not by role hygiene alone.
- The **coverage gate** converging on all collect nodes, with the population
  denominator taken from inventory.
- Remediation in a separate workflow with separate, write-capable credentials.

## Applying configuration

`awx.awx` provides equivalents for every module the AAP path uses
(`awx.awx.job_template`, `awx.awx.workflow_job_template`,
`awx.awx.credential_type`, …). The data files in `aap/controller/` describe the
same objects; only the role or module wrapping them differs.

The `awx` CLI can export an existing configuration in a shape close to these
files, which is the easier direction when adopting this into an estate that
already has templates defined by hand.

## Verification status

Identical to the AAP page: definitions and playbooks are verified, images build
in CI, and **applying configuration to a real AWX instance is not verified
here** — no instance is available in this environment.
