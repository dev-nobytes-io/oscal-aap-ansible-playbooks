# Ansible Automation Platform / AWX

| Directory | Contents |
|---|---|
| `execution-environment/` | `ee-current` and `ee-legacy` definitions for `ansible-builder` |
| `controller/` | Configuration-as-code: projects, job templates, workflows, schedules, RBAC |
| `eda/` | Event-Driven Ansible rulebooks |

Targets **AAP 2.6** (current), with AWX parity maintained throughout — nothing
here should require a subscription to run.

EDA rulebooks trigger *assessment*, not remediation. Automatically changing
production hosts in response to a compliance signal is a real operational risk
and is not the default posture of this project.
