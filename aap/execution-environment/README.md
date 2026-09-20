# Execution environments

Two images, because one cannot reach the whole estate:

| Image | ansible-core | Reaches |
|---|---|---|
| `ee-current` | 2.19.x | Windows Server 2016+/Win 11, RHEL 9/10, Ubuntu 22.04/24.04 |
| `ee-legacy` | 2.16.x | Windows Server 2012/2012 R2, RHEL 7/8, Python 2.7/3.6 targets |

This is a deliberate capability, not technical debt. ansible-core removed
Windows Server 2012/2012 R2 support after 2.16, removed managed-node Python
2.7/3.6 in 2.17, and does not support RHEL 8 as a managed node in 2.20 — while
large government estates still run all of them. Refusing to assess a legacy host
does not make it secure; it makes it unmeasured.

Only *collection* needs the legacy image. Evaluation runs centrally on current
Python no matter how old the target is, so both tiers produce identical fact
bundles and are judged by identical code.

Built with `ansible-builder`; expected to be served from a private Automation
Hub in air-gapped environments.
