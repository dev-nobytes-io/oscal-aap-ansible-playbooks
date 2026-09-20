# Playbooks

Thin entrypoints. Logic belongs in collection roles and plugins, not here —
playbooks exist so AAP job templates and `ansible-playbook` have something
stable to point at.

| Playbook | Does | Mutates? |
|---|---|---|
| `collect.yml` | Gathers raw facts from targets | **No — never** |
| `evaluate.yml` | Applies control assertions to collected facts | No |
| `assess.yml` | collect + evaluate + emit, end to end | No |
| `report.yml` | Renders reports from assessment results | No |
| `remediate.yml` | Applies fixes — opt-in, per-control, explicit | **Yes** |

The read-only guarantee for assessment is structural, not a convention:
collection playbooks and their roles have no mutating module surface at all, so
"assessment never changes a host" is enforceable by review and by lint rather
than promised in a comment.

`remediate.yml` is deliberately separate, never invoked by assessment, and
never runs without explicit per-control opt-in.
