# Controller configuration-as-code

Declarative definitions for `infra.aap_configuration` (AAP 2.5+; supersedes
`redhat_cop.controller_configuration`), with `awx.awx` equivalents for AWX.

Covers organisations, projects, inventories, credential types, job templates,
the collect-evaluate-report workflow, surveys for baseline and scope selection,
schedules, and RBAC.

Credentials are **never** stored here — only the credential *types* and the
names templates expect to be bound to.
