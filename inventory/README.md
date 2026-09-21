# Inventory examples

Example inventories only. Real estate inventories do not belong in this
repository — they are sensitive, and in AAP they come from an inventory source
or dynamic plugin.

Two group variables drive behaviour:

- **`ism_baseline`** — which OSCAL profile applies (e.g. `e8-ml1`, `protected`)
- **`estate_tier`** — `current` or `legacy`, selecting the execution environment

`estate_tier` exists because ansible-core dropped Windows Server 2012/2012 R2
after 2.16, dropped managed-node Python 2.7/3.6 in 2.17, and does not support
RHEL 8 as a managed node in 2.20. Estates running those still need assessing,
so older targets are collected with a pinned legacy execution environment.

## Subjects that are not hosts

An Entra ID tenant is a **subject**, not a machine. It has no `estate_tier`,
because no execution environment manages it — the control node calls Microsoft
Graph directly.

`playbooks/collect.yml` therefore has two plays. The host play targets
`all:!entra_tenants`; the tenant play targets `entra_tenants` with
`connection: local`. Running the Windows or Linux collectors against a tenant
would derive a platform family from the *control node's* facts and file the
answer under the tenant's name.

Both example inventories declare the group, `self.yml` with no members. Ansible
warns on a host pattern that matches no group at all, so declaring it keeps a
tenant-less run quiet — and leaves the warning meaningful in an estate that
expected a tenant and has none.

Tenant credentials (`collect_entra_id_tenant_id`, `_client_id`,
`_client_secret`) belong in a vault or an AAP credential. The role refuses to
run without all three rather than collecting nothing: an empty fact set
evaluates to `unassessed` for every control, which reads as though the tenant
had been assessed and found undetermined.

