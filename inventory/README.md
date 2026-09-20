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
