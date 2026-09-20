# Ansible collections

`ansible_collections/nobytes/compliance/` is this project's own collection —
collectors, evaluator plugins, filters and reporting.

Third-party collections are installed here by `make deps` and are **not**
committed; `.gitignore` excludes everything under `ansible_collections/` except
our own namespace.

The layout lets a checkout of this repository be used directly as an AAP or AWX
project, with `collections/` picked up automatically.
