# ADR 0004: Ship two execution environments to reach legacy estates

## Context

The target estates are large Australian government environments: on-prem
primary, hybrid, and genuinely running Windows Server 2012 and Windows 10 today.

Modern `ansible-core` cannot reach them. Verified against the support matrix:

- Windows Server 2012 / 2012 R2 / 8.1 support was **dropped after 2.16**; 2.17+
  requires Server 2016 or Windows 10 and newer.
- **2.17 dropped managed-node Python 2.7 and 3.6**, requiring 3.7+.
- **RHEL 8 is not a supported managed OS on 2.20** — RHEL 8 targets require the
  2.16 default.

Refusing to assess these hosts does not make them secure. It makes them
unmeasured, which is worse: they are the hosts most likely to be failing.

## Decision

Ship two execution environments, selected per inventory group by an
`estate_tier` fact:

| Image | ansible-core | Reaches |
|---|---|---|
| `ee-current` | 2.19.x | Server 2016+/Win 11, RHEL 9/10, Ubuntu 22.04/24.04 |
| `ee-legacy` | 2.16.x | Server 2012/2012 R2, RHEL 7/8, Python 2.7/3.6 |

A job template binds exactly one execution environment, so the **inventory** is
split by tier, not the job. Tier is derived from CMDB/AD/vCenter OS data, not
from gathered facts — the image must be chosen before anything can be gathered.

## Status

Accepted.

## Consequences

Legacy hosts are assessable rather than invisible. Because only *collection*
needs the old image, both tiers produce identical fact bundles judged by
identical code — a Server 2012 box and a RHEL 10 box are evaluated the same way.

Cost: two images to build, patch and test, and a CI matrix that runs the
evaluator suite in both. An inventory-tiering rule that must stay correct; a host
in the wrong tier fails loudly by design rather than producing subtly broken
facts.

Worth noting: an estate running these systems fails `ism-1501`, `ism-1704` and
`ism-1905` — all Essential Eight ML1 controls — by definition. Detecting and
quantifying that is a feature of this project, not an awkwardness.
