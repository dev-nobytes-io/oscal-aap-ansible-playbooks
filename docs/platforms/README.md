# Platform pages

One page per target family, each answering the same questions:

- What can genuinely be evidenced here, and what cannot
- Transport and the **least privilege** actually required (never "just use admin")
- Which ISM controls this platform can evidence, and at what confidence
- Legacy support boundaries and which execution environment is required
- How to verify the collector works, and what cannot be verified without real kit

Delivered: [`windows.md`](windows.md), [`linux.md`](linux.md),
[`entra-id.md`](entra-id.md), [`active-directory.md`](active-directory.md).

Planned: `adcs.md`, `adfs.md`, `keycloak.md`,
`exchange.md`, `cyberark.md`, `netapp.md`, `splunk.md`, `change-auditor.md`,
`vmware.md`, `proxmox.md`, `xcp-ng.md`, `containers.md`, `kubernetes.md`,
`network.md`, `cloud.md`.

Each page ships with the pull request that delivers its collector — or, in
[`active-directory.md`](active-directory.md)'s case, with the pull request that
explains why five of its six controls deliberately have none.
