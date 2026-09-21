---
title: "Authentication strengths"
weight: 40
type: docs
description: "This page describes the configuration of authentication strengths within Microsoft Entra ID associated with systems built according to the guidance provided by ASD's Blueprint for Secure Cloud."
---

{{% alert title="Instruction" color="dark" %}}

The below tables outline the _as built_ configuration for ASD's _Blueprint for Secure Cloud_ (the Blueprint) for the Microsoft Entra admin portal at the following URL:

<https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/AuthStrengths/fromNav>

The settings described on these pages provide a baseline implementation for a system configured using the Blueprint. Any implementation implied by these pages should not be considered as prescriptive as to how an organisation must scope, build, document, or assess a system.

Implementation of the guidance provided by the Blueprint will differ depending on an organisation’s operating context and organisational culture. Organisations should implement the Blueprint in alignment with their existing change management, business processes and frameworks.

Placeholders such as `<ORGANISATION.GOV.AU>`, `<BLUEPRINT.GOV.AU>` and `<TENANT-NAME>` should be replaced with the relevant details as required.

{{% /alert %}}

| Item                               | Value                                                                                            |
| ---------------------------------- | ------------------------------------------------------------------------------------------------ |
| **Phishing-resistant MFA and TAP** |                                                                                                  |
| Name                               | Phishing-resistant MFA and TAP                                                                   |
| Phishing-resistant MFA             | Windows Hello For Business<br>Passkeys (FIDO2)<br>Certificate-based Authentication (Multifactor) |
| Multifactor authentication         | Temporary Access Pass (One-time use)<br>Temporary Access Pass (Multi-use)                        |

New authentication strengths can take some time to appear for use in Conditional Access policy drop-downs.

### Related information

#### Security and governance

- [Multi-factor authentication](/security-and-governance/essential-eight/multi-factor-authentication)

#### Design

- [Conditional access](/design/platform/identity/conditional-access)
- [Purview labels](/design/shared-services/purview/labelling-and-classification)

#### Configuration

- [Entra ID Protection](/configuration/entra-id/protection)
- [Endpoint security policies](/configuration/defender/endpoints/configuration-management/endpoint-security-policies)

#### References

- [Conditional Access: Target resources](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#authentication-context)
