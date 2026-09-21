---
title: "ASD Edge hardening guidelines"
weight: 30
description: "This section describes the configuration of device configuration profiles within Microsoft Intune associated with systems built according to the guidance provided by ASD's Blueprint for Secure Cloud."
---

{{% alert title="Instruction" color="dark" %}}

The below tables outline the _as built_ configuration for ASD's _Blueprint for Secure Cloud_ (the Blueprint) for the Microsoft Intune portal at the following URL:

<https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/configuration>

The settings described on these pages provide a baseline implementation for a system configured using the Blueprint. Any implementation implied by these pages should not be considered as prescriptive as to how an organisation must scope, build, document, or assess a system.

Implementation of the guidance provided by the Blueprint will differ depending on an organisation’s operating context and organisational culture. Organisations should implement the Blueprint in alignment with their existing change management, business processes and frameworks.

Placeholders such as `<ORGANISATION.GOV.AU>`, `<BLUEPRINT.GOV.AU>` and `<TENANT-NAME>` should be replaced with the relevant details as required.

{{% /alert %}}

{{% alert title="Policy import" color="info" %}}

This configuration policy can be imported.

Download the {{% download file="/content/files/intune-config-policies/EdgeHardening.txt" %}} Edge Hardening Guidelines {{% /download %}} _.txt_ file and change the extension to _.json_, then select **Create > Import Policy**.

{{% /alert %}}

### Basics

| Item        |                         Value |
| ----------- | ----------------------------: |
| Name        | ASD Edge hardening guidelines |
| Description |                               |
| Platform    |          Windows 10 and later |

### Assignments

#### Included groups

| Item   |       Value |
| ------ | ----------: |
| Groups | All devices |

#### Excluded groups

| Item   |              Value |
| ------ | -----------------: |
| Groups | No groups selected |

### Scope tags

| Item       |   Value |
| ---------- | ------: |
| Scope tags | Default |

### Configuration settings

#### Defender

| Item                      |                Value |
| ------------------------- | -------------------: |
| Enable Network Protection | Enabled (block mode) |

#### Microsoft Edge

| Item                                                                         |                                 Value |
| ---------------------------------------------------------------------------- | ------------------------------------: |
| Ads setting for sites with intrusive ads                                     |                               Enabled |
| - Ads setting for sites with intrusive ads (Device)                          | Block ads on sites with intrusive ads |
| Allow download restrictions                                                  |                               Enabled |
| - Download restrictions (Device)                                             | Block potentially dangerous downloads |
| Configure Do Not Track                                                       |                               Enabled |
| Control the mode of DNS-over-HTTPS                                           |                               Enabled |
| - Control the mode of DNS-over-HTTPS (Device)                                |                Disable DNS-over-HTTPS |
| Control where developer tools can be used                                    |                               Enabled |
| - Control where developer tools can be used (Device)                         | Don't allow using the developer tools |
| DNS interception checks enabled                                              |                              Disabled |
| **Content settings**                                                         |                                       |
| Default pop-up window setting                                                |                               Enabled |
| - Default pop-up window setting (Device)                                     |                               Enabled |
| **Password manager and protection**                                          |                                       |
| Enable saving passwords to the password manager                              |                              Disabled |
| **SmartScreen settings**                                                     |                                       |
| Configure Microsoft Defender SmartScreen                                     |                               Enabled |
| Prevent bypassing Microsoft Defender SmartScreen prompts for sites           |                               Enabled |
| Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads |                               Enabled |

### Related information

#### Security and governance

- [User application hardening](/security-and-governance/system-security-plan/system-hardening-user-apps)
- [Essential Eight - Application control](/security-and-governance/essential-eight/application-control)
- [Enterprise mobility](/security-and-governance/system-security-plan/enterprise-mobility)
- [Essential Eight - Restrict Microsoft Office macros](/security-and-governance/essential-eight/restrict-microsoft-office-macros)
- [Essential Eight - Patch applications](/security-and-governance/essential-eight/patch-applications)
- [Essential Eight - Patch operating systems](/security-and-governance/essential-eight/patch-os)
- [Essential Eight - Regular backups](/security-and-governance/essential-eight/regular-backups)
- [System management](/security-and-governance/system-security-plan/system-management)
- [System monitoring](/security-and-governance/system-security-plan/system-monitoring)

#### Design

- [Microsoft Edge hardening](/design/endpoints/windows/security/edge-hardening)

#### Configuration

- [Security Baseline for Microsoft Edge](/configuration/intune/endpoint-security/security-baselines/security-baseline-for-microsoft-edge)
- [Microsoft Intune - profile configurations](/configuration/intune/devices/configuration-policies)
- [Endpoint security policies](/configuration/defender/endpoints/configuration-management/endpoint-security-policies)
- [Permissions](/configuration/defender/system/settings/endpoints/permissions)
- [Rules](/configuration/defender/system/settings/endpoints/rules)

#### References

- None identified
