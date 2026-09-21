# -*- coding: utf-8 -*-
"""Apply the deployment's redaction policy to a fact bundle.

This exists because the policy was declared and never applied. Until PR 16,
`fact_bundle_redaction_keys` was referenced nowhere outside `defaults/main.yml`,
no hashing existed anywhere in the collection, and `finalise.yml` wrote
`facts: "{{ fact_bundle_facts }}"` verbatim from a task named "Redact
identifiers and write the fact bundle" -- while stamping `redaction_policy`
into the bundle. Every bundle asserted a protection it did not have.

Redaction runs HERE, between collection and persistence, because you cannot
retroactively un-collect. See ADR 0008 for why the policy is per-deployment
rather than fixed by this project.

Scope, stated because the boundary is deliberate: this redacts the bundle's
`facts` only. `subject.asset_id` is NOT redacted -- it is the correlation key
that gives a POA&M item continuity across runs, and hashing it here would break
that while doing nothing for privacy, since the inventory it came from holds
the same value in clear. A deployment that needs the asset id pseudonymous sets
`cca_asset_id` to an already-pseudonymous value in inventory.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib

from ansible.errors import AnsibleFilterError

DOCUMENTATION = r"""
name: redact_facts
short_description: Apply a redaction policy to collected facts
description:
  - Walks a fact mapping and applies a per-key action to identifier values.
  - Runs on the controller between collection and persistence.
options:
  _input:
    description: The accumulated facts mapping.
    type: dict
    required: true
  keys:
    description: Mapping of key name (case-insensitive) to action.
    type: dict
    required: true
  default:
    description: Action for keys not named in C(keys).
    type: str
    default: retain
  salt:
    description: Salt for hashed identifiers. Required when any action is C(hash).
    type: str
    default: ""
"""

#: The shipped placeholder. Hashing with it would be trivially reversible and
#: correlatable across organisations, so it is refused rather than warned about.
_UNSET_SALT = "CHANGE-ME-PER-DEPLOYMENT"

ACTIONS = ("retain", "hash", "truncate", "drop")

#: Truncation keeps the part that carries no individual identity and masks the
#: part that does. Only two shapes appear in the shipped policy, and guessing
#: at a third would mangle data rather than protect it, so anything else keeps
#: a two-character prefix and says how much it dropped.
_MASK = "***"


def _hash(value, salt):
    digest = hashlib.sha256((salt + str(value)).encode("utf-8")).hexdigest()
    # 128 bits is far beyond collision risk for an estate-sized population, and
    # a full 64-character digest makes a bundle unreadable to a human auditor.
    return "sha256:" + digest[:32]


def _truncate(value):
    text = str(value)
    if "@" in text:
        # UPN or email: the domain is organisational, the local part is the person.
        local, _, domain = text.partition("@")
        return "{0}@{1}".format(_MASK, domain) if domain else _MASK
    if text.upper().startswith("S-1-") and text.count("-") >= 3:
        # SID. docs/13-security-model.md defines truncation here as removing
        # the RID, and the RID is indeed the per-person part: within a domain
        # it is the account. So it goes.
        #
        # With one carve-out. RIDs below 1000 are well-known and identical on
        # every Windows domain on earth -- 500 is the built-in Administrator,
        # 512 Domain Admins, 513 Domain Users. They name a ROLE, not a person,
        # and dropping them would make a truncated bundle unable to answer the
        # privileged-access controls it was collected for while protecting
        # nobody. Those are kept; anything >= 1000 is masked.
        parts = text.split("-")
        rid = parts[-1]
        if rid.isdigit() and int(rid) < 1000:
            return text
        return "-".join(parts[:-1] + [_MASK])
    if len(text) <= 2:
        return _MASK
    return "{0}{1}({2} chars)".format(text[:2], _MASK, len(text))


def _apply(action, value, salt):
    if action == "hash":
        return _hash(value, salt)
    if action == "truncate":
        return _truncate(value)
    return value


def redact_facts(facts, keys=None, default="retain", salt=""):
    """Return a copy of `facts` with the policy applied.

    Fails closed rather than degrading: an unknown action, or hashing without a
    salt, raises. A redaction layer that silently did nothing is the defect this
    replaces, so it must not be possible for it to silently do nothing again.
    """
    if facts is None:
        return {}
    if not isinstance(facts, dict):
        raise AnsibleFilterError("redact_facts expects a mapping of fact key to record")

    policy = {str(k).lower(): str(v) for k, v in (keys or {}).items()}
    default = str(default)

    for action in list(policy.values()) + [default]:
        if action not in ACTIONS:
            raise AnsibleFilterError(
                "unknown redaction action {0!r}; expected one of {1}".format(
                    action, ", ".join(ACTIONS)
                )
            )

    if "hash" in list(policy.values()) + [default]:
        if not salt or salt == _UNSET_SALT:
            raise AnsibleFilterError(
                "redaction policy asks for hashing but fact_bundle_redaction_salt "
                "is unset or still the shipped default. Hashed identifiers would "
                "be trivially reversible and correlatable across organisations. "
                "Set it from a vault before collecting anything."
            )

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for key, value in node.items():
                action = policy.get(str(key).lower(), default)
                if action == "drop":
                    continue
                if isinstance(value, (dict, list)):
                    # A container never carries an identifier itself; its
                    # leaves might. Recurse rather than hashing a whole subtree
                    # into one opaque string, which would destroy the evidence.
                    out[key] = walk(value)
                else:
                    out[key] = _apply(action, value, salt)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(facts)


class FilterModule(object):
    def filters(self):
        return {"redact_facts": redact_facts}
