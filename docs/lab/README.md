# Lab validation runbook

**Read this first: what a lab run can and cannot establish is in
[`experiment-sheet.md`](experiment-sheet.md), and it is written before any run
rather than after one.**

Fourteen of the fifteen automated controls have never had their collector
executed against the platform it reads. [ADR 0017](../adr/0017-the-collector-output-contract.md)
established what that costs: the entire Windows collection path had never
populated a fact on a real host, and it surfaced as one confident false
`not-satisfied` and one false `satisfied` at **`direct`** confidence.

This runbook closes that gap for whatever the lab can actually reach.

## What crosses the boundary — and what does not

**The bundle never leaves the lab. The digest does.**

A fact bundle is evidence about a real estate: hostnames, SIDs, installed
software, registry contents. None of it is needed for the comparison this
harness makes, which is about key *paths* and value *types*.

`cca lab-digest` reduces a bundle to a **shape digest**: every key path, each
value's type, list cardinalities — and **no values at all**. Where a mapping's
*keys* are themselves collected content (`java_surface.javasoft` is keyed by
verbatim registry path; `policy.rows[].values` by Group Policy setting name,
including custom organisational ADMX) the digest emits a count plus a salted
hash per key, so a comparison still sees *that* a key differs without learning
what it was. `subject.asset_id` is dropped; `platform_family` and `estate_tier`
travel, because the comparison must be keyed on platform.

Credentials never reach the repository or anyone reviewing the digest.

## The read-only credential

This is the real control. The code is not.

Run the collectors under an account scoped per
[`docs/13-security-model.md`](../13-security-model.md). Two things are worth
stating plainly:

- **Running as Domain Admin proves the collectors *work*. It does not prove they
  work with the read-only credential the documentation specifies.** Those are
  different claims, and conflating them is how an assessment tool ends up
  needing privilege it told you it did not need.
- **Some reads genuinely require elevation.** `Get-WindowsOptionalFeature -Online`
  does, `Win32_DeviceGuard` needs an explicit WMI namespace ACE, and another
  user's profile hive is unreadable to a non-admin by design. Record which
  credential each run used — a floor met under Domain Admin and a floor met
  under a scoped account are not the same result.

## Running it

### Step 0 — prove the pipeline works before involving Windows

```bash
make assess-self
```

This runs the **real** `collect.yml` against the control node itself, evaluates it
and emits three schema-valid OSCAL documents. It exercises the install, the
evaluators, the emitters and the reporting — everything except the Windows
transport. **It works today**, so if it is green you have a known-good baseline
and any later failure is isolated to Windows.

### Step 1 — preflight

```bash
cp inventory/lab.yml.example inventory/lab.yml   # gitignored; edit for your lab

make lab-preflight LAB_SALT="$(vault-read cca/lab/salt)" \
  LAB_EXTRA='-e ansible_user=LAB\\svc-cca -e ansible_password=...'
```

Run this **before** `lab-validate`. It separates a control-node problem from an
inventory problem from a target problem, and every failure names its fix. Two of
the four things it catches were found by pointing this repository at a Windows
host and watching it fail on the control node rather than the target.

It also reports **which identity actually authenticated** — see the credential
note above. Record that with the run.

### Step 2 — collect and reconcile

```bash
make lab-validate LAB_SALT="$(vault-read cca/lab/salt)" \
  LAB_EXTRA='-e ansible_user=LAB\\svc-cca -e ansible_password=...'
```

That runs the **real** `playbooks/collect.yml` — not a parallel lab playbook.
A separate code path could diverge from the one production uses, which is this
repository's recurring defect in a new costume. Then:

```bash
make lab-digest LAB_SALT=…    # bundle -> out/lab/digest.json, no values
make lab-diff   LAB_SALT=…    # reconcile, and exit non-zero on a hard failure
```

## What comes back

Send **`out/lab/digest.json`**. Nothing else is needed, and nothing else should
travel.

The digest carries a `self_sha256` over its own content, so a hand-edited digest
is detectable — `lab-diff` refuses one outright. It also carries the bundle's
classification `marking`, the run id and the collection timestamp. **Review it
before it leaves**, and treat that review as the control: the guarantee here is
the declared keyspace split plus a human reading the file, not a proof.

## How to read the result

`lab-diff` reconciles three things, and two would not be enough — collector
reality against the fixtures is two artefacts an author wrote from one
assumption, which is exactly how the `display_name`/`name` defect passed 260
tests. The third leg is what the evaluators actually read, extracted from their
AST.

| Result | Means |
|---|---|
| **FAIL** — keys read but never emitted | An evaluator reads a key nothing produces, on a fact this run carried. It will read as absent on every host, forever, silently. This is the `display_name` signature. |
| **FAIL** — floors unmet | The run establishes **nothing** about those facts. Not that the estate lacks the thing — that nothing was learned. They must not be promoted. |
| **REVIEW** — read but never exercised | A key no bundle in scope populates. Often a platform this run did not touch; always a branch no real observation has hit. |
| **REVIEW** — lab found, fixtures do not model | Reality is ahead of the corpus. Usually means a fixture should gain a path. |
| **REVIEW** — fixtures model, lab did not produce | Either the host genuinely lacks it, or the fixture is a fiction. Worth deciding which. |

Only the two FAIL rows are failures. Everything else needs a person, and saying
so is deliberate: a guard that cried wolf on every difference would be switched
off within a week, and a guard that is switched off is worse than none.

## Troubleshooting

Every message below was **reproduced** by running this repository, not written
from memory. Match on the text you see.

| What you get | What it means | Fix |
|---|---|---|
| `"winrm or requests is not installed: No module named 'winrm'"` | `pywinrm` is missing from the control node. It was absent from `requirements.txt` until PR 23 while both EE images carried it, so AAP worked and local `ansible-playbook` could not reach Windows at all | `pip install -r requirements.txt` |
| `"WinRM Kerberos authentication requested but the python kerberos library is not installed"` | Kerberos needs `pywinrm[kerberos]` (a compiler and krb5 headers), krb5 client tools on `PATH`, `/etc/krb5.conf` and a current ticket. None is installed by `make bootstrap` | Use `ansible_winrm_transport: ntlm` for a first test, or install all four |
| `"ntlm: auth method ntlm requires a username"` | No credential was supplied | `-e ansible_user=DOMAIN\\account -e ansible_password=...` at run time. Never in inventory |
| `"ntlm: ('Connection aborted.', ConnectionResetError(104, ...))"` or a DNS resolution error | Nothing is listening, the name does not resolve, or a firewall is in the way. **No credential has been offered yet** — this is a network result, not an auth one | On the host: `Enable-PSRemoting -Force`, then `winrm enumerate winrm/config/listener` |
| `"fact_bundle_redaction_salt is unset or still the shipped default"` | The role refuses to start rather than hash identifiers under a known salt (ADR 0016) | `-e fact_bundle_redaction_salt=...` from a vault |
| An `SSLError` that does not mention certificates | A self-signed certificate on 5986 | `ansible_winrm_server_cert_validation: ignore`, or use NTLM on 5985 |

`make lab-preflight` produces a specific message for each of the first five
before anything is collected, which is the reason it exists.

## What to expect on a domain controller

**Roughly three of five collectors return data and two return nothing**, and
several controls come back `unassessed`. That is the correct result, not a
fault — Office is not installed on a DC, and browser policy keys do not exist
until an Edge GPO is applied. `make lab-diff` reports those as **unmet floors**
declared in advance in [`floors.yml`](floors.yml), precisely so "nothing was
learned" cannot be mistaken for "the estate is compliant".

[`experiment-sheet.md`](experiment-sheet.md) records per collector, before any
run, what is and is not promotable.

**The honest residual risk:** no Windows collector has ever executed against
Windows. The output-contract fix in
[ADR 0017](../adr/0017-the-collector-output-contract.md) is reasoned from
`win_powershell.ps1:528-531` and unit-tested on the wire form, never run. If
something breaks after preflight passes, the likeliest cause is a
`ConvertTo-Json -Depth` value (the collectors use 3–8) being too shallow for
real estate data. The facts will carry a `collection_error` in `meta` rather
than silently reading as empty.
