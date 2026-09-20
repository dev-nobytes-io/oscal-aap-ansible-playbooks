# Component definitions — the control-to-check binding

One OSCAL component-definition per platform family. This is where a control
stops being prose and becomes something executable.

Each declares `implemented-requirements` keyed by ISM control ID, naming the
collector that gathers evidence, the evaluator that judges it, and the
confidence that judgement carries.

The payoff is that **coverage becomes queryable data rather than a claim**.
"Which ML1 controls can we actually test on Windows Server 2019?" is answered
by querying these files, and the coverage ledger is generated from them — never
hand-maintained, so it cannot drift into flattery.

A component is not always a machine. Some are `service` components for systems
that *hold* evidence about a control rather than being constrained by it —
CyberArk for privileged access, Splunk for log retention.
