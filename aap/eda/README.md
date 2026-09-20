# Event-Driven Ansible rulebooks

Rulebooks that trigger assessment in response to events: a change detected by
an audit tool, a new host registered, a patch window closing, a fresh ISM
release published.

These trigger **assessment**, never remediation. The event says "something
changed, go and measure"; deciding what to do about the result stays a human
call by default.
