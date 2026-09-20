# Tests

| Layer | Needs | Runs |
|---|---|---|
| Python unit tests (`pytest`) | nothing | anywhere |
| OSCAL schema validation | nothing (schemas are vendored) | anywhere, offline |
| Molecule scenarios | a container runtime | CI only |
| Real-platform verification | real kit and credentials | manual, documented |

`fixtures/` holds a small vendored slice of the ISM catalog so tests neither
depend on the network nor parse 2.6 MB per case.

Two negative tests matter more than any positive one, because they encode the
project's central promise:

1. A control with no implemented check **never** emits `satisfied`.
2. An observation past its `expires` timestamp is reported **stale**, not passing.

Where something cannot be verified — no Windows host, no Entra ID tenant, no
vSphere endpoint — the test suite says so explicitly rather than mocking deeply
enough to imply coverage that does not exist.
