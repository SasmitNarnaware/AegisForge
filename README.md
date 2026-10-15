# AegisForge

AegisForge is a deterministic foundation for a multi-agent cybersecurity
simulation. It uses **LangGraph** to coordinate four modular agents:

1. **Red Team Agent** — identifies simulated prompt-injection, malicious
   tool-call, and data-exfiltration indicators. It generates typed defensive
   proposals but never executes an attack.
2. **Policy Enforcer Agent** — creates the initial security policies and
   approves only known, sandbox-scoped action types.
3. **Blue Team Agent** — applies approved defensive actions after re-checking
   approval at the sandbox boundary.
4. **Audit Agent** — records decisions and produces a stable report with
   SHA-256 event digests.

This stage is intentionally provider-free: no API key, model download, network
service, shell, subprocess, or host filesystem is required to run the demo or
tests.

## Project structure

```text
AegisForge/
├── .dockerignore
├── .gitignore
├── .python-version
├── Dockerfile
├── Makefile
├── README.md
├── pyproject.toml
├── uv.lock
├── src/aegisforge/
│   ├── __init__.py
│   ├── __main__.py
│   ├── context.py
│   ├── domain.py
│   ├── graph.py
│   ├── initializer.py
│   ├── state.py
│   ├── agents/
│   │   ├── audit.py
│   │   ├── base.py
│   │   ├── blue.py
│   │   ├── policy.py
│   │   └── red.py
│   ├── audit/
│   │   ├── __init__.py
│   │   └── recorder.py
│   └── sandbox/
│       ├── __init__.py
│       ├── memory.py
│       └── protocol.py
└── tests/
    ├── conftest.py
    └── test_workflow.py
```

## Setup

The runtime is pinned to Python **3.11.2** and dependencies are locked in
`uv.lock`. Install [uv](https://docs.astral.sh/uv/) 0.13.0 or a compatible
release, then run:

```bash
uv sync --locked
```

No global Python packages are needed; uv creates `.venv` in the project.

## Run the demo

```bash
uv run --locked python -m aegisforge
```

The command prints a JSON audit report for a simulated prompt injection and
malicious tool-call scenario.

## Test and lint

The single offline test command is:

```bash
make test
```

For style checks:

```bash
make lint
```

Tests exercise the approved graph path, deterministic output, policy/sandbox
boundaries, and path-traversal rejection. They do not contact a real target.

## Docker

With Docker installed locally:

```bash
docker build -t aegisforge .
docker run --rm aegisforge
```

The image uses the pinned Python 3.11.2 slim base and installs from
`uv.lock`. This environment does not require Docker for local tests.

## Communication and safety boundary

The graph is the communication layer. Each node returns a partial `RunState`
update, and LangGraph passes it to the next node:

```text
START → Red Team → Policy Enforcer ── approved → Blue Team → Audit → END
                              └────── denied ───────────────→ Audit → END
```

`RuntimeContext` supplies the sandbox and audit recorder without placing
mutable dependencies in graph state. The `MemorySandbox` stores only virtual
files and controls in Python dictionaries. It accepts a small typed action
allowlist and explicitly rejects absolute paths, traversal, NUL bytes, oversized
content, unknown action kinds, and unapproved actions. It has no API for
subprocesses, sockets, shell commands, or host-file access.

This is a **simulation foundation**, not authorization to test real systems.
Future integrations should be added behind separately reviewed, explicit
adapters and policy gates.

## Extending the foundation

- Add a new agent under `src/aegisforge/agents/` implementing the small `Agent`
  protocol in `agents/base.py`.
- Add its node and edges in `graph.py`.
- Keep agent outputs typed with the dataclasses in `domain.py`.
- Add or revise policy allowlists before introducing any new action kind.
- Add deterministic tests in `tests/` and run `make test` after each change.
