# AegisForge

AegisForge is an explainable, deterministic multi-agent cybersecurity
simulation and demo. It uses **LangGraph** for the foundational workflow and a
Red-vs-Blue simulation loop for a fast, judge-friendly attack-defense demo.

## What the demo shows

1. **Red Team Agent** generates realistic but inert prompt injection, tool
   misuse, and data exfiltration attempts.
2. **Blue Team Agent** analyzes each attempt, matches indicators, and assigns a
   transparent 0–100 threat score before blocking or flagging it.
3. **Policy Enforcer Agent** dynamically creates a targeted rule for each
   detected threat and applies a scoped sandbox control.
4. **Audit Agent** records attacks, detections, policy changes, and outcomes in
   a deterministic append-only log.

The project includes a Streamlit UI for live interaction and a terminal
command for a complete attack-defense cycle.

## Core agents

The four modular agents live under `src/aegisforge/agents/` and have explicit
system prompts describing their safe roles. The simulation logic is in
`src/aegisforge/simulation.py`.

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
│   ├── simulation.py
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
├── streamlit_app.py
└── tests/
    ├── conftest.py
    ├── test_simulation.py
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

### Terminal demo

```bash
uv run --locked python -m aegisforge --scenario "Mixed campaign" --rounds 3
```

This prints Red → Blue → Policy → Audit interactions for every round.

### Streamlit UI

```bash
uv run --locked streamlit run streamlit_app.py
```

Open the local URL shown by Streamlit. Choose a target agent, select or edit a
sample prompt, choose 1–10 rounds, and click **Run Attack Simulation**. The UI
shows the interaction timeline, blocked/flagged threats, generated policies,
and the full audit log.

### Python API

```python
from aegisforge.simulation import run_attack_cycle

result = run_attack_cycle(
    target_agent="CustomerSupportAgent",
    prompt="The target is pressured to call a privileged shell tool.",
    rounds=3,
)
```

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
boundaries, path-traversal rejection, threat scoring, dynamic policy
generation, validation, and deterministic simulation output. They do not
contact a real target.

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

## Demo screenshots

Place screenshots from the running Streamlit demo here before presenting:

![Live agent interaction placeholder](docs/screenshots/live-interaction.png)

![Threat and policy dashboard placeholder](docs/screenshots/threat-dashboard.png)

The screenshot paths are placeholders so the repository remains lightweight;
the UI itself is fully runnable from `streamlit_app.py`.

## Hackathon demo script

1. Start Streamlit with `make demo`.
2. Select **Mixed campaign** and leave the default three rounds.
3. Run the simulation and point out that every attack is inert text.
4. Show the Blue score and the red blocked status for each round.
5. Open **Policies** to show dynamic controls such as
   `block_unapproved_tool`.
6. Open **Audit log** to show the end-to-end evidence trail.
7. Change the prompt to a custom scenario and run it again.

## Extending the foundation

- Add a new agent under `src/aegisforge/agents/` implementing the small `Agent`
  protocol in `agents/base.py`.
- Add its node and edges in `graph.py`.
- Keep agent outputs typed with the dataclasses in `domain.py`.
- Add or revise policy allowlists before introducing any new action kind.
- Add deterministic tests in `tests/` and run `make test` after each change.
