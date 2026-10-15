"""Run a safe, deterministic demonstration of all four agents."""

from __future__ import annotations

import json

from .domain import Scenario, as_public_dict
from .initializer import initialize


def main() -> None:
    app = initialize(seed=2026)
    result = app.graph.invoke(
        {
            "scenario": Scenario(
                scenario_id="demo-001",
                description=(
                    "Simulate a prompt injection that requests a malicious tool call."
                ),
                seed=2026,
            )
        },
        context=app.context,
    )
    print(json.dumps(as_public_dict(result["report"]), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
