from __future__ import annotations

import pytest

from aegisforge.simulation import DEFAULT_SCENARIOS, run_attack_cycle


def test_simulation_runs_red_blue_policy_audit_loop() -> None:
    result = run_attack_cycle(
        target_agent="DemoAgent",
        prompt=DEFAULT_SCENARIOS["Mixed campaign"],
        rounds=3,
        seed=11,
    )

    assert len(result.attacks) == 3
    assert len(result.detections) == 3
    assert all(d.score >= 70 and d.action == "blocked" for d in result.detections)
    assert len(result.policies) == 3
    assert len(result.changes) == 3
    assert result.events[-1].event_type == "run_completed"


def test_simulation_is_deterministic_and_verbose_safe(capsys) -> None:
    first = run_attack_cycle(
        prompt=DEFAULT_SCENARIOS["Tool misuse"], rounds=2, seed=5, verbose=True
    )
    output = capsys.readouterr().out
    second = run_attack_cycle(prompt=DEFAULT_SCENARIOS["Tool misuse"], rounds=2, seed=5)

    assert "[Round 1] RED" in output
    assert first == second


@pytest.mark.parametrize(
    "kwargs",
    [
        {"target_agent": "", "prompt": "valid"},
        {"target_agent": "target", "prompt": ""},
        {"target_agent": "target", "prompt": "valid", "rounds": 0},
        {"target_agent": "target", "prompt": "valid", "rounds": 11},
    ],
)
def test_simulation_validates_demo_inputs(kwargs) -> None:
    with pytest.raises(ValueError):
        run_attack_cycle(**kwargs)
