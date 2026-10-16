"""Run one complete AegisForge attack-defense cycle from the terminal."""

from __future__ import annotations

import argparse

from .simulation import DEFAULT_SCENARIOS, print_simulation, run_attack_cycle


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a safe AegisForge security simulation")
    parser.add_argument("--target", default="AegisTarget", help="simulated target agent name")
    parser.add_argument(
        "--scenario",
        choices=tuple(DEFAULT_SCENARIOS),
        default="Mixed campaign",
        help="built-in attack scenario",
    )
    parser.add_argument("--rounds", type=int, default=3, help="number of attack-defense rounds")
    args = parser.parse_args()
    try:
        result = run_attack_cycle(
            target_agent=args.target,
            prompt=DEFAULT_SCENARIOS[args.scenario],
            rounds=args.rounds,
            verbose=True,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print_simulation(result)


if __name__ == "__main__":
    main()
