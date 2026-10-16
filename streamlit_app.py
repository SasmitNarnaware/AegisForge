"""AegisForge's interactive hackathon demo.

Run with: ``uv run --locked streamlit run streamlit_app.py``
"""

from __future__ import annotations

import streamlit as st

from aegisforge.simulation import DEFAULT_SCENARIOS, run_attack_cycle

st.set_page_config(
    page_title="AegisForge | Agentic Cyber Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def badge(label: str, value: str, color: str) -> None:
    st.markdown(
        f"<div style='padding:1rem;border-radius:.7rem;background:{color};'>"
        f"<small>{label}</small><h2 style='margin:.15rem 0'>{value}</h2></div>",
        unsafe_allow_html=True,
    )


def main() -> None:
    st.title("🛡️ AegisForge")
    st.subheader("Multi-agent cyber defense in a safe, explainable simulation")
    st.caption(
        "Red Team generates inert attack payloads → Blue Team scores threats → "
        "Policy Enforcer creates controls → Audit Agent records every decision."
    )

    with st.sidebar:
        st.header("Simulation controls")
        target = st.text_input("Target agent", value="AegisTarget")
        scenario_name = st.selectbox("Attack scenario", tuple(DEFAULT_SCENARIOS))
        prompt = st.text_area(
            "Scenario prompt",
            value=DEFAULT_SCENARIOS[scenario_name],
            height=130,
            help="This is treated as untrusted simulation input; no payload is executed.",
        )
        rounds = st.slider("Attack-defense rounds", min_value=1, max_value=10, value=3)
        run = st.button("🚀 Run Attack Simulation", type="primary", use_container_width=True)
        st.divider()
        st.markdown("**Safety boundary**")
        st.caption(
            "No network, shell, subprocess, or host-file access. All actions stay in memory."
        )

    if run:
        try:
            with st.spinner("Agents are negotiating the trust boundary…"):
                st.session_state["result"] = run_attack_cycle(
                    target_agent=target,
                    prompt=prompt,
                    rounds=rounds,
                )
        except (ValueError, RuntimeError) as exc:
            st.error(f"Simulation could not start: {exc}")
            st.stop()

    result = st.session_state.get("result")
    if result is None:
        st.info("Choose a target and scenario, then run the simulation to see the agents interact.")
        st.markdown("### Demo flow")
        st.markdown(
            "1. **Red Team** creates a realistic but inert attack attempt.\n"
            "2. **Blue Team** extracts indicators and assigns a 0–100 threat score.\n"
            "3. **Policy Enforcer** creates a targeted rule and enforcement control.\n"
            "4. **Audit Agent** records the full evidence trail for judging and review."
        )
        return

    blocked = sum(d.action == "blocked" for d in result.detections)
    flagged = sum(d.action == "flagged" for d in result.detections)
    avg_score = round(sum(d.score for d in result.detections) / len(result.detections))
    st.success(f"Simulation complete: {blocked} attack(s) blocked, {flagged} flagged.")
    metrics = st.columns(4)
    with metrics[0]:
        badge("THREATS DETECTED", str(len(result.detections)), "#fff3cd")
    with metrics[1]:
        badge("ATTACKS BLOCKED", str(blocked), "#d1e7dd")
    with metrics[2]:
        badge("AVG THREAT SCORE", f"{avg_score}/100", "#f8d7da")
    with metrics[3]:
        badge("POLICIES GENERATED", str(len(result.policies)), "#cfe2ff")

    tabs = st.tabs(["⚡ Live interaction", "🚨 Threats", "📜 Policies", "🧾 Audit log"])
    with tabs[0]:
        st.markdown(f"#### Target: `{result.target_agent}` · {result.rounds} rounds")
        for attack, detection, policy in zip(
            result.attacks, result.detections, result.policies, strict=True
        ):
            with st.container(border=True):
                st.markdown(f"**Round {attack.round_number}** · `{attack.attack_type}`")
                st.markdown(f"🔴 **RED:** {attack.payload}")
                status = "🟢 BLOCKED" if detection.action == "blocked" else "🟡 FLAGGED"
                st.markdown(
                    f"🔵 **BLUE:** {status} · `{detection.score}/100` · "
                    f"{detection.rationale}"
                )
                st.markdown(f"🟣 **POLICY:** `{policy.enforcement}` — {policy.statement}")
    with tabs[1]:
        for detection in result.detections:
            icon = "🔴" if detection.action == "blocked" else "🟡"
            st.markdown(
                f"{icon} **{detection.threat_type.replace('_', ' ').title()}** — "
                f"`{detection.score}/100` · {detection.action.upper()}"
            )
            st.caption(f"Indicators: {', '.join(detection.indicators) or 'none'}")
    with tabs[2]:
        for policy in result.policies:
            st.markdown(f"**{policy.policy_id}** · `{policy.enforcement}`")
            st.write(policy.statement)
            st.caption(f"Trigger: {policy.trigger}")
    with tabs[3]:
        for event in result.events:
            st.markdown(f"`{event.sequence:02d}` **{event.agent}** · `{event.event_type}`")
            st.caption(event.detail)

    with st.expander("Deterministic audit report"):
        st.json(
            {
                "scenario_id": result.report.scenario_id,
                "decision": result.report.decision,
                "event_count": result.report.event_count,
                "sandbox_digest": result.report.sandbox_digest,
                "event_digests": list(result.report.event_digests),
            }
        )


if __name__ == "__main__":
    main()
