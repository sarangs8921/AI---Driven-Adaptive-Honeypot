import json
from pathlib import Path


ANALYZED_FILE = Path(
    "data/processed/sessions/analyzed_sessions.jsonl"
)

RISK_FILE = Path(
    "data/processed/sessions/risk_sessions.jsonl"
)

OUTPUT_FILE = Path(
    "data/processed/sessions/stateful_sessions.jsonl"
)


STATE_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def determine_state(score):

    if score >= 70:
        return "CRITICAL"

    if score >= 45:
        return "HIGH"

    if score >= 20:
        return "MEDIUM"

    return "LOW"


def determine_transition(previous_state, current_state):

    previous_level = STATE_ORDER[previous_state]
    current_level = STATE_ORDER[current_state]

    if current_level > previous_level:
        return "ESCALATED"

    if current_level < previous_level:
        return "DEESCALATED"

    return "UNCHANGED"


def load_jsonl(path):

    records = {}

    with path.open("r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            record = json.loads(line)

            session_id = record.get("session_id")

            if session_id:
                records[session_id] = record

    return records


def build_state_record(analyzed, risk):

    # Risk score is nested inside the "risk" object
    risk_data = risk.get("risk", {})

    risk_score = risk_data.get("score", 0)

    risk_state = risk_data.get(
        "state",
        determine_state(risk_score)
    )

    current_state = determine_state(risk_score)

    previous_state = "LOW"

    transition = determine_transition(
        previous_state,
        current_state
    )

    behavior_counts = analyzed.get(
        "behavior_counts",
        {}
    )

    return {
        "session_id": analyzed.get("session_id"),

        "risk_score": risk_score,

        "risk_state": risk_state,

        "previous_state": previous_state,

        "current_state": current_state,

        "state_transition": transition,

        "escalated": (
            STATE_ORDER[current_state]
            > STATE_ORDER[previous_state]
        ),

        "behaviors": sorted(
            behavior_counts.keys()
        ),

        "behavior_counts": behavior_counts,

        "commands": analyzed.get(
            "commands",
            []
        ),

        "authentication": analyzed.get(
            "authentication",
            {}
        ),

        "event_count": analyzed.get(
            "event_count",
            0
        ),

        "risk_reasons": risk_data.get(
            "reasons",
            []
        ),
    }


def main():

    if not ANALYZED_FILE.exists():

        print(
            f"ERROR: Missing file: {ANALYZED_FILE}"
        )

        return

    if not RISK_FILE.exists():

        print(
            f"ERROR: Missing file: {RISK_FILE}"
        )

        return

    analyzed_sessions = load_jsonl(
        ANALYZED_FILE
    )

    risk_sessions = load_jsonl(
        RISK_FILE
    )

    print("\nSTATEFUL THREAT ANALYSIS")
    print("-" * 40)

    print(
        f"Analyzed sessions : "
        f"{len(analyzed_sessions)}"
    )

    print(
        f"Risk sessions     : "
        f"{len(risk_sessions)}"
    )

    records = []

    for session_id, analyzed in analyzed_sessions.items():

        risk = risk_sessions.get(session_id)

        if risk is None:

            print(
                f"WARNING: No risk record for "
                f"{session_id}"
            )

            continue

        record = build_state_record(
            analyzed,
            risk
        )

        records.append(record)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as f:

        for record in records:

            f.write(
                json.dumps(record)
                + "\n"
            )

    state_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    escalation_count = 0

    for record in records:

        state = record["current_state"]

        state_counts[state] += 1

        if record["escalated"]:
            escalation_count += 1

    print("\nState distribution:")

    for state in [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]:

        print(
            f"  {state:<8}: "
            f"{state_counts[state]}"
        )

    print(
        f"\nEscalated sessions : "
        f"{escalation_count}"
    )

    print(
        f"\nOutput written to: "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()