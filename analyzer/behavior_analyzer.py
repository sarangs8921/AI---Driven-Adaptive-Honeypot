import json
from pathlib import Path

from analyzer.rules import detect_behaviors, get_attack_context


INPUT_FILE = Path(
    "data/processed/sessions/sessions.jsonl"
)

OUTPUT_FILE = Path(
    "data/processed/sessions/analyzed_sessions.jsonl"
)


def analyze_session(session):
    """
    Analyze one reconstructed Cowrie session.

    The function adds behavioral observations but does not
    calculate a threat/risk score.
    """

    analyzed_commands = []

    behavior_counts = {}

    technique_ids = set()

    for item in session.get("commands", []):

        command = item.get("command", "")
        timestamp = item.get("timestamp")

        behaviors = detect_behaviors(command)

        attack_context = []

        for behavior in behaviors:

            behavior_counts[behavior] = (
                behavior_counts.get(behavior, 0) + 1
            )

            context = get_attack_context(behavior)

            if context:
                attack_context.append(context)

                technique_ids.add(
                    context["technique_id"]
                )

        analyzed_commands.append(
            {
                "command": command,
                "timestamp": timestamp,
                "behaviors": behaviors,
                "attack_context": attack_context,
            }
        )

    analyzed_session = dict(session)

    analyzed_session["analyzed_commands"] = analyzed_commands

    analyzed_session["behavior_counts"] = behavior_counts

    analyzed_session["behaviors"] = sorted(
        behavior_counts.keys()
    )

    analyzed_session["technique_ids"] = sorted(
        technique_ids
    )

    return analyzed_session


def load_sessions():
    """
    Load reconstructed sessions from JSONL.
    """

    sessions = []

    if not INPUT_FILE.exists():
        print(f"ERROR: Input file not found: {INPUT_FILE}")
        return sessions

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                sessions.append(json.loads(line))

            except json.JSONDecodeError:
                print("WARNING: Invalid JSON skipped.")

    return sessions


def save_sessions(sessions):
    """
    Save analyzed sessions as JSONL.
    """

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        for session in sessions:

            file.write(
                json.dumps(
                    session,
                    ensure_ascii=False,
                )
                + "\n"
            )


def main():

    print("=" * 60)
    print("COWRIE BEHAVIOR ANALYZER")
    print("=" * 60)

    sessions = load_sessions()

    print(f"Sessions loaded: {len(sessions)}")

    analyzed_sessions = []

    for session in sessions:

        analyzed = analyze_session(session)

        analyzed_sessions.append(analyzed)

    save_sessions(analyzed_sessions)

    print(
        f"Analyzed sessions: "
        f"{len(analyzed_sessions)}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print("\nAnalysis complete.")


if __name__ == "__main__":
    main()