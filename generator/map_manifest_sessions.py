import json
import subprocess
from pathlib import Path
from collections import defaultdict


MANIFEST_PATH = Path("data/generated/scenario_manifest.jsonl")
OUTPUT_PATH = Path("data/generated/manifest_session_mapping.jsonl")

COWRIE_LOG = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json.2026-09-30"
COWRIE_PYTHON = "/cowrie/cowrie-env/bin/python"


def load_manifest():
    records = []

    with MANIFEST_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    return records


def load_cowrie_events():
    """
    Read the live Cowrie JSON log from inside the container.
    """

    script = f"""
import json

path = "{COWRIE_LOG}"

with open(path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)
            print(json.dumps(event))
        except Exception:
            pass
"""

    result = subprocess.run(
        [
            "docker",
            "exec",
            "cowrie",
            COWRIE_PYTHON,
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    events = []

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    return events


def main():

    print("=" * 70)
    print("MANIFEST → COWRIE SESSION MAPPING")
    print("=" * 70)

    manifest = load_manifest()

    print(f"Manifest records : {len(manifest)}")

    events = load_cowrie_events()

    print(f"Cowrie events    : {len(events)}")

    # ---------------------------------------------------------
    # Build session → events mapping
    # ---------------------------------------------------------

    sessions = defaultdict(list)

    for event in events:

        session_id = event.get("session")

        if session_id:
            sessions[session_id].append(event)

    print(f"Cowrie sessions  : {len(sessions)}")

    # ---------------------------------------------------------
    # Search for each dataset marker
    # ---------------------------------------------------------

    results = []

    matched = 0
    unmatched = 0
    ambiguous = 0

    for record in manifest:

        run_id = record["run_id"]
        marker = record["marker"]

        matching_sessions = []

        for session_id, session_events in sessions.items():

            for event in session_events:

                command = event.get("input")

                if not command:
                    command = event.get("command")

                if not command:
                    continue

                if marker in str(command):

                    matching_sessions.append(session_id)
                    break

        matching_sessions = list(dict.fromkeys(matching_sessions))

        result = dict(record)

        result["matched_session_ids"] = matching_sessions

        if len(matching_sessions) == 1:

            result["session_id"] = matching_sessions[0]
            result["mapping_status"] = "matched"

            matched += 1

        elif len(matching_sessions) == 0:

            result["session_id"] = None
            result["mapping_status"] = "unmatched"

            unmatched += 1

        else:

            result["session_id"] = None
            result["mapping_status"] = "ambiguous"

            ambiguous += 1

        results.append(result)

    # ---------------------------------------------------------
    # Save
    # ---------------------------------------------------------

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as f:

        for result in results:

            f.write(
                json.dumps(
                    result,
                    ensure_ascii=False
                )
                + "\n"
            )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    print("\n" + "-" * 70)
    print("MAPPING SUMMARY")
    print("-" * 70)

    print(f"Manifest records : {len(manifest)}")
    print(f"Matched          : {matched}")
    print(f"Unmatched        : {unmatched}")
    print(f"Ambiguous        : {ambiguous}")

    print("\nOutput:")
    print(OUTPUT_PATH)

    # ---------------------------------------------------------
    # Show unmatched records
    # ---------------------------------------------------------

    if unmatched:

        print("\n" + "-" * 70)
        print("UNMATCHED RUNS")
        print("-" * 70)

        for result in results:

            if result["mapping_status"] == "unmatched":

                print(
                    result["run_id"],
                    "|",
                    result["scenario_label"]
                )

    # ---------------------------------------------------------
    # Show ambiguous records
    # ---------------------------------------------------------

    if ambiguous:

        print("\n" + "-" * 70)
        print("AMBIGUOUS RUNS")
        print("-" * 70)

        for result in results:

            if result["mapping_status"] == "ambiguous":

                print(
                    result["run_id"],
                    "|",
                    result["matched_session_ids"]
                )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()