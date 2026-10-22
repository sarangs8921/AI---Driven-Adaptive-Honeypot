import json
from pathlib import Path


COWRIE_LOG = (
    "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
)

MANIFEST_FILE = Path(
    "data/generated/independent_evaluation/"
    "evaluation_manifest.jsonl"
)

OUTPUT_FILE = Path(
    "data/generated/independent_evaluation/"
    "evaluation_sessions.jsonl"
)


def load_jsonl(path):
    records = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:

        for line in handle:

            line = line.strip()

            if not line:
                continue

            records.append(
                json.loads(line)
            )

    return records


def load_cowrie_events():
    """
    Load Cowrie events from the live log inside
    the Cowrie container.
    """

    import subprocess

    command = [
        "docker",
        "exec",
        "cowrie",
        "/cowrie/cowrie-env/bin/python",
        "-c",
        (
            "from pathlib import Path; "
            f"print(Path('{COWRIE_LOG}').read_text())"
        ),
    ]

    result = subprocess.run(
        command,
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

            events.append(
                json.loads(line)
            )

        except json.JSONDecodeError:

            continue

    return events


def main():

    print("=" * 70)
    print("COLLECTING INDEPENDENT COWRIE EVALUATION SESSIONS")
    print("=" * 70)

    manifest = load_jsonl(
        MANIFEST_FILE
    )

    events = load_cowrie_events()

    print(
        f"Manifest records : {len(manifest)}"
    )

    print(
        f"Cowrie events    : {len(events)}"
    )

    # --------------------------------------------------------
    # Build marker → Cowrie session mapping.
    # --------------------------------------------------------

    marker_to_session = {}

    for event in events:

        session_id = event.get(
            "session"
        )

        if not session_id:
            continue

        # Cowrie may store the marker in different
        # fields depending on event type.
        event_text = json.dumps(
            event,
            ensure_ascii=False,
        )

        marker_start = event_text.find(
            "DATASET_EVAL_"
        )

        if marker_start == -1:
            continue

        marker_end = marker_start

        while (
            marker_end < len(event_text)
            and event_text[marker_end]
            not in [
                '"',
                "'",
                " ",
                "\\",
            ]
        ):
            marker_end += 1

        marker = event_text[
            marker_start:marker_end
        ]

        # UUID markers end at the UUID itself.
        if marker.startswith(
            "DATASET_EVAL_"
        ):

            marker_to_session[
                marker
            ] = session_id

    print(
        f"Evaluation markers found : "
        f"{len(marker_to_session)}"
    )

    # --------------------------------------------------------
    # Group all Cowrie events by session.
    # --------------------------------------------------------

    events_by_session = {}

    for event in events:

        session_id = event.get(
            "session"
        )

        if not session_id:
            continue

        events_by_session.setdefault(
            session_id,
            [],
        ).append(event)

    # --------------------------------------------------------
    # Build manifest lookup.
    # --------------------------------------------------------

    manifest_by_marker = {}

    for record in manifest:

        marker = record.get(
            "marker"
        )

        if marker:

            marker_by_value = marker.replace(
                "echo ",
                "",
                1,
            )

            manifest_by_marker[
                marker_by_value
            ] = record

    # --------------------------------------------------------
    # Reconstruct sessions.
    # --------------------------------------------------------

    output_records = []

    missing_markers = []
    missing_sessions = []

    for marker, session_id in sorted(
        marker_to_session.items()
    ):

        manifest_record = (
            manifest_by_marker.get(
                marker
            )
        )

        if manifest_record is None:

            missing_markers.append(
                marker
            )

            continue

        session_events = (
            events_by_session.get(
                session_id,
                [],
            )
        )

        if not session_events:

            missing_sessions.append(
                session_id
            )

            continue

        output_records.append(
            {
                "evaluation": True,
                "run_id":
                    manifest_record[
                        "run_id"
                    ],
                "scenario_label":
                    manifest_record[
                        "scenario_label"
                    ],
                "expected_behaviors":
                    manifest_record[
                        "expected_behaviors"
                    ],
                "random_seed":
                    manifest_record[
                        "random_seed"
                    ],
                "repetition":
                    manifest_record[
                        "repetition"
                    ],
                "marker":
                    marker,
                "cowrie_session_id":
                    session_id,
                "events":
                    session_events,
            }
        )

    # --------------------------------------------------------
    # Write output.
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as handle:

        for record in output_records:

            handle.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    # --------------------------------------------------------
    # Validation.
    # --------------------------------------------------------

    unique_run_ids = {
        record["run_id"]
        for record in output_records
    }

    unique_sessions = {
        record["cowrie_session_id"]
        for record in output_records
    }

    print()
    print("=" * 70)
    print("INDEPENDENT EVALUATION COLLECTION SUMMARY")
    print("=" * 70)

    print(
        f"Manifest records     : {len(manifest)}"
    )

    print(
        f"Markers found        : "
        f"{len(marker_to_session)}"
    )

    print(
        f"Sessions reconstructed: "
        f"{len(output_records)}"
    )

    print(
        f"Unique run IDs       : "
        f"{len(unique_run_ids)}"
    )

    print(
        f"Unique Cowrie IDs    : "
        f"{len(unique_sessions)}"
    )

    print(
        f"Missing markers      : "
        f"{len(missing_markers)}"
    )

    print(
        f"Missing sessions     : "
        f"{len(missing_sessions)}"
    )

    print(
        f"Output               : "
        f"{OUTPUT_FILE}"
    )

    if (
        len(output_records) == 180
        and len(unique_run_ids) == 180
        and len(unique_sessions) == 180
        and not missing_markers
        and not missing_sessions
    ):

        print()
        print(
            "STATUS: PASS"
        )

    else:

        print()
        print(
            "STATUS: FAIL"
        )


if __name__ == "__main__":
    main()