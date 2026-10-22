import json
from pathlib import Path

from generator.ml_feature_extractor import extract_features


INPUT_FILE = Path(
    "data/generated/independent_evaluation/"
    "evaluation_sessions.jsonl"
)

OUTPUT_FILE = Path(
    "data/generated/independent_evaluation/"
    "evaluation_ml_features.jsonl"
)

EXCLUDED_FEATURES = {
    "failed_attempts",
    "max_command_length",
    "successful_auth",
}


def convert_evaluation_record(record):
    """
    Convert the independent evaluation record into the
    session structure expected by the production feature
    extractor.

    The evaluation collector stores raw Cowrie events under
    `events`. The production extractor expects:
        commands
        session_id
        duration_ms
        event_count
        successful_auth
        failed_attempts
    """

    events = record.get("events", [])

    session_id = record.get(
        "cowrie_session_id"
    )

    commands = []

    timestamps = []

    for event in events:

        event_type = event.get("eventid", "")

        timestamp = event.get(
            "timestamp"
        )

        if timestamp:
            timestamps.append(timestamp)

        # ----------------------------------------------------
        # Cowrie command events
        # ----------------------------------------------------

        if event_type == "cowrie.command.input":

            command = event.get(
                "input",
                ""
            )

            if command:

                commands.append(
                    {
                        "command": str(
                            command
                        ).strip(),
                        "timestamp":
                            timestamp,
                    }
                )

    # --------------------------------------------------------
    # Determine session duration.
    # --------------------------------------------------------

    duration_ms = 0

    parsed_timestamps = []

    from generator.ml_feature_extractor import (
        parse_timestamp,
    )

    for timestamp in timestamps:

        parsed = parse_timestamp(
            timestamp
        )

        if parsed is not None:

            parsed_timestamps.append(
                parsed
            )

    if len(parsed_timestamps) >= 2:

        duration_ms = int(
            (
                max(parsed_timestamps)
                - min(parsed_timestamps)
            ).total_seconds()
            * 1000
        )

    # --------------------------------------------------------
    # Authentication
    #
    # These are excluded from the ML model, but we preserve
    # them in the temporary session structure so the
    # production extractor remains compatible.
    # --------------------------------------------------------

    successful_auth = None
    failed_attempts = None

    for event in events:

        event_type = event.get(
            "eventid",
            ""
        )

        if event_type == "cowrie.login.success":

            successful_auth = True

        elif event_type == "cowrie.login.failed":

            if failed_attempts is None:

                failed_attempts = 0

            failed_attempts += 1

    # --------------------------------------------------------
    # Construct production-compatible session.
    # --------------------------------------------------------

    session = {
        "session_id": session_id,
        "commands": commands,
        "duration_ms": duration_ms,
        "event_count": len(events),
        "successful_auth": successful_auth,
        "failed_attempts": failed_attempts,
    }

    return session


def main():

    print("=" * 70)
    print("INDEPENDENT EVALUATION ML FEATURE EXTRACTION")
    print("=" * 70)

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    records = []

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
    ) as handle:

        for line in handle:

            line = line.strip()

            if line:

                records.append(
                    json.loads(line)
                )

    print(
        f"Evaluation sessions loaded : "
        f"{len(records)}"
    )

    output_records = []

    schemas = set()

    for record in records:

        session = convert_evaluation_record(
            record
        )

        features = extract_features(
            session
        )

        # ----------------------------------------------------
        # Remove exactly the same 3 features removed during
        # training dataset preparation.
        # ----------------------------------------------------

        for feature_name in EXCLUDED_FEATURES:

            features.pop(
                feature_name,
                None
            )

        # ----------------------------------------------------
        # Preserve evaluation ground truth separately.
        # These labels are NEVER passed to the model.
        # ----------------------------------------------------

        output_record = {
            "session_id":
                record[
                    "cowrie_session_id"
                ],

            "run_id":
                record[
                    "run_id"
                ],

            "scenario_label":
                record[
                    "scenario_label"
                ],

            "expected_behaviors":
                record[
                    "expected_behaviors"
                ],

            "features":
                features,
        }

        output_records.append(
            output_record
        )

        schemas.add(
            tuple(
                sorted(
                    features.keys()
                )
            )
        )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    expected_feature_count = 30

    if len(output_records) != 180:

        raise ValueError(
            "Expected 180 evaluation records, "
            f"found {len(output_records)}"
        )

    if len(schemas) != 1:

        raise ValueError(
            "Evaluation records do not have "
            "an identical feature schema."
        )

    actual_feature_count = len(
        output_records[0]["features"]
    )

    if actual_feature_count != expected_feature_count:

        raise ValueError(
            "Expected 30 features, "
            f"found {actual_feature_count}"
        )

    feature_names = set(
        output_records[0]["features"].keys()
    )

    # --------------------------------------------------------
    # Numeric validation
    # --------------------------------------------------------

    for record in output_records:

        for name, value in record[
            "features"
        ].items():

            if not isinstance(
                value,
                (int, float)
            ):

                raise ValueError(
                    f"Non-numeric feature: "
                    f"{name}"
                )

            if isinstance(
                value,
                float
            ):

                if value != value:

                    raise ValueError(
                        f"NaN feature value: "
                        f"{name}"
                    )

                if value in (
                    float("inf"),
                    float("-inf"),
                ):

                    raise ValueError(
                        f"Infinite feature value: "
                        f"{name}"
                    )

    # --------------------------------------------------------
    # Write output
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
    # Class distribution
    # --------------------------------------------------------

    class_counts = {}

    for record in output_records:

        label = record[
            "scenario_label"
        ]

        class_counts[label] = (
            class_counts.get(
                label,
                0
            )
            + 1
        )

    print()
    print("=" * 70)
    print("INDEPENDENT EVALUATION FEATURE SUMMARY")
    print("=" * 70)

    print(
        f"Records            : "
        f"{len(output_records)}"
    )

    print(
        f"Features           : "
        f"{len(feature_names)}"
    )

    print(
        "Excluded features  : "
        f"{len(EXCLUDED_FEATURES)}"
    )

    print()

    print("Scenario distribution:")

    for label in sorted(
        class_counts
    ):

        print(
            f"  {label:<22}: "
            f"{class_counts[label]}"
        )

    print()

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print(
        "STATUS: PASS"
    )


if __name__ == "__main__":
    main()