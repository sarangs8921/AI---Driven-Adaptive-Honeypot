import json
from pathlib import Path


MAPPING_PATH = Path(
    "data/generated/manifest_session_mapping.jsonl"
)

SESSIONS_PATH = Path(
    "data/processed/sessions/sessions.jsonl"
)

FEATURES_PATH = Path(
    "data/generated/ml_features.jsonl"
)

OUTPUT_PATH = Path(
    "data/generated/validated_ml_dataset.jsonl"
)


def load_jsonl(path):
    records = []

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    with path.open("r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            records.append(
                json.loads(line)
            )

    return records


def main():

    print("=" * 75)
    print("BUILDING VALIDATED ML DATASET")
    print("=" * 75)

    # ---------------------------------------------------------
    # Load files
    # ---------------------------------------------------------

    mapping_records = load_jsonl(
        MAPPING_PATH
    )

    session_records = load_jsonl(
        SESSIONS_PATH
    )

    feature_records = load_jsonl(
        FEATURES_PATH
    )

    print(
        f"\nMapping records : {len(mapping_records)}"
    )

    print(
        f"Session records : {len(session_records)}"
    )

    print(
        f"Feature records : {len(feature_records)}"
    )

    # ---------------------------------------------------------
    # Build lookup tables
    # ---------------------------------------------------------

    sessions_by_id = {}

    for session in session_records:

        session_id = session.get(
            "session_id"
        )

        if session_id:
            sessions_by_id[session_id] = session

    features_by_id = {}

    for record in feature_records:

        session_id = record.get(
            "session_id"
        )

        if session_id:
            features_by_id[session_id] = record

    print(
        f"\nIndexed Cowrie sessions : "
        f"{len(sessions_by_id)}"
    )

    print(
        f"Indexed feature records  : "
        f"{len(features_by_id)}"
    )

    # ---------------------------------------------------------
    # Validation containers
    # ---------------------------------------------------------

    validated_records = []

    missing_sessions = []
    missing_features = []
    duplicate_session_ids = []

    used_session_ids = set()

    # ---------------------------------------------------------
    # Process every mapping record
    # ---------------------------------------------------------

    for mapping in mapping_records:

        run_id = mapping.get(
            "run_id"
        )

        session_id = mapping.get(
            "session_id"
        )

        scenario_label = mapping.get(
            "scenario_label"
        )

        expected_behaviors = mapping.get(
            "expected_behaviors",
            []
        )

        commands = mapping.get(
            "commands",
            []
        )

        # -----------------------------------------------------
        # Check session ID
        # -----------------------------------------------------

        if not session_id:

            missing_sessions.append(
                run_id
            )

            continue

        # -----------------------------------------------------
        # Check whether Cowrie session exists
        # -----------------------------------------------------

        if session_id not in sessions_by_id:

            missing_sessions.append(
                session_id
            )

            continue

        # -----------------------------------------------------
        # Detect duplicate session mapping
        # -----------------------------------------------------

        if session_id in used_session_ids:

            duplicate_session_ids.append(
                session_id
            )

            continue

        used_session_ids.add(
            session_id
        )

        session = sessions_by_id[
            session_id
        ]

        # -----------------------------------------------------
        # Check ML features
        # -----------------------------------------------------

        if session_id not in features_by_id:

            missing_features.append(
                session_id
            )

            continue

        feature_record = features_by_id[
            session_id
        ]

        features = feature_record.get(
            "features",
            {}
        )

        # -----------------------------------------------------
        # Validate feature structure
        # -----------------------------------------------------

        if not isinstance(
            features,
            dict
        ):

            missing_features.append(
                session_id
            )

            continue

        # -----------------------------------------------------
        # Verify feature/session ID consistency
        # -----------------------------------------------------

        if feature_record.get(
            "session_id"
        ) != session_id:

            print(
                f"WARNING: Feature session mismatch "
                f"for {session_id}"
            )

            missing_features.append(
                session_id
            )

            continue

        # -----------------------------------------------------
        # Verify marker exists in manifest commands
        # -----------------------------------------------------

        marker = mapping.get(
            "marker"
        )

        marker_found = False

        for command in commands:

            if (
                marker
                and
                marker in str(command)
            ):

                marker_found = True

                break

        if not marker_found:

            print(
                f"WARNING: Marker missing from "
                f"manifest commands: {run_id}"
            )

        # -----------------------------------------------------
        # Create validated record
        # -----------------------------------------------------

        validated_record = {

            "run_id":
                run_id,

            "session_id":
                session_id,

            "scenario_label":
                scenario_label,

            "expected_behaviors":
                expected_behaviors,

            "commands":
                commands,

            "random_seed":
                mapping.get(
                    "random_seed"
                ),

            "repetition":
                mapping.get(
                    "repetition"
                ),

            "marker":
                marker,

            "source_port":
                mapping.get(
                    "source_port"
                ),

            "generated_at":
                mapping.get(
                    "generated_at"
                ),

            "cowrie_session": {

                "successful_auth":
                    session.get(
                        "successful_auth"
                    ),

                "failed_attempts":
                    session.get(
                        "failed_attempts",
                        0
                    ),

                "event_count":
                    session.get(
                        "event_count",
                        0
                    ),

                "command_count":
                    session.get(
                        "command_count",
                        0
                    ),

                "duration_ms":
                    session.get(
                        "duration_ms"
                    )
            },

            "features":
                features
        }

        validated_records.append(
            validated_record
        )

    # ---------------------------------------------------------
    # Save validated dataset
    # ---------------------------------------------------------

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8"
    ) as f:

        for record in validated_records:

            f.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                )
                + "\n"
            )

    # ---------------------------------------------------------
    # Dataset summary
    # ---------------------------------------------------------

    print("\n" + "=" * 75)
    print("VALIDATION SUMMARY")
    print("=" * 75)

    print(
        f"Manifest records       : "
        f"{len(mapping_records)}"
    )

    print(
        f"Validated records      : "
        f"{len(validated_records)}"
    )

    print(
        f"Missing sessions       : "
        f"{len(missing_sessions)}"
    )

    print(
        f"Missing features       : "
        f"{len(missing_features)}"
    )

    print(
        f"Duplicate session IDs  : "
        f"{len(duplicate_session_ids)}"
    )

    # ---------------------------------------------------------
    # Scenario distribution
    # ---------------------------------------------------------

    scenario_counts = {}

    for record in validated_records:

        label = record.get(
            "scenario_label",
            "unknown"
        )

        scenario_counts[label] = (
            scenario_counts.get(
                label,
                0
            )
            + 1
        )

    print("\n" + "-" * 75)
    print("SCENARIO DISTRIBUTION")
    print("-" * 75)

    for label, count in sorted(
        scenario_counts.items()
    ):

        print(
            f"{label:30} {count}"
        )

    # ---------------------------------------------------------
    # Feature schema validation
    # ---------------------------------------------------------

    feature_counts = []

    for record in validated_records:

        feature_counts.append(
            len(
                record.get(
                    "features",
                    {}
                )
            )
        )

    print("\n" + "-" * 75)
    print("FEATURE SCHEMA")
    print("-" * 75)

    if feature_counts:

        print(
            f"Minimum features/record : "
            f"{min(feature_counts)}"
        )

        print(
            f"Maximum features/record : "
            f"{max(feature_counts)}"
        )

        print(
            f"Unique schema sizes      : "
            f"{sorted(set(feature_counts))}"
        )

    # ---------------------------------------------------------
    # Final validation
    # ---------------------------------------------------------

    # The manifest may contain historical records that do not
    # belong to the current Cowrie log. Those records are counted
    # as unmatched and intentionally excluded.
    #
    # Therefore:
    #
    # validated records == matched mappings
    #
    # rather than:
    #
    # validated records == all manifest records

    matched_mapping_count = (
        len(mapping_records)
        - len(missing_sessions)
    )

    unmatched_mapping_count = (
        len(missing_sessions)
    )

    print("\n" + "=" * 75)
    print("FINAL VALIDATION")
    print("=" * 75)

    print(
        f"Matched mappings        : "
        f"{matched_mapping_count}"
    )

    print(
        f"Unmatched mappings      : "
        f"{unmatched_mapping_count}"
    )

    # ---------------------------------------------------------
    # PASS conditions
    # ---------------------------------------------------------

    validation_passed = (

        len(validated_records)
        ==
        matched_mapping_count

        and

        not missing_features

        and

        not duplicate_session_ids

        and

        len(validated_records) > 0
    )

    if validation_passed:

        print(
            "\nSTATUS: VALIDATION PASSED"
        )

        print(
            "All matched Cowrie sessions have "
            "unique ML features."
        )

    else:

        print(
            "\nSTATUS: VALIDATION FAILED"
        )

        print(
            "Do not use this dataset for ML training yet."
        )

    print("=" * 75)

    print(
        f"\nOutput: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
import json
from pathlib import Path


MAPPING_PATH = Path(
    "data/generated/manifest_session_mapping.jsonl"
)

SESSIONS_PATH = Path(
    "data/processed/sessions/sessions.jsonl"
)

FEATURES_PATH = Path(
    "data/generated/ml_features.jsonl"
)

OUTPUT_PATH = Path(
    "data/generated/validated_ml_dataset.jsonl"
)


def load_jsonl(path):
    records = []

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    with path.open("r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            records.append(
                json.loads(line)
            )

    return records


def main():

    print("=" * 75)
    print("BUILDING VALIDATED ML DATASET")
    print("=" * 75)

    # ---------------------------------------------------------
    # Load files
    # ---------------------------------------------------------

    mapping_records = load_jsonl(
        MAPPING_PATH
    )

    session_records = load_jsonl(
        SESSIONS_PATH
    )

    feature_records = load_jsonl(
        FEATURES_PATH
    )

    print(
        f"\nMapping records : {len(mapping_records)}"
    )

    print(
        f"Session records : {len(session_records)}"
    )

    print(
        f"Feature records : {len(feature_records)}"
    )

    # ---------------------------------------------------------
    # Build lookup tables
    # ---------------------------------------------------------

    sessions_by_id = {}

    for session in session_records:

        session_id = session.get(
            "session_id"
        )

        if session_id:
            sessions_by_id[session_id] = session

    features_by_id = {}

    for record in feature_records:

        session_id = record.get(
            "session_id"
        )

        if session_id:
            features_by_id[session_id] = record

    print(
        f"\nIndexed Cowrie sessions : "
        f"{len(sessions_by_id)}"
    )

    print(
        f"Indexed feature records  : "
        f"{len(features_by_id)}"
    )

    # ---------------------------------------------------------
    # Validation containers
    # ---------------------------------------------------------

    validated_records = []

    missing_sessions = []
    missing_features = []
    duplicate_session_ids = []

    used_session_ids = set()

    # ---------------------------------------------------------
    # Process every mapping record
    # ---------------------------------------------------------

    for mapping in mapping_records:

        run_id = mapping.get(
            "run_id"
        )

        session_id = mapping.get(
            "session_id"
        )

        scenario_label = mapping.get(
            "scenario_label"
        )

        expected_behaviors = mapping.get(
            "expected_behaviors",
            []
        )

        commands = mapping.get(
            "commands",
            []
        )

        # -----------------------------------------------------
        # Check session ID
        # -----------------------------------------------------

        if not session_id:

            missing_sessions.append(
                run_id
            )

            continue

        # -----------------------------------------------------
        # Check whether Cowrie session exists
        # -----------------------------------------------------

        if session_id not in sessions_by_id:

            missing_sessions.append(
                session_id
            )

            continue

        # -----------------------------------------------------
        # Detect duplicate session mapping
        # -----------------------------------------------------

        if session_id in used_session_ids:

            duplicate_session_ids.append(
                session_id
            )

            continue

        used_session_ids.add(
            session_id
        )

        session = sessions_by_id[
            session_id
        ]

        # -----------------------------------------------------
        # Check ML features
        # -----------------------------------------------------

        if session_id not in features_by_id:

            missing_features.append(
                session_id
            )

            continue

        feature_record = features_by_id[
            session_id
        ]

        features = feature_record.get(
            "features",
            {}
        )

        # -----------------------------------------------------
        # Validate feature structure
        # -----------------------------------------------------

        if not isinstance(
            features,
            dict
        ):

            missing_features.append(
                session_id
            )

            continue

        # -----------------------------------------------------
        # Verify feature/session ID consistency
        # -----------------------------------------------------

        if feature_record.get(
            "session_id"
        ) != session_id:

            print(
                f"WARNING: Feature session mismatch "
                f"for {session_id}"
            )

            missing_features.append(
                session_id
            )

            continue

        # -----------------------------------------------------
        # Verify marker exists in manifest commands
        # -----------------------------------------------------

        marker = mapping.get(
            "marker"
        )

        marker_found = False

        for command in commands:

            if (
                marker
                and
                marker in str(command)
            ):

                marker_found = True

                break

        if not marker_found:

            print(
                f"WARNING: Marker missing from "
                f"manifest commands: {run_id}"
            )

        # -----------------------------------------------------
        # Create validated record
        # -----------------------------------------------------

        validated_record = {

            "run_id":
                run_id,

            "session_id":
                session_id,

            "scenario_label":
                scenario_label,

            "expected_behaviors":
                expected_behaviors,

            "commands":
                commands,

            "random_seed":
                mapping.get(
                    "random_seed"
                ),

            "repetition":
                mapping.get(
                    "repetition"
                ),

            "marker":
                marker,

            "source_port":
                mapping.get(
                    "source_port"
                ),

            "generated_at":
                mapping.get(
                    "generated_at"
                ),

            "cowrie_session": {

                "successful_auth":
                    session.get(
                        "successful_auth"
                    ),

                "failed_attempts":
                    session.get(
                        "failed_attempts",
                        0
                    ),

                "event_count":
                    session.get(
                        "event_count",
                        0
                    ),

                "command_count":
                    session.get(
                        "command_count",
                        0
                    ),

                "duration_ms":
                    session.get(
                        "duration_ms"
                    )
            },

            "features":
                features
        }

        validated_records.append(
            validated_record
        )

    # ---------------------------------------------------------
    # Save validated dataset
    # ---------------------------------------------------------

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8"
    ) as f:

        for record in validated_records:

            f.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                )
                + "\n"
            )

    # ---------------------------------------------------------
    # Dataset summary
    # ---------------------------------------------------------

    print("\n" + "=" * 75)
    print("VALIDATION SUMMARY")
    print("=" * 75)

    print(
        f"Manifest records       : "
        f"{len(mapping_records)}"
    )

    print(
        f"Validated records      : "
        f"{len(validated_records)}"
    )

    print(
        f"Missing sessions       : "
        f"{len(missing_sessions)}"
    )

    print(
        f"Missing features       : "
        f"{len(missing_features)}"
    )

    print(
        f"Duplicate session IDs  : "
        f"{len(duplicate_session_ids)}"
    )

    # ---------------------------------------------------------
    # Scenario distribution
    # ---------------------------------------------------------

    scenario_counts = {}

    for record in validated_records:

        label = record.get(
            "scenario_label",
            "unknown"
        )

        scenario_counts[label] = (
            scenario_counts.get(
                label,
                0
            )
            + 1
        )

    print("\n" + "-" * 75)
    print("SCENARIO DISTRIBUTION")
    print("-" * 75)

    for label, count in sorted(
        scenario_counts.items()
    ):

        print(
            f"{label:30} {count}"
        )

    # ---------------------------------------------------------
    # Feature schema validation
    # ---------------------------------------------------------

    feature_counts = []

    for record in validated_records:

        feature_counts.append(
            len(
                record.get(
                    "features",
                    {}
                )
            )
        )

    print("\n" + "-" * 75)
    print("FEATURE SCHEMA")
    print("-" * 75)

    if feature_counts:

        print(
            f"Minimum features/record : "
            f"{min(feature_counts)}"
        )

        print(
            f"Maximum features/record : "
            f"{max(feature_counts)}"
        )

        print(
            f"Unique schema sizes      : "
            f"{sorted(set(feature_counts))}"
        )

    # ---------------------------------------------------------
    # Final validation
    # ---------------------------------------------------------

    # The manifest may contain historical records that do not
    # belong to the current Cowrie log. Those records are counted
    # as unmatched and intentionally excluded.
    #
    # Therefore:
    #
    # validated records == matched mappings
    #
    # rather than:
    #
    # validated records == all manifest records

    matched_mapping_count = (
        len(mapping_records)
        - len(missing_sessions)
    )

    unmatched_mapping_count = (
        len(missing_sessions)
    )

    print("\n" + "=" * 75)
    print("FINAL VALIDATION")
    print("=" * 75)

    print(
        f"Matched mappings        : "
        f"{matched_mapping_count}"
    )

    print(
        f"Unmatched mappings      : "
        f"{unmatched_mapping_count}"
    )

    # ---------------------------------------------------------
    # PASS conditions
    # ---------------------------------------------------------

    validation_passed = (

        len(validated_records)
        ==
        matched_mapping_count

        and

        not missing_features

        and

        not duplicate_session_ids

        and

        len(validated_records) > 0
    )

    if validation_passed:

        print(
            "\nSTATUS: VALIDATION PASSED"
        )

        print(
            "All matched Cowrie sessions have "
            "unique ML features."
        )

    else:

        print(
            "\nSTATUS: VALIDATION FAILED"
        )

        print(
            "Do not use this dataset for ML training yet."
        )

    print("=" * 75)

    print(
        f"\nOutput: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()