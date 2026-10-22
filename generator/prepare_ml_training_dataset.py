from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

INPUT_PATH = Path(
    "data/generated/validated_ml_dataset.jsonl"
)

OUTPUT_PATH = Path(
    "data/generated/ml_training_dataset.jsonl"
)


# ============================================================
# CONSTANT FEATURES
# ============================================================
#
# These are constant across the current 504-session dataset
# and therefore contain no information useful for ML.
#
# IMPORTANT:
# This list is based on the CURRENT 504-session variability
# audit, not the previous 90-session dataset.
# ============================================================

EXCLUDED_FEATURES = {
    "max_command_length",
    "successful_auth",
    "failed_attempts",
}


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print("=" * 70)
    print("PREPARING ML TRAINING DATASET")
    print("=" * 70)

    # --------------------------------------------------------
    # Check input
    # --------------------------------------------------------

    if not INPUT_PATH.exists():

        raise FileNotFoundError(
            f"Input dataset not found: {INPUT_PATH}"
        )

    # --------------------------------------------------------
    # Load records
    # --------------------------------------------------------

    with INPUT_PATH.open(
        "r",
        encoding="utf-8"
    ) as f:

        records = [
            json.loads(line)
            for line in f
            if line.strip()
        ]

    if not records:

        raise ValueError(
            "Input dataset contains no records."
        )

    print(
        f"\nInput records : {len(records)}"
    )

    # --------------------------------------------------------
    # Validate required fields
    # --------------------------------------------------------

    required_fields = {
        "session_id",
        "scenario_label",
        "features",
    }

    for index, record in enumerate(records):

        missing = (
            required_fields
            - set(record.keys())
        )

        if missing:

            raise ValueError(
                f"Record {index} is missing "
                f"fields: {sorted(missing)}"
            )

        if not isinstance(
            record["features"],
            dict
        ):

            raise ValueError(
                f"Record {index} has invalid "
                "feature structure."
            )

    # --------------------------------------------------------
    # Determine feature schema
    # --------------------------------------------------------

    original_features = list(
        records[0]["features"].keys()
    )

    original_feature_set = set(
        original_features
    )

    print(
        f"Original features : "
        f"{len(original_features)}"
    )

    # --------------------------------------------------------
    # Validate feature schema consistency
    # --------------------------------------------------------

    expected_schema = set(
        original_features
    )

    for index, record in enumerate(records):

        record_schema = set(
            record["features"].keys()
        )

        if record_schema != expected_schema:

            missing = (
                expected_schema
                - record_schema
            )

            extra = (
                record_schema
                - expected_schema
            )

            raise ValueError(
                f"Record {index} has inconsistent "
                f"feature schema.\n"
                f"Missing: {sorted(missing)}\n"
                f"Extra: {sorted(extra)}"
            )

    # --------------------------------------------------------
    # Validate excluded features
    # --------------------------------------------------------

    missing_excluded = (
        EXCLUDED_FEATURES
        - original_feature_set
    )

    if missing_excluded:

        raise ValueError(
            "Excluded features were not found "
            f"in the input dataset: "
            f"{sorted(missing_excluded)}"
        )

    # --------------------------------------------------------
    # Select training features
    # --------------------------------------------------------

    training_features = [
        feature
        for feature in original_features
        if feature not in EXCLUDED_FEATURES
    ]

    print(
        f"Excluded features : "
        f"{len(EXCLUDED_FEATURES)}"
    )

    print(
        f"Training features  : "
        f"{len(training_features)}"
    )

    # --------------------------------------------------------
    # Display excluded features
    # --------------------------------------------------------

    print("\nExcluded features:")

    for feature in sorted(
        EXCLUDED_FEATURES
    ):

        print(
            f"  - {feature}"
        )

    # --------------------------------------------------------
    # Build training records
    # --------------------------------------------------------

    training_records = []

    for record in records:

        selected_features = {
            feature: record["features"][feature]
            for feature in training_features
        }

        training_record = {

            "session_id":
                record["session_id"],

            "scenario_label":
                record["scenario_label"],

            "features":
                selected_features,
        }

        training_records.append(
            training_record
        )

    # --------------------------------------------------------
    # Validate training records
    # --------------------------------------------------------

    expected_feature_count = len(
        training_features
    )

    for index, record in enumerate(
        training_records
    ):

        actual_count = len(
            record["features"]
        )

        if actual_count != expected_feature_count:

            raise ValueError(
                f"Record {index}: expected "
                f"{expected_feature_count} features, "
                f"found {actual_count}"
            )

        for feature, value in (
            record["features"].items()
        ):

            if value is None:

                raise ValueError(
                    f"Record {index} contains "
                    f"None for feature "
                    f"'{feature}'"
                )

    # --------------------------------------------------------
    # Scenario distribution
    # --------------------------------------------------------

    scenario_counts = Counter(
        record["scenario_label"]
        for record in training_records
    )

    print("\nScenario distribution:")

    for label, count in sorted(
        scenario_counts.items()
    ):

        print(
            f"  {label:<25} : {count}"
        )

    # --------------------------------------------------------
    # Validate class balance
    # --------------------------------------------------------

    if len(scenario_counts) != 9:

        raise ValueError(
            "Expected exactly 9 scenario classes, "
            f"found {len(scenario_counts)}"
        )

    class_counts = list(
        scenario_counts.values()
    )

    if len(set(class_counts)) != 1:

        print(
            "\nWARNING: Dataset is not perfectly "
            "class-balanced."
        )

    else:

        print(
            "\nClass balance: PASS"
        )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8"
    ) as f:

        for record in training_records:

            f.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                )
                + "\n"
            )

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("DATASET PREPARATION COMPLETE")
    print("=" * 70)

    print(
        f"Input records     : "
        f"{len(records)}"
    )

    print(
        f"Output records    : "
        f"{len(training_records)}"
    )

    print(
        f"Original features : "
        f"{len(original_features)}"
    )

    print(
        f"Excluded features : "
        f"{len(EXCLUDED_FEATURES)}"
    )

    print(
        f"Training features : "
        f"{len(training_features)}"
    )

    print(
        f"Output            : "
        f"{OUTPUT_PATH}"
    )

    print()
    print(
        "STATUS: PASS"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()