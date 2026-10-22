import json
from pathlib import Path
from collections import Counter


DATASET_PATH = Path(
    "data/generated/validated_ml_dataset.jsonl"
)

ANALYZED_PATH = Path(
    "data/processed/sessions/analyzed_sessions.jsonl"
)


def load_jsonl(path):
    records = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                records.append(json.loads(line))

    return records


def normalize_behaviors(values):
    if not values:
        return set()

    return {
        str(value).strip()
        for value in values
        if str(value).strip()
    }


def main():

    print("=" * 75)
    print("BEHAVIOR LABEL VALIDATION")
    print("=" * 75)

    dataset = load_jsonl(DATASET_PATH)
    analyzed = load_jsonl(ANALYZED_PATH)

    print(f"\nValidated dataset : {len(dataset)}")
    print(f"Analyzed sessions : {len(analyzed)}")

    # ---------------------------------------------------------
    # Build analyzer lookup
    # ---------------------------------------------------------

    analyzed_by_id = {}

    for session in analyzed:

        session_id = session.get("session_id")

        if session_id:
            analyzed_by_id[session_id] = session

    print(
        f"Indexed analyzed sessions : "
        f"{len(analyzed_by_id)}"
    )

    # ---------------------------------------------------------
    # Compare labels
    # ---------------------------------------------------------

    exact_matches = 0
    partial_matches = 0
    mismatches = 0
    missing = 0

    mismatch_details = []

    expected_counter = Counter()
    observed_counter = Counter()

    for record in dataset:

        session_id = record["session_id"]

        expected = normalize_behaviors(
            record.get("expected_behaviors", [])
        )

        # benign is a scenario label, not an analyzer behavior
        expected.discard("benign")

        expected_counter.update(expected)

        analyzed_record = analyzed_by_id.get(
            session_id
        )

        if not analyzed_record:

            missing += 1

            mismatch_details.append({
                "session_id": session_id,
                "scenario": record.get("scenario_label"),
                "type": "missing_analyzer_record",
                "expected": sorted(expected),
                "observed": []
            })

            continue

        observed = normalize_behaviors(
            analyzed_record.get("behaviors", [])
        )

        observed_counter.update(observed)

        # -----------------------------------------------------
        # Compare
        # -----------------------------------------------------

        missing_expected = expected - observed
        additional_observed = observed - expected

        if not expected and not observed:

            exact_matches += 1

        elif expected == observed:

            exact_matches += 1

        elif expected.issubset(observed):

            partial_matches += 1

            mismatch_details.append({
                "session_id": session_id,
                "scenario": record.get("scenario_label"),
                "type": "additional_observed_behavior",
                "expected": sorted(expected),
                "observed": sorted(observed),
                "additional": sorted(additional_observed)
            })

        else:

            mismatches += 1

            mismatch_details.append({
                "session_id": session_id,
                "scenario": record.get("scenario_label"),
                "type": "expected_behavior_missing",
                "expected": sorted(expected),
                "observed": sorted(observed),
                "missing": sorted(missing_expected),
                "additional": sorted(additional_observed)
            })

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    print("\n" + "-" * 75)
    print("VALIDATION SUMMARY")
    print("-" * 75)

    print(
        f"Exact matches              : {exact_matches}"
    )

    print(
        f"Partial matches            : {partial_matches}"
    )

    print(
        f"Behavior mismatches        : {mismatches}"
    )

    print(
        f"Missing analyzer records   : {missing}"
    )

    # ---------------------------------------------------------
    # Expected behavior distribution
    # ---------------------------------------------------------

    print("\n" + "-" * 75)
    print("EXPECTED BEHAVIOR DISTRIBUTION")
    print("-" * 75)

    for behavior, count in sorted(
        expected_counter.items()
    ):
        print(
            f"{behavior:30} {count}"
        )

    # ---------------------------------------------------------
    # Observed behavior distribution
    # ---------------------------------------------------------

    print("\n" + "-" * 75)
    print("OBSERVED BEHAVIOR DISTRIBUTION")
    print("-" * 75)

    for behavior, count in sorted(
        observed_counter.items()
    ):
        print(
            f"{behavior:30} {count}"
        )

    # ---------------------------------------------------------
    # Detailed mismatches
    # ---------------------------------------------------------

    print("\n" + "-" * 75)
    print("BEHAVIOR DIFFERENCES")
    print("-" * 75)

    if not mismatch_details:

        print("None")

    else:

        for item in mismatch_details:

            print(
                f"\nSession : {item['session_id']}"
            )

            print(
                f"Scenario: {item['scenario']}"
            )

            print(
                f"Type    : {item['type']}"
            )

            print(
                f"Expected: {item['expected']}"
            )

            print(
                f"Observed: {item['observed']}"
            )

            if "missing" in item:
                print(
                    f"Missing : {item['missing']}"
                )

            if "additional" in item:
                print(
                    f"Extra   : {item['additional']}"
                )

    # ---------------------------------------------------------
    # Final interpretation
    # ---------------------------------------------------------

    print("\n" + "=" * 75)
    print("INTERPRETATION")
    print("=" * 75)

    if missing > 0:

        print(
            "WARNING: Some validated sessions do not have "
            "an analyzer record."
        )

    elif mismatches > 0:

        print(
            "WARNING: Some scenarios contain expected "
            "behaviors that were not observed."
        )

    elif partial_matches > 0:

        print(
            "GOOD: All expected behaviors were observed, "
            "but some sessions contain additional overlapping behaviors."
        )

    else:

        print(
            "GOOD: Expected and observed behaviors match."
        )

    print(
        "\nNote: Additional observed behaviors are not "
        "automatically errors. A single command can legitimately "
        "trigger multiple behavior categories."
    )

    print("=" * 75)


if __name__ == "__main__":
    main()