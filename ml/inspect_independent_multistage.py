from pathlib import Path
import json


EVALUATION_FILE = Path(
    "data/generated/independent_evaluation/evaluation_ml_features.jsonl"
)

PREDICTIONS_FILE = Path(
    "models/lightgbm/independent_evaluation/predictions.jsonl"
)


# ============================================================
# LOAD PREDICTIONS
# ============================================================

predictions = {}

with PREDICTIONS_FILE.open("r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        record = json.loads(line)

        predictions[record["session_id"]] = record


# ============================================================
# LOAD EVALUATION FEATURES
# ============================================================

records = []

with EVALUATION_FILE.open("r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        records.append(json.loads(line))


multi_stage = [
    record
    for record in records
    if record.get("scenario_label") == "multi_stage"
]


print("=" * 80)
print("INDEPENDENT MULTI-STAGE SESSION INSPECTION")
print("=" * 80)

print()
print(f"Total multi-stage sessions: {len(multi_stage)}")


for index, record in enumerate(multi_stage, start=1):

    session_id = record["session_id"]

    prediction = predictions.get(session_id, {})

    predicted = prediction.get(
        "predicted",
        "UNKNOWN"
    )

    actual = prediction.get(
        "actual",
        "multi_stage"
    )

    features = record.get("features", {})

    print()
    print("-" * 80)
    print(f"SESSION {index}")
    print("-" * 80)

    print(f"Session ID : {session_id}")
    print(f"Run ID     : {record.get('run_id')}")
    print(f"Actual     : {actual}")
    print(f"Predicted  : {predicted}")

    print()
    print("Expected behaviors:")

    for behavior in record.get(
        "expected_behaviors",
        []
    ):
        print(f"  - {behavior}")

    print()
    print("Key behavioral features:")

    key_features = [
        "duration_ms",
        "event_count",
        "command_count",
        "unique_command_count",
        "avg_command_length",
        "command_diversity",
        "unique_category_count",
        "transition_count",
        "unique_transition_count",
        "identity_command_count",
        "system_command_count",
        "filesystem_command_count",
        "process_command_count",
        "network_command_count",
        "read_command_count",
        "interpreter_command_count",
        "privilege_command_count",
        "file_modify_command_count",
        "transfer_command_count",
        "persistence_command_count",
    ]

    for feature in key_features:

        value = features.get(feature, 0)

        print(
            f"  {feature:<30} : {value}"
        )


print()
print("=" * 80)
print("INSPECTION COMPLETE")
print("=" * 80)