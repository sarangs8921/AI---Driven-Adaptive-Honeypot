from pathlib import Path
import json
from collections import Counter

import pandas as pd


# ============================================================
# PATHS
# ============================================================

PREDICTIONS_FILE = Path(
    "models/lightgbm/independent_evaluation/predictions.jsonl"
)

OUTPUT_DIR = Path(
    "models/lightgbm/independent_evaluation/error_analysis"
)

ERRORS_FILE = OUTPUT_DIR / "misclassified_sessions.jsonl"
SUMMARY_FILE = OUTPUT_DIR / "error_summary.json"


# ============================================================
# SETUP
# ============================================================

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# LOAD PREDICTIONS
# ============================================================

if not PREDICTIONS_FILE.exists():
    raise FileNotFoundError(
        f"Prediction file not found: {PREDICTIONS_FILE}"
    )


records = []

with PREDICTIONS_FILE.open("r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        records.append(json.loads(line))


if not records:
    raise ValueError("No prediction records found.")


# ============================================================
# VALIDATE PREDICTION FORMAT
# ============================================================

required_fields = {
    "session_id",
    "run_id",
    "actual",
    "predicted",
}

for index, record in enumerate(records):

    missing = required_fields - set(record.keys())

    if missing:
        raise ValueError(
            f"Record {index} is missing fields: {sorted(missing)}"
        )


# ============================================================
# BUILD DATAFRAME
# ============================================================

rows = []

for record in records:

    actual = record["actual"]
    predicted = record["predicted"]

    rows.append(
        {
            "session_id": record["session_id"],
            "run_id": record["run_id"],
            "actual": actual,
            "predicted": predicted,
            "correct": actual == predicted,
        }
    )


df = pd.DataFrame(rows)


# ============================================================
# BASIC SUMMARY
# ============================================================

total = len(df)
correct = int(df["correct"].sum())
incorrect = total - correct

accuracy = correct / total if total else 0.0


print("=" * 70)
print("INDEPENDENT LIGHTGBM ERROR ANALYSIS")
print("=" * 70)

print()
print(f"Total evaluation sessions : {total}")
print(f"Correct predictions       : {correct}")
print(f"Incorrect predictions     : {incorrect}")
print(f"Accuracy                  : {accuracy:.4f}")


# ============================================================
# PER-CLASS ERROR ANALYSIS
# ============================================================

print()
print("=" * 70)
print("PER-CLASS ERROR ANALYSIS")
print("=" * 70)

class_summary = {}

classes = sorted(df["actual"].unique())

for actual_class in classes:

    class_df = df[df["actual"] == actual_class]

    support = len(class_df)
    correct_count = int(class_df["correct"].sum())
    error_count = support - correct_count

    recall = correct_count / support if support else 0.0

    predicted_distribution = Counter(
        class_df["predicted"]
    )

    class_summary[actual_class] = {
        "support": support,
        "correct": correct_count,
        "errors": error_count,
        "recall": recall,
        "predicted_as": dict(predicted_distribution),
    }

    print()
    print(actual_class)
    print(f"  Support       : {support}")
    print(f"  Correct       : {correct_count}")
    print(f"  Errors        : {error_count}")
    print(f"  Recall        : {recall:.4f}")

    print("  Predictions:")

    for predicted_class, count in predicted_distribution.most_common():

        print(
            f"    {predicted_class:<22} : {count}"
        )


# ============================================================
# CONFUSION PAIRS
# ============================================================

errors_df = df[~df["correct"]].copy()

confusion_pairs = Counter(
    zip(
        errors_df["actual"],
        errors_df["predicted"],
    )
)


print()
print("=" * 70)
print("TOP CONFUSION PAIRS")
print("=" * 70)

if confusion_pairs:

    for (actual, predicted), count in confusion_pairs.most_common():

        print(
            f"{actual:<22} -> {predicted:<22} : {count}"
        )

else:

    print("No misclassified sessions.")


# ============================================================
# MULTI-STAGE ANALYSIS
# ============================================================

print()
print("=" * 70)
print("MULTI-STAGE ERROR ANALYSIS")
print("=" * 70)

multi_stage = df[
    df["actual"] == "multi_stage"
]

if len(multi_stage):

    multi_correct = int(
        multi_stage["correct"].sum()
    )

    multi_errors = len(multi_stage) - multi_correct

    print()
    print(
        f"Total multi-stage sessions : {len(multi_stage)}"
    )

    print(
        f"Correctly classified       : {multi_correct}"
    )

    print(
        f"Misclassified              : {multi_errors}"
    )

    print(
        f"Recall                     : "
        f"{multi_correct / len(multi_stage):.4f}"
    )

    print()
    print("Multi-stage predictions:")

    for predicted_class, count in Counter(
        multi_stage["predicted"]
    ).most_common():

        print(
            f"  {predicted_class:<22} : {count}"
        )


# ============================================================
# SAVE MISCLASSIFIED SESSIONS
# ============================================================

with ERRORS_FILE.open("w", encoding="utf-8") as f:

    for _, row in errors_df.iterrows():

        record = {
            "session_id": row["session_id"],
            "run_id": row["run_id"],
            "actual": row["actual"],
            "predicted": row["predicted"],
        }

        f.write(
            json.dumps(record)
            + "\n"
        )


# ============================================================
# SAVE SUMMARY
# ============================================================

summary = {
    "total_sessions": total,
    "correct_predictions": correct,
    "incorrect_predictions": incorrect,
    "accuracy": accuracy,
    "class_summary": class_summary,
    "confusion_pairs": [
        {
            "actual": actual,
            "predicted": predicted,
            "count": count,
        }
        for (actual, predicted), count
        in confusion_pairs.most_common()
    ],
}


with SUMMARY_FILE.open("w", encoding="utf-8") as f:

    json.dump(
        summary,
        f,
        indent=2,
    )


# ============================================================
# FINAL STATUS
# ============================================================

print()
print("=" * 70)
print("ERROR ANALYSIS COMPLETE")
print("=" * 70)

print()
print(f"Misclassified sessions : {ERRORS_FILE}")
print(f"Summary                : {SUMMARY_FILE}")

print()
print("STATUS: PASS")