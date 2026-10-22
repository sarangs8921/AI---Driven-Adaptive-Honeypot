from pathlib import Path
import json

import pandas as pd


# ============================================================
# PATHS
# ============================================================

SHAP_DIR = Path(
    "models/lightgbm/final_shap"
)

OUTPUT_DIR = SHAP_DIR / "final_report"

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# CLASS MAPPING
# ============================================================

CLASS_NAMES = {
    "0": "benign",
    "1": "credential_access",
    "2": "execution",
    "3": "file_discovery",
    "4": "file_modification",
    "5": "multi_stage",
    "6": "persistence",
    "7": "privilege_activity",
    "8": "reconnaissance",
}


# ============================================================
# LOAD GLOBAL SHAP
# ============================================================

GLOBAL_FILE = (
    SHAP_DIR /
    "global_feature_importance.csv"
)

if not GLOBAL_FILE.exists():
    raise FileNotFoundError(
        f"Missing file: {GLOBAL_FILE}"
    )


global_df = pd.read_csv(
    GLOBAL_FILE
)

global_df = global_df.sort_values(
    "mean_abs_shap",
    ascending=False
)


# ============================================================
# GLOBAL TOP FEATURES
# ============================================================

global_top = []

for rank, (_, row) in enumerate(
    global_df.head(15).iterrows(),
    start=1
):

    global_top.append(
        {
            "rank": rank,
            "feature": row["feature"],
            "mean_abs_shap": float(
                row["mean_abs_shap"]
            ),
        }
    )


# ============================================================
# CLASS-SPECIFIC REPORT
# ============================================================

class_report = {}

print("=" * 75)
print("FINAL HUMAN-READABLE SHAP REPORT")
print("=" * 75)

print()
print("GLOBAL TOP FEATURES")
print("-" * 75)

for item in global_top:

    print(
        f"{item['rank']:>2}. "
        f"{item['feature']:<35} "
        f"{item['mean_abs_shap']:.6f}"
    )


print()
print("=" * 75)
print("CLASS-SPECIFIC SHAP IMPORTANCE")
print("=" * 75)


for class_id, class_name in CLASS_NAMES.items():

    source_file = (
        SHAP_DIR /
        f"{class_id}_shap_importance.csv"
    )

    # Current SHAP script creates files using
    # numeric class IDs only if model classes are numeric.
    #
    # If those files don't exist, use the human-readable
    # filenames created by the current SHAP script.

    if not source_file.exists():

        source_file = (
            SHAP_DIR /
            f"{class_name}_shap_importance.csv"
        )

    if not source_file.exists():

        print()
        print(
            f"WARNING: No SHAP CSV found for "
            f"{class_name}"
        )

        continue

    class_df = pd.read_csv(
        source_file
    )

    class_df = class_df.sort_values(
        "mean_abs_shap",
        ascending=False
    )

    top_features = []

    for rank, (_, row) in enumerate(
        class_df.head(15).iterrows(),
        start=1
    ):

        top_features.append(
            {
                "rank": rank,
                "feature": row["feature"],
                "mean_abs_shap": float(
                    row["mean_abs_shap"]
                ),
            }
        )

    class_report[class_name] = {
        "class_id": int(class_id),
        "top_features": top_features,
    }

    print()
    print(
        f"{class_name.upper()}"
    )
    print("-" * 75)

    for item in top_features[:10]:

        print(
            f"{item['rank']:>2}. "
            f"{item['feature']:<35} "
            f"{item['mean_abs_shap']:.6f}"
        )


# ============================================================
# BUILD FINAL JSON
# ============================================================

final_report = {
    "model": "LightGBM",
    "dataset": {
        "records": 5040,
        "features": 30,
        "classes": 9,
    },
    "global_top_features": global_top,
    "classes": class_report,
}


# ============================================================
# SAVE JSON
# ============================================================

JSON_FILE = (
    OUTPUT_DIR /
    "final_shap_report.json"
)

with JSON_FILE.open(
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        final_report,
        f,
        indent=2
    )


# ============================================================
# SAVE MARKDOWN REPORT
# ============================================================

MD_FILE = (
    OUTPUT_DIR /
    "final_shap_report.md"
)

with MD_FILE.open(
    "w",
    encoding="utf-8"
) as f:

    f.write(
        "# Final LightGBM SHAP Report\n\n"
    )

    f.write(
        "## Model Summary\n\n"
    )

    f.write(
        "- Model: LightGBM\n"
        "- Dataset: 5,040 Cowrie sessions\n"
        "- Features: 30\n"
        "- Classes: 9\n\n"
    )

    f.write(
        "## Global Feature Importance\n\n"
    )

    f.write(
        "| Rank | Feature | Mean Absolute SHAP |\n"
    )

    f.write(
        "|---:|---|---:|\n"
    )

    for item in global_top:

        f.write(
            f"| {item['rank']} | "
            f"{item['feature']} | "
            f"{item['mean_abs_shap']:.6f} |\n"
        )

    f.write("\n")

    f.write(
        "## Class-Specific Feature Importance\n\n"
    )

    for class_name, data in class_report.items():

        f.write(
            f"### {class_name}\n\n"
        )

        f.write(
            "| Rank | Feature | Mean Absolute SHAP |\n"
        )

        f.write(
            "|---:|---|---:|\n"
        )

        for item in data["top_features"]:

            f.write(
                f"| {item['rank']} | "
                f"{item['feature']} | "
                f"{item['mean_abs_shap']:.6f} |\n"
            )

        f.write("\n")


# ============================================================
# FINAL STATUS
# ============================================================

print()
print("=" * 75)
print("FINAL SHAP REPORT COMPLETE")
print("=" * 75)

print()
print(f"JSON report     : {JSON_FILE}")
print(f"Markdown report : {MD_FILE}")

print()
print("STATUS: PASS")