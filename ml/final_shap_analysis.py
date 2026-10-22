from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
import shap
import matplotlib.pyplot as plt


# ============================================================
# PATHS
# ============================================================

MODEL_FILE = Path(
    "models/lightgbm/baseline_model.pkl"
)

FEATURE_NAMES_FILE = Path(
    "models/lightgbm/feature_names.json"
)

DATASET_FILE = Path(
    "data/generated/ml_training_dataset.jsonl"
)

OUTPUT_DIR = Path(
    "models/lightgbm/final_shap"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 70)
print("FINAL LIGHTGBM SHAP ANALYSIS")
print("=" * 70)

print()
print("Loading model...")

model = joblib.load(MODEL_FILE)

print("Model loaded successfully.")


# ============================================================
# LOAD FEATURE NAMES
# ============================================================

with FEATURE_NAMES_FILE.open(
    "r",
    encoding="utf-8"
) as f:

    feature_names = json.load(f)


print(
    f"Expected features: {len(feature_names)}"
)


# ============================================================
# LOAD DATASET
# ============================================================

print()
print("Loading training dataset...")

records = []

with DATASET_FILE.open(
    "r",
    encoding="utf-8"
) as f:

    for line in f:

        line = line.strip()

        if not line:
            continue

        records.append(
            json.loads(line)
        )


print(
    f"Dataset records: {len(records)}"
)


# ============================================================
# BUILD FEATURE MATRIX
# ============================================================

X_rows = []
labels = []

for record in records:

    features = record["features"]

    X_rows.append(
        [
            features[name]
            for name in feature_names
        ]
    )

    labels.append(
        record["scenario_label"]
    )


X = pd.DataFrame(
    X_rows,
    columns=feature_names
)


print(
    f"X shape: {X.shape}"
)


# ============================================================
# VALIDATION
# ============================================================

if list(X.columns) != feature_names:

    raise ValueError(
        "Feature ordering does not match model feature names."
    )


if X.isnull().any().any():

    raise ValueError(
        "Dataset contains NaN values."
    )


if not np.isfinite(X.to_numpy()).all():

    raise ValueError(
        "Dataset contains infinite values."
    )


# ============================================================
# CREATE SHAP EXPLAINER
# ============================================================

print()
print("Creating SHAP TreeExplainer...")

explainer = shap.TreeExplainer(model)

print("Explainer created.")


# ============================================================
# CALCULATE SHAP VALUES
# ============================================================

print()
print("Calculating SHAP values...")

shap_values = explainer.shap_values(X)

print("SHAP calculation complete.")


# ============================================================
# HANDLE SHAP OUTPUT FORMAT
# ============================================================

if isinstance(shap_values, list):

    # Older SHAP format:
    # list[class] -> samples x features

    shap_array = np.stack(
        shap_values,
        axis=-1
    )

else:

    shap_array = np.asarray(
        shap_values
    )


print(
    f"SHAP array shape: {shap_array.shape}"
)


# Expected:
# samples x features x classes

if shap_array.ndim != 3:

    raise ValueError(
        f"Unexpected SHAP shape: {shap_array.shape}"
    )


n_samples = shap_array.shape[0]
n_features = shap_array.shape[1]
n_classes = shap_array.shape[2]


if n_features != len(feature_names):

    raise ValueError(
        "SHAP feature count does not match feature names."
    )


# ============================================================
# CLASS NAMES
# ============================================================

if hasattr(model, "classes_"):

    class_names = [
        str(x)
        for x in model.classes_
    ]

else:

    class_names = [
        str(x)
        for x in range(n_classes)
    ]


print()
print("Classes:")

for index, name in enumerate(class_names):

    print(
        f"  {index}: {name}"
    )


# ============================================================
# GLOBAL FEATURE IMPORTANCE
# ============================================================

print()
print("=" * 70)
print("GLOBAL SHAP FEATURE IMPORTANCE")
print("=" * 70)


global_importance = np.mean(
    np.abs(shap_array),
    axis=(0, 2)
)


global_df = pd.DataFrame(
    {
        "feature": feature_names,
        "mean_abs_shap": global_importance
    }
).sort_values(
    "mean_abs_shap",
    ascending=False
)


print()

print(
    global_df.to_string(
        index=False
    )
)


global_df.to_csv(
    OUTPUT_DIR / "global_feature_importance.csv",
    index=False
)


# ============================================================
# GLOBAL BAR PLOT
# ============================================================

plt.figure(
    figsize=(10, 10)
)

top_global = global_df.head(20).sort_values(
    "mean_abs_shap"
)

plt.barh(
    top_global["feature"],
    top_global["mean_abs_shap"]
)

plt.xlabel(
    "Mean Absolute SHAP Value"
)

plt.ylabel(
    "Feature"
)

plt.title(
    "Global LightGBM Feature Importance using SHAP"
)

plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "global_feature_importance.png",
    dpi=300
)

plt.close()


# ============================================================
# CLASS-SPECIFIC IMPORTANCE
# ============================================================

class_results = {}


print()
print("=" * 70)
print("CLASS-SPECIFIC SHAP IMPORTANCE")
print("=" * 70)


for class_index, class_name in enumerate(class_names):

    class_values = shap_array[
        :,
        :,
        class_index
    ]

    importance = np.mean(
        np.abs(class_values),
        axis=0
    )

    class_df = pd.DataFrame(
        {
            "feature": feature_names,
            "mean_abs_shap": importance
        }
    ).sort_values(
        "mean_abs_shap",
        ascending=False
    )

    class_results[class_name] = (
        class_df
        .head(15)
        .to_dict(
            orient="records"
        )
    )

    print()
    print(
        f"{class_name}"
    )
    print(
        "-" * len(class_name)
    )

    for _, row in class_df.head(10).iterrows():

        print(
            f"{row['feature']:<35} "
            f"{row['mean_abs_shap']:.6f}"
        )

    class_df.to_csv(
        OUTPUT_DIR /
        f"{class_name}_shap_importance.csv",
        index=False
    )


# ============================================================
# SAVE CLASS SUMMARY
# ============================================================

with (
    OUTPUT_DIR /
    "class_shap_summary.json"
).open(
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        class_results,
        f,
        indent=2
    )


# ============================================================
# SAVE COMPLETE GLOBAL SUMMARY
# ============================================================

summary = {
    "dataset_records": n_samples,
    "feature_count": n_features,
    "class_count": n_classes,
    "features": feature_names,
    "classes": class_names,
    "global_importance": (
        global_df
        .to_dict(
            orient="records"
        )
    )
}


with (
    OUTPUT_DIR /
    "shap_summary.json"
).open(
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        summary,
        f,
        indent=2
    )


# ============================================================
# FINAL STATUS
# ============================================================

print()
print("=" * 70)
print("FINAL SHAP ANALYSIS COMPLETE")
print("=" * 70)

print()
print(
    f"Output directory: {OUTPUT_DIR}"
)

print()
print(
    "Files generated:"
)

print(
    "  global_feature_importance.csv"
)

print(
    "  global_feature_importance.png"
)

print(
    "  class_shap_summary.json"
)

print(
    "  shap_summary.json"
)

print()
print("STATUS: PASS")