from __future__ import annotations

import json
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap

from sklearn.model_selection import train_test_split


# ============================================================
# PATHS
# ============================================================

INPUT_PATH = Path(
    "data/generated/ml_training_dataset.jsonl"
)

MODEL_PATH = Path(
    "models/lightgbm/baseline_model.pkl"
)

LABEL_ENCODER_PATH = Path(
    "models/lightgbm/label_encoder.pkl"
)

FEATURES_PATH = Path(
    "models/lightgbm/feature_names.json"
)

OUTPUT_DIR = Path(
    "models/lightgbm/shap"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42
TEST_SIZE = 0.20

EXPECTED_RECORDS = 5040
EXPECTED_FEATURES = 30
EXPECTED_CLASSES = 9

TOP_N_FEATURES = 15


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {INPUT_PATH}"
        )

    records = []

    with INPUT_PATH.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line in f:

            if line.strip():

                records.append(
                    json.loads(line)
                )

    if not records:

        raise ValueError(
            "Dataset is empty."
        )

    rows = []

    for record in records:

        row = {
            "session_id":
                record["session_id"],

            "scenario_label":
                record["scenario_label"],
        }

        row.update(
            record["features"]
        )

        rows.append(row)

    return pd.DataFrame(rows)


# ============================================================
# VALIDATE DATASET
# ============================================================

def validate_dataset(
    df: pd.DataFrame,
    feature_columns,
    label_encoder,
):

    if len(df) != EXPECTED_RECORDS:

        raise ValueError(
            f"Expected {EXPECTED_RECORDS} records, "
            f"found {len(df)}"
        )

    if len(feature_columns) != EXPECTED_FEATURES:

        raise ValueError(
            f"Expected {EXPECTED_FEATURES} model features, "
            f"found {len(feature_columns)}"
        )

    if (
        df["scenario_label"].nunique()
        != EXPECTED_CLASSES
    ):

        raise ValueError(
            f"Expected {EXPECTED_CLASSES} classes, "
            f"found "
            f"{df['scenario_label'].nunique()}"
        )

    # Check every model feature exists.
    missing_features = [
        feature
        for feature in feature_columns
        if feature not in df.columns
    ]

    if missing_features:

        raise ValueError(
            "Dataset is missing model features: "
            f"{missing_features}"
        )

    # Check feature values.
    if (
        df[feature_columns]
        .isnull()
        .any()
        .any()
    ):

        raise ValueError(
            "Dataset contains missing feature values."
        )

    if not np.isfinite(
        df[feature_columns]
        .to_numpy(dtype=float)
    ).all():

        raise ValueError(
            "Dataset contains infinite feature values."
        )

    # Check labels.
    try:

        label_encoder.transform(
            df["scenario_label"]
        )

    except ValueError as exc:

        raise ValueError(
            "Dataset contains labels that are "
            "not present in the trained label encoder."
        ) from exc

    # Check duplicate sessions.
    if df["session_id"].duplicated().any():

        raise ValueError(
            "Duplicate session IDs detected."
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)

    print(
        "LIGHTGBM SHAP ANALYSIS"
    )

    print("=" * 70)

    # --------------------------------------------------------
    # Verify files
    # --------------------------------------------------------

    if not MODEL_PATH.exists():

        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    if not LABEL_ENCODER_PATH.exists():

        raise FileNotFoundError(
            "Label encoder not found: "
            f"{LABEL_ENCODER_PATH}"
        )

    if not FEATURES_PATH.exists():

        raise FileNotFoundError(
            f"Feature list not found: {FEATURES_PATH}"
        )

    # --------------------------------------------------------
    # Load model
    # --------------------------------------------------------

    model = joblib.load(
        MODEL_PATH
    )

    label_encoder = joblib.load(
        LABEL_ENCODER_PATH
    )

    with FEATURES_PATH.open(
        "r",
        encoding="utf-8",
    ) as f:

        feature_columns = json.load(f)

    print(
        "\nModel loaded successfully."
    )

    print(
        f"Features expected by model: "
        f"{len(feature_columns)}"
    )

    print(
        f"Classes expected by model: "
        f"{len(label_encoder.classes_)}"
    )

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    df = load_dataset()

    validate_dataset(
        df,
        feature_columns,
        label_encoder,
    )

    print(
        f"Dataset records: {len(df)}"
    )

    # --------------------------------------------------------
    # Prepare X and y
    # --------------------------------------------------------

    X = df[
        feature_columns
    ].copy()

    y_text = (
        df["scenario_label"]
        .copy()
    )

    y = label_encoder.transform(
        y_text
    )

    # --------------------------------------------------------
    # Recreate exact baseline split
    # --------------------------------------------------------

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = train_test_split(

        X,
        y,

        test_size=TEST_SIZE,

        random_state=RANDOM_STATE,

        stratify=y,
    )

    print(
        "\nBaseline split recreated."
    )

    print(
        f"Training samples: "
        f"{len(X_train)}"
    )

    print(
        f"Test samples    : "
        f"{len(X_test)}"
    )

    # --------------------------------------------------------
    # Verify feature order
    # --------------------------------------------------------

    if (
        list(X_test.columns)
        != feature_columns
    ):

        raise ValueError(
            "Feature order does not match "
            "the trained model."
        )

    # --------------------------------------------------------
    # Verify model dimensions
    # --------------------------------------------------------

    if (
        model.n_features_in_
        != len(feature_columns)
    ):

        raise ValueError(
            "Model feature count does not "
            "match feature schema."
        )

    # --------------------------------------------------------
    # Create SHAP explainer
    # --------------------------------------------------------

    print(
        "\nCreating SHAP TreeExplainer..."
    )

    explainer = shap.TreeExplainer(
        model
    )

    print(
        "Calculating SHAP values..."
    )

    shap_values = (
        explainer.shap_values(
            X_test
        )
    )

    print(
        "SHAP calculation complete."
    )

    # --------------------------------------------------------
    # Handle SHAP output format
    # --------------------------------------------------------

    if isinstance(
        shap_values,
        list,
    ):

        shap_array = np.stack(
            shap_values,
            axis=-1,
        )

    else:

        shap_array = np.asarray(
            shap_values
        )

        if shap_array.ndim != 3:

            raise ValueError(
                "Unexpected SHAP output shape: "
                f"{shap_array.shape}"
            )

    print(
        f"SHAP array shape: "
        f"{shap_array.shape}"
    )

    # Expected:
    #
    # samples × features × classes

    n_samples = (
        shap_array.shape[0]
    )

    n_features = (
        shap_array.shape[1]
    )

    n_classes = (
        shap_array.shape[2]
    )

    if (
        n_features
        != len(feature_columns)
    ):

        raise ValueError(
            "SHAP feature dimension does not "
            "match feature list."
        )

    class_names = (
        label_encoder
        .classes_
        .tolist()
    )

    if (
        n_classes
        != len(class_names)
    ):

        raise ValueError(
            "SHAP class dimension does not "
            "match label encoder."
        )

    # --------------------------------------------------------
    # Output directory
    # --------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Global SHAP importance
    # --------------------------------------------------------

    global_importance = np.mean(
        np.abs(shap_array),
        axis=(0, 2),
    )

    global_df = pd.DataFrame(
        {
            "feature":
                feature_columns,

            "mean_absolute_shap":
                global_importance,
        }
    )

    global_df = (
        global_df
        .sort_values(
            "mean_absolute_shap",
            ascending=False,
        )
        .reset_index(drop=True)
    )

    # --------------------------------------------------------
    # Print global importance
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "GLOBAL SHAP FEATURE IMPORTANCE"
    )

    print(
        "=" * 70
    )

    print(
        global_df
        .head(TOP_N_FEATURES)
        .to_string(index=False)
    )

    # --------------------------------------------------------
    # Save global importance
    # --------------------------------------------------------

    global_df.to_csv(
        OUTPUT_DIR /
        "global_shap_importance.csv",
        index=False,
    )

    # --------------------------------------------------------
    # Global SHAP bar plot
    # --------------------------------------------------------

    plt.figure(
        figsize=(10, 7)
    )

    top_df = (
        global_df
        .head(TOP_N_FEATURES)
    )

    plt.barh(
        top_df["feature"][::-1],
        top_df[
            "mean_absolute_shap"
        ][::-1],
    )

    plt.xlabel(
        "Mean |SHAP value|"
    )

    plt.ylabel(
        "Feature"
    )

    plt.title(
        "Global SHAP Feature Importance"
    )

    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR /
        "global_shap_importance.png",
        dpi=200,
        bbox_inches="tight",
    )

    plt.close()

    # --------------------------------------------------------
    # SHAP summary plot
    # --------------------------------------------------------

    mean_abs_class_shap = (
        np.mean(
            np.abs(shap_array),
            axis=2,
        )
    )

    plt.figure(
        figsize=(10, 7)
    )

    shap.summary_plot(
        mean_abs_class_shap,
        X_test,
        feature_names=feature_columns,
        max_display=TOP_N_FEATURES,
        show=False,
    )

    plt.title(
        "SHAP Summary - Overall Feature Influence"
    )

    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR /
        "shap_summary.png",
        dpi=200,
        bbox_inches="tight",
    )

    plt.close()

    # --------------------------------------------------------
    # Per-class SHAP analysis
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "PER-CLASS SHAP IMPORTANCE"
    )

    print(
        "=" * 70
    )

    per_class_results = {}

    for class_index, class_name in enumerate(
        class_names
    ):

        class_values = (
            shap_array[
                :,
                :,
                class_index,
            ]
        )

        class_importance = (
            np.mean(
                np.abs(
                    class_values
                ),
                axis=0,
            )
        )

        class_df = pd.DataFrame(
            {
                "feature":
                    feature_columns,

                "mean_absolute_shap":
                    class_importance,
            }
        )

        class_df = (
            class_df
            .sort_values(
                "mean_absolute_shap",
                ascending=False,
            )
            .reset_index(drop=True)
        )

        per_class_results[
            class_name
        ] = {}

        for _, row in (
            class_df.iterrows()
        ):

            per_class_results[
                class_name
            ][
                row["feature"]
            ] = float(
                row[
                    "mean_absolute_shap"
                ]
            )

        print(
            f"\n{class_name}"
        )

        print(
            class_df
            .head(TOP_N_FEATURES)
            .to_string(index=False)
        )

        # ----------------------------------------------------
        # Save class CSV
        # ----------------------------------------------------

        safe_name = (
            class_name
            .replace(" ", "_")
            .replace("/", "_")
        )

        class_df.to_csv(
            OUTPUT_DIR /
            f"shap_{safe_name}.csv",
            index=False,
        )

        # ----------------------------------------------------
        # Save class bar plot
        # ----------------------------------------------------

        top_class_df = (
            class_df
            .head(TOP_N_FEATURES)
        )

        plt.figure(
            figsize=(10, 7)
        )

        plt.barh(
            top_class_df["feature"][::-1],
            top_class_df[
                "mean_absolute_shap"
            ][::-1],
        )

        plt.xlabel(
            "Mean |SHAP value|"
        )

        plt.ylabel(
            "Feature"
        )

        plt.title(
            f"SHAP Importance - {class_name}"
        )

        plt.tight_layout()

        plt.savefig(
            OUTPUT_DIR /
            f"shap_{safe_name}.png",
            dpi=200,
            bbox_inches="tight",
        )

        plt.close()

    # --------------------------------------------------------
    # Save JSON summary
    # --------------------------------------------------------

    summary = {

        "dataset_records":
            len(df),

        "test_samples":
            n_samples,

        "features":
            feature_columns,

        "classes":
            class_names,

        "random_state":
            RANDOM_STATE,

        "test_size":
            TEST_SIZE,

        "global_importance": {

            row["feature"]:
                float(
                    row[
                        "mean_absolute_shap"
                    ]
                )

            for _, row
            in global_df.iterrows()
        },

        "per_class_importance":
            per_class_results,
    }

    with (
        OUTPUT_DIR /
        "shap_analysis_summary.json"
    ).open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            summary,
            f,
            indent=2,
        )

    # --------------------------------------------------------
    # Final output
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "SHAP OUTPUTS"
    )

    print(
        "=" * 70
    )

    print(
        f"Output directory: "
        f"{OUTPUT_DIR}"
    )

    print(
        "\nGenerated:"
    )

    print(
        "  - global_shap_importance.csv"
    )

    print(
        "  - global_shap_importance.png"
    )

    print(
        "  - shap_summary.png"
    )

    print(
        "  - shap_<class>.csv"
    )

    print(
        "  - shap_<class>.png"
    )

    print(
        "  - shap_analysis_summary.json"
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "STATUS: SHAP ANALYSIS COMPLETE"
    )

    print(
        "=" * 70
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
