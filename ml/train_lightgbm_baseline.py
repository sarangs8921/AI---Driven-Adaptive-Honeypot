from __future__ import annotations

import json
from pathlib import Path

import joblib
import lightgbm as lgb
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


# ============================================================
# PATHS
# ============================================================

INPUT_PATH = Path(
    "data/generated/ml_training_dataset.jsonl"
)

MODEL_DIR = Path(
    "models/lightgbm"
)

MODEL_PATH = (
    MODEL_DIR /
    "baseline_model.pkl"
)

LABEL_ENCODER_PATH = (
    MODEL_DIR /
    "label_encoder.pkl"
)

FEATURES_PATH = (
    MODEL_DIR /
    "feature_names.json"
)

METRICS_PATH = (
    MODEL_DIR /
    "baseline_metrics.json"
)

CONFUSION_MATRIX_PATH = (
    MODEL_DIR /
    "baseline_confusion_matrix.png"
)

FEATURE_IMPORTANCE_PATH = (
    MODEL_DIR /
    "baseline_feature_importance.png"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

TEST_SIZE = 0.20

EXPECTED_RECORDS = 5040

EXPECTED_FEATURES = 30

EXPECTED_CLASSES = 9


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset() -> pd.DataFrame:

    if not INPUT_PATH.exists():

        raise FileNotFoundError(
            f"Training dataset not found: "
            f"{INPUT_PATH}"
        )

    records = []

    with INPUT_PATH.open(
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            if line.strip():

                records.append(
                    json.loads(line)
                )

    if not records:

        raise ValueError(
            "Training dataset is empty."
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
    df: pd.DataFrame
):

    required_columns = {
        "session_id",
        "scenario_label",
    }

    missing = (
        required_columns
        - set(df.columns)
    )

    if missing:

        raise ValueError(
            f"Missing required columns: "
            f"{sorted(missing)}"
        )

    feature_columns = [
        column
        for column in df.columns
        if column not in {
            "session_id",
            "scenario_label",
        }
    ]

    # --------------------------------------------------------
    # Current dataset validation
    # --------------------------------------------------------

    if len(df) != EXPECTED_RECORDS:

        raise ValueError(
            f"Expected {EXPECTED_RECORDS} records, "
            f"found {len(df)}"
        )

    if len(feature_columns) != EXPECTED_FEATURES:

        raise ValueError(
            f"Expected {EXPECTED_FEATURES} ML features, "
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

    # --------------------------------------------------------
    # Missing values
    # --------------------------------------------------------

    if (
        df[feature_columns]
        .isnull()
        .any()
        .any()
    ):

        raise ValueError(
            "Dataset contains missing feature values."
        )

    # --------------------------------------------------------
    # Infinite values
    # --------------------------------------------------------

    if not np.isfinite(
        df[feature_columns]
        .to_numpy(dtype=float)
    ).all():

        raise ValueError(
            "Dataset contains infinite feature values."
        )

    # --------------------------------------------------------
    # Missing labels
    # --------------------------------------------------------

    if (
        df["scenario_label"]
        .isnull()
        .any()
    ):

        raise ValueError(
            "Dataset contains missing scenario labels."
        )

    # --------------------------------------------------------
    # Duplicate sessions
    # --------------------------------------------------------

    if df["session_id"].duplicated().any():

        duplicates = (
            df.loc[
                df["session_id"].duplicated(),
                "session_id",
            ]
            .tolist()
        )

        raise ValueError(
            "Duplicate session IDs detected: "
            f"{duplicates}"
        )

    # --------------------------------------------------------
    # Validate every class has 56 sessions
    # --------------------------------------------------------

    class_counts = (
        df["scenario_label"]
        .value_counts()
    )

    if not (
        class_counts == 560
    ).all():

        raise ValueError(
            "Dataset is expected to contain "
            "560 sessions per class.\n"
            f"Distribution:\n{class_counts}"
        )

    return feature_columns


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("LIGHTGBM BASELINE TRAINING")
    print("=" * 70)

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    df = load_dataset()

    print("\nDataset:")
    print(
        f"  Records : {len(df)}"
    )

    feature_columns = (
        validate_dataset(df)
    )

    print(
        f"  Features: "
        f"{len(feature_columns)}"
    )

    print(
        f"  Classes : "
        f"{df['scenario_label'].nunique()}"
    )

    # --------------------------------------------------------
    # Class distribution
    # --------------------------------------------------------

    print("\nClass distribution:")

    class_distribution = (
        df["scenario_label"]
        .value_counts()
        .sort_index()
    )

    for label, count in (
        class_distribution.items()
    ):

        print(
            f"  {label:25s}: "
            f"{count}"
        )

    # --------------------------------------------------------
    # Prepare X and y
    # --------------------------------------------------------

    X = (
        df[feature_columns]
        .copy()
    )

    y_text = (
        df["scenario_label"]
        .copy()
    )

    # --------------------------------------------------------
    # Encode labels
    # --------------------------------------------------------

    label_encoder = (
        LabelEncoder()
    )

    y = label_encoder.fit_transform(
        y_text
    )

    class_names = (
        label_encoder.classes_
        .tolist()
    )

    print("\nEncoded classes:")

    for index, name in enumerate(
        class_names
    ):

        print(
            f"  {index}: {name}"
        )

    # --------------------------------------------------------
    # Stratified train/test split
    # --------------------------------------------------------

    print(
        "\nCreating stratified "
        "train/test split..."
    )

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
        f"  Training samples: "
        f"{len(X_train)}"
    )

    print(
        f"  Test samples    : "
        f"{len(X_test)}"
    )

    # --------------------------------------------------------
    # Check split
    # --------------------------------------------------------

    train_counts = np.bincount(
        y_train,
        minlength=len(class_names)
    )

    test_counts = np.bincount(
        y_test,
        minlength=len(class_names)
    )

    print("\nSplit distribution:")

    for index, name in enumerate(
        class_names
    ):

        print(
            f"  {name:25s}: "
            f"train={train_counts[index]:2d}, "
            f"test={test_counts[index]:2d}"
        )

    # --------------------------------------------------------
    # Create LightGBM model
    # --------------------------------------------------------

    print(
        "\nTraining LightGBM..."
    )

    model = lgb.LGBMClassifier(

        objective="multiclass",

        num_class=len(
            class_names
        ),

        n_estimators=150,

        learning_rate=0.05,

        num_leaves=15,

        max_depth=-1,

        min_child_samples=5,

        subsample=0.9,

        colsample_bytree=0.9,

        reg_alpha=0.1,

        reg_lambda=0.1,

        random_state=RANDOM_STATE,

        n_jobs=-1,

        verbosity=-1,
    )

    model.fit(
        X_train,
        y_train,
    )

    print(
        "Training complete."
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    print(
        "\nGenerating predictions..."
    )

    y_pred = model.predict(
        X_test
    )

    y_pred = (
        np.asarray(y_pred)
        .astype(int)
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred,
    )

    macro_precision = (
        precision_score(
            y_test,
            y_pred,
            average="macro",
            zero_division=0,
        )
    )

    macro_recall = (
        recall_score(
            y_test,
            y_pred,
            average="macro",
            zero_division=0,
        )
    )

    macro_f1 = f1_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0,
    )

    weighted_f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0,
    )

    micro_f1 = f1_score(
        y_test,
        y_pred,
        average="micro",
        zero_division=0,
    )

    # --------------------------------------------------------
    # Overall metrics
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "OVERALL METRICS"
    )

    print(
        "=" * 70
    )

    print(
        f"Accuracy          : "
        f"{accuracy:.4f}"
    )

    print(
        f"Macro Precision   : "
        f"{macro_precision:.4f}"
    )

    print(
        f"Macro Recall      : "
        f"{macro_recall:.4f}"
    )

    print(
        f"Macro F1          : "
        f"{macro_f1:.4f}"
    )

    print(
        f"Weighted F1       : "
        f"{weighted_f1:.4f}"
    )

    print(
        f"Micro F1          : "
        f"{micro_f1:.4f}"
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    report = classification_report(

        y_test,

        y_pred,

        labels=np.arange(
            len(class_names)
        ),

        target_names=class_names,

        output_dict=True,

        zero_division=0,
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "PER-CLASS METRICS"
    )

    print(
        "=" * 70
    )

    print(
        classification_report(

            y_test,

            y_pred,

            labels=np.arange(
                len(class_names)
            ),

            target_names=class_names,

            zero_division=0,
        )
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    cm = confusion_matrix(

        y_test,

        y_pred,

        labels=np.arange(
            len(class_names)
        ),
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "CONFUSION MATRIX"
    )

    print(
        "=" * 70
    )

    print(cm)

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    importance = (
        model.feature_importances_
    )

    feature_importance = (
        pd.DataFrame(
            {
                "feature":
                    feature_columns,

                "importance":
                    importance,
            }
        )
        .sort_values(
            "importance",
            ascending=False,
        )
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "FEATURE IMPORTANCE"
    )

    print(
        "=" * 70
    )

    print(
        feature_importance
        .to_string(index=False)
    )

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    joblib.dump(
        model,
        MODEL_PATH,
    )

    joblib.dump(
        label_encoder,
        LABEL_ENCODER_PATH,
    )

    with FEATURES_PATH.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            feature_columns,
            f,
            indent=2,
        )

    # --------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------

    metrics = {

        "dataset": {

            "records":
                len(df),

            "training_records":
                len(X_train),

            "test_records":
                len(X_test),

            "features":
                len(feature_columns),

            "classes":
                class_names,

            "random_state":
                RANDOM_STATE,

            "test_size":
                TEST_SIZE,
        },

        "overall": {

            "accuracy":
                float(accuracy),

            "macro_precision":
                float(
                    macro_precision
                ),

            "macro_recall":
                float(
                    macro_recall
                ),

            "macro_f1":
                float(
                    macro_f1
                ),

            "weighted_f1":
                float(
                    weighted_f1
                ),

            "micro_f1":
                float(
                    micro_f1
                ),
        },

        "classification_report":
            report,

        "confusion_matrix":
            cm.tolist(),

        "feature_importance": {

            row["feature"]:
                float(row["importance"])

            for _, row
            in feature_importance.iterrows()
        },
    }

    with METRICS_PATH.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            metrics,
            f,
            indent=2,
        )

    # --------------------------------------------------------
    # Save confusion matrix figure
    # --------------------------------------------------------

    plt.figure(
        figsize=(10, 8)
    )

    plt.imshow(
        cm,
        interpolation="nearest",
    )

    plt.title(
        "LightGBM Baseline Confusion Matrix"
    )

    plt.colorbar()

    tick_marks = np.arange(
        len(class_names)
    )

    plt.xticks(
        tick_marks,
        class_names,
        rotation=45,
        ha="right",
    )

    plt.yticks(
        tick_marks,
        class_names,
    )

    plt.xlabel(
        "Predicted Label"
    )

    plt.ylabel(
        "True Label"
    )

    plt.tight_layout()

    plt.savefig(
        CONFUSION_MATRIX_PATH,
        dpi=200,
        bbox_inches="tight",
    )

    plt.close()

    # --------------------------------------------------------
    # Save feature importance figure
    # --------------------------------------------------------

    top_features = (
        feature_importance
        .head(20)
        .sort_values(
            "importance"
        )
    )

    plt.figure(
        figsize=(10, 8)
    )

    plt.barh(
        top_features["feature"],
        top_features["importance"],
    )

    plt.xlabel(
        "Feature Importance"
    )

    plt.ylabel(
        "Feature"
    )

    plt.title(
        "LightGBM Baseline Feature Importance"
    )

    plt.tight_layout()

    plt.savefig(
        FEATURE_IMPORTANCE_PATH,
        dpi=200,
        bbox_inches="tight",
    )

    plt.close()

    # --------------------------------------------------------
    # Final output
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "MODEL SAVING COMPLETE"
    )

    print(
        "=" * 70
    )

    print(
        f"Model              : "
        f"{MODEL_PATH}"
    )

    print(
        f"Label encoder      : "
        f"{LABEL_ENCODER_PATH}"
    )

    print(
        f"Feature schema     : "
        f"{FEATURES_PATH}"
    )

    print(
        f"Metrics             : "
        f"{METRICS_PATH}"
    )

    print(
        f"Confusion matrix   : "
        f"{CONFUSION_MATRIX_PATH}"
    )

    print(
        f"Feature importance : "
        f"{FEATURE_IMPORTANCE_PATH}"
    )

    print(
        "\nSTATUS: BASELINE TRAINING COMPLETE"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()