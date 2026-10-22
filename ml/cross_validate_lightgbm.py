from __future__ import annotations

import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder


# ============================================================
# PATHS
# ============================================================

INPUT_PATH = Path(
    "data/generated/ml_training_dataset.jsonl"
)

OUTPUT_PATH = Path(
    "models/lightgbm/cross_validation_metrics.json"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

N_SPLITS = 5

EXPECTED_RECORDS = 504

EXPECTED_FEATURES = 30

EXPECTED_CLASSES = 9

EXPECTED_RECORDS_PER_CLASS = 56


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset() -> pd.DataFrame:

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
    df: pd.DataFrame,
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
    # Record count
    # --------------------------------------------------------

    if len(df) != EXPECTED_RECORDS:

        raise ValueError(
            f"Expected {EXPECTED_RECORDS} records, "
            f"found {len(df)}"
        )

    # --------------------------------------------------------
    # Feature count
    # --------------------------------------------------------

    if len(feature_columns) != EXPECTED_FEATURES:

        raise ValueError(
            f"Expected {EXPECTED_FEATURES} features, "
            f"found {len(feature_columns)}"
        )

    # --------------------------------------------------------
    # Class count
    # --------------------------------------------------------

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

        raise ValueError(
            "Duplicate session IDs detected."
        )

    # --------------------------------------------------------
    # Class balance
    # --------------------------------------------------------

    class_counts = (
        df["scenario_label"]
        .value_counts()
    )

    if not (
        class_counts
        == EXPECTED_RECORDS_PER_CLASS
    ).all():

        raise ValueError(
            "Unexpected class distribution:\n"
            f"{class_counts}"
        )

    return feature_columns


# ============================================================
# CREATE MODEL
# ============================================================

def create_model(
    num_classes: int,
):

    return lgb.LGBMClassifier(

        objective="multiclass",

        num_class=num_classes,

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


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)

    print(
        "LIGHTGBM 5-FOLD CROSS-VALIDATION"
    )

    print("=" * 70)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    df = load_dataset()

    feature_columns = (
        validate_dataset(df)
    )

    X = df[
        feature_columns
    ]

    y_text = df[
        "scenario_label"
    ]

    # --------------------------------------------------------
    # Encode labels
    # --------------------------------------------------------

    encoder = LabelEncoder()

    y = encoder.fit_transform(
        y_text
    )

    class_names = (
        encoder.classes_
    )

    # --------------------------------------------------------
    # Dataset information
    # --------------------------------------------------------

    print(
        f"\nRecords  : {len(df)}"
    )

    print(
        f"Features : {len(feature_columns)}"
    )

    print(
        f"Classes  : {len(class_names)}"
    )

    print(
        f"Folds    : {N_SPLITS}"
    )

    print("\nClasses:")

    for i, name in enumerate(
        class_names
    ):

        print(
            f"  {i}: {name}"
        )

    # --------------------------------------------------------
    # Cross-validation splitter
    # --------------------------------------------------------

    skf = StratifiedKFold(

        n_splits=N_SPLITS,

        shuffle=True,

        random_state=RANDOM_STATE,
    )

    fold_results = []

    # --------------------------------------------------------
    # Fold training
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "FOLD RESULTS"
    )

    print(
        "=" * 70
    )

    for fold, (
        train_idx,
        test_idx,
    ) in enumerate(
        skf.split(X, y),
        start=1,
    ):

        X_train = X.iloc[
            train_idx
        ]

        X_test = X.iloc[
            test_idx
        ]

        y_train = y[
            train_idx
        ]

        y_test = y[
            test_idx
        ]

        print(
            f"\nFold {fold}"
        )

        print(
            "-" * 40
        )

        print(
            f"Training samples: "
            f"{len(X_train)}"
        )

        print(
            f"Test samples    : "
            f"{len(X_test)}"
        )

        # ----------------------------------------------------
        # Model
        # ----------------------------------------------------

        model = create_model(
            len(class_names)
        )

        model.fit(
            X_train,
            y_train,
        )

        # ----------------------------------------------------
        # Predictions
        # ----------------------------------------------------

        y_pred = model.predict(
            X_test
        )

        y_pred = (
            np.asarray(y_pred)
            .astype(int)
        )

        # ----------------------------------------------------
        # Metrics
        # ----------------------------------------------------

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

        print(
            f"Accuracy        : "
            f"{accuracy:.4f}"
        )

        print(
            f"Macro Precision : "
            f"{macro_precision:.4f}"
        )

        print(
            f"Macro Recall    : "
            f"{macro_recall:.4f}"
        )

        print(
            f"Macro F1        : "
            f"{macro_f1:.4f}"
        )

        print(
            f"Weighted F1     : "
            f"{weighted_f1:.4f}"
        )

        fold_results.append(
            {
                "fold": fold,

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
            }
        )

    # --------------------------------------------------------
    # Aggregate metrics
    # --------------------------------------------------------

    metrics = [
        "accuracy",
        "macro_precision",
        "macro_recall",
        "macro_f1",
        "weighted_f1",
    ]

    summary = {}

    for metric in metrics:

        values = [
            result[metric]
            for result in fold_results
        ]

        summary[metric] = {

            "mean":
                float(
                    np.mean(values)
                ),

            "std":
                float(
                    np.std(values)
                ),

            "min":
                float(
                    np.min(values)
                ),

            "max":
                float(
                    np.max(values)
                ),
        }

    # --------------------------------------------------------
    # Print summary
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "5-FOLD CROSS-VALIDATION SUMMARY"
    )

    print(
        "=" * 70
    )

    for metric in metrics:

        result = summary[
            metric
        ]

        print(
            f"{metric:18s}: "
            f"{result['mean']:.4f} "
            f"+/- "
            f"{result['std']:.4f}"
        )

        print(
            f"{'':18s}  "
            f"range="
            f"{result['min']:.4f}"
            f" - "
            f"{result['max']:.4f}"
        )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = {

        "dataset": {

            "records":
                len(df),

            "features":
                len(feature_columns),

            "classes":
                class_names.tolist(),

            "n_splits":
                N_SPLITS,

            "random_state":
                RANDOM_STATE,
        },

        "fold_results":
            fold_results,

        "summary":
            summary,
    }

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            output,
            f,
            indent=2,
        )

    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "STATUS: "
        "CROSS-VALIDATION COMPLETE"
    )

    print(
        "=" * 70
    )

    print(
        f"Results saved to: "
        f"{OUTPUT_PATH}"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
