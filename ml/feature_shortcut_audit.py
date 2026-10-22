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
    "models/lightgbm/feature_shortcut_audit.json"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

N_SPLITS = 5

EXPECTED_RECORDS = 5040

EXPECTED_FEATURES = 30

EXPECTED_CLASSES = 9

EXPECTED_RECORDS_PER_CLASS = 560


# ============================================================
# DIRECT BEHAVIOR FEATURES
# ============================================================

DIRECT_BEHAVIOR_FEATURES = {
    "identity_command_count",
    "system_command_count",
    "filesystem_command_count",
    "process_command_count",
    "network_command_count",
    "read_command_count",
    "interpreter_command_count",
    "privilege_command_count",
    "file_modify_command_count",
    "persistence_command_count",
}


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
            "Dataset contains missing labels."
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
# LIGHTGBM FACTORY
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
# CROSS-VALIDATION
# ============================================================

def evaluate_feature_set(
    X: pd.DataFrame,
    y: np.ndarray,
    feature_name: str,
):

    print(
        "\n" + "=" * 70
    )

    print(
        f"EVALUATING: {feature_name}"
    )

    print(
        "=" * 70
    )

    print(
        f"Features: {X.shape[1]}"
    )

    skf = StratifiedKFold(

        n_splits=N_SPLITS,

        shuffle=True,

        random_state=RANDOM_STATE,
    )

    fold_results = []

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

        model = create_model(
            num_classes=len(
                np.unique(y)
            )
        )

        model.fit(
            X_train,
            y_train,
        )

        y_pred = model.predict(
            X_test
        )

        y_pred = (
            np.asarray(y_pred)
            .astype(int)
        )

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
            f"Fold {fold}: "
            f"accuracy={accuracy:.4f}, "
            f"macro_f1={macro_f1:.4f}"
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

    print(
        "\nSummary:"
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

    return {
        "feature_count":
            X.shape[1],

        "fold_results":
            fold_results,

        "summary":
            summary,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 70
    )

    print(
        "LIGHTGBM FEATURE SHORTCUT AUDIT"
    )

    print(
        "=" * 70
    )

    # --------------------------------------------------------
    # Load and validate
    # --------------------------------------------------------

    df = load_dataset()

    all_features = (
        validate_dataset(df)
    )

    # --------------------------------------------------------
    # Check direct behavior features
    # --------------------------------------------------------

    missing_direct = (
        DIRECT_BEHAVIOR_FEATURES
        - set(all_features)
    )

    if missing_direct:

        raise ValueError(
            "Expected direct behavior features "
            f"not found: "
            f"{sorted(missing_direct)}"
        )

    # --------------------------------------------------------
    # Encode labels
    # --------------------------------------------------------

    encoder = LabelEncoder()

    y = encoder.fit_transform(
        df["scenario_label"]
    )

    class_names = (
        encoder.classes_.tolist()
    )

    # --------------------------------------------------------
    # Feature sets
    # --------------------------------------------------------

    full_features = (
        all_features
    )

    reduced_features = [
        feature
        for feature in all_features
        if feature
        not in DIRECT_BEHAVIOR_FEATURES
    ]

    print(
        "\nDataset:"
    )

    print(
        f"Records: {len(df)}"
    )

    print(
        f"Original features: "
        f"{len(full_features)}"
    )

    print(
        f"Direct behavior features removed: "
        f"{len(DIRECT_BEHAVIOR_FEATURES)}"
    )

    print(
        f"Reduced features: "
        f"{len(reduced_features)}"
    )

    print(
        "\nRemoved features:"
    )

    for feature in sorted(
        DIRECT_BEHAVIOR_FEATURES
    ):

        print(
            f"  - {feature}"
        )

    # --------------------------------------------------------
    # Full model
    # --------------------------------------------------------

    X_full = df[
        full_features
    ].copy()

    full_results = (
        evaluate_feature_set(
            X_full,
            y,
            "FULL 30-FEATURE MODEL",
        )
    )

    # --------------------------------------------------------
    # Reduced model
    # --------------------------------------------------------

    X_reduced = df[
        reduced_features
    ].copy()

    reduced_results = (
        evaluate_feature_set(
            X_reduced,
            y,
            "REDUCED MODEL WITHOUT DIRECT BEHAVIOR COUNTS",
        )
    )

    # --------------------------------------------------------
    # Compare
    # --------------------------------------------------------

    full_f1 = (
        full_results[
            "summary"
        ][
            "macro_f1"
        ]["mean"]
    )

    reduced_f1 = (
        reduced_results[
            "summary"
        ][
            "macro_f1"
        ]["mean"]
    )

    full_accuracy = (
        full_results[
            "summary"
        ][
            "accuracy"
        ]["mean"]
    )

    reduced_accuracy = (
        reduced_results[
            "summary"
        ][
            "accuracy"
        ]["mean"]
    )

    f1_difference = (
        full_f1
        - reduced_f1
    )

    accuracy_difference = (
        full_accuracy
        - reduced_accuracy
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "SHORTCUT AUDIT COMPARISON"
    )

    print(
        "=" * 70
    )

    print(
        f"Full model accuracy   : "
        f"{full_accuracy:.4f}"
    )

    print(
        f"Reduced model accuracy: "
        f"{reduced_accuracy:.4f}"
    )

    print(
        f"Accuracy difference   : "
        f"{accuracy_difference:+.4f}"
    )

    print()

    print(
        f"Full model Macro F1   : "
        f"{full_f1:.4f}"
    )

    print(
        f"Reduced model Macro F1: "
        f"{reduced_f1:.4f}"
    )

    print(
        f"Macro F1 difference   : "
        f"{f1_difference:+.4f}"
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

            "original_features":
                len(full_features),

            "reduced_features":
                len(reduced_features),

            "classes":
                class_names,

            "n_splits":
                N_SPLITS,

            "random_state":
                RANDOM_STATE,
        },

        "removed_features":
            sorted(
                DIRECT_BEHAVIOR_FEATURES
            ),

        "full_model":
            full_results,

        "reduced_model":
            reduced_results,

        "comparison": {

            "accuracy_difference":
                float(
                    accuracy_difference
                ),

            "macro_f1_difference":
                float(
                    f1_difference
                ),
        },
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
        "STATUS: SHORTCUT AUDIT COMPLETE"
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
