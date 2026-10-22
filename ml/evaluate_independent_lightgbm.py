import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


FEATURE_FILE = Path(
    "data/generated/independent_evaluation/"
    "evaluation_ml_features.jsonl"
)

MODEL_FILE = Path(
    "models/lightgbm/baseline_model.pkl"
)

LABEL_ENCODER_FILE = Path(
    "models/lightgbm/label_encoder.pkl"
)

FEATURE_SCHEMA_FILE = Path(
    "models/lightgbm/feature_names.json"
)


def load_jsonl(path):

    records = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:

        for line in handle:

            line = line.strip()

            if line:

                records.append(
                    json.loads(line)
                )

    return records


def main():

    print("=" * 70)
    print("INDEPENDENT LIGHTGBM EVALUATION")
    print("=" * 70)

    # --------------------------------------------------------
    # Load model
    # --------------------------------------------------------

    if not MODEL_FILE.exists():

        raise FileNotFoundError(
            f"Model not found: {MODEL_FILE}"
        )

    if not LABEL_ENCODER_FILE.exists():

        raise FileNotFoundError(
            f"Label encoder not found: "
            f"{LABEL_ENCODER_FILE}"
        )

    if not FEATURE_SCHEMA_FILE.exists():

        raise FileNotFoundError(
            f"Feature schema not found: "
            f"{FEATURE_SCHEMA_FILE}"
        )

    model = joblib.load(
        MODEL_FILE
    )

    label_encoder = joblib.load(
        LABEL_ENCODER_FILE
    )

    with FEATURE_SCHEMA_FILE.open(
        "r",
        encoding="utf-8",
    ) as handle:

        feature_names = json.load(
            handle
        )

    print()
    print(
        f"Model loaded successfully."
    )

    print(
        f"Expected features: "
        f"{len(feature_names)}"
    )

    print(
        f"Expected classes : "
        f"{len(label_encoder.classes_)}"
    )

    # --------------------------------------------------------
    # Load independent evaluation data
    # --------------------------------------------------------

    records = load_jsonl(
        FEATURE_FILE
    )

    print(
        f"Evaluation records: "
        f"{len(records)}"
    )

    if len(records) != 180:

        raise ValueError(
            f"Expected 180 evaluation records, "
            f"found {len(records)}"
        )

    # --------------------------------------------------------
    # Validate feature schema
    # --------------------------------------------------------

    actual_features = set(
        records[0]["features"].keys()
    )

    expected_features = set(
        feature_names
    )

    if actual_features != expected_features:

        missing = sorted(
            expected_features
            - actual_features
        )

        extra = sorted(
            actual_features
            - expected_features
        )

        raise ValueError(
            "Feature schema mismatch.\n"
            f"Missing: {missing}\n"
            f"Extra: {extra}"
        )

    # --------------------------------------------------------
    # Build X and y
    # --------------------------------------------------------

    X = np.array(
        [
            [
                record["features"][name]
                for name in feature_names
            ]
            for record in records
        ],
        dtype=float,
    )

    y_text = np.array(
        [
            record["scenario_label"]
            for record in records
        ]
    )

    print()
    print(
        f"X shape: {X.shape}"
    )

    print(
        f"Y shape: {y_text.shape}"
    )

    # --------------------------------------------------------
    # Validate labels
    # --------------------------------------------------------

    known_classes = set(
        label_encoder.classes_
    )

    evaluation_classes = set(
        y_text
    )

    if evaluation_classes != known_classes:

        raise ValueError(
            "Evaluation classes do not match "
            "training classes.\n"
            f"Missing: "
            f"{sorted(known_classes - evaluation_classes)}\n"
            f"Extra: "
            f"{sorted(evaluation_classes - known_classes)}"
        )

    # --------------------------------------------------------
    # Encode labels
    # --------------------------------------------------------

    y = label_encoder.transform(
        y_text
    )

    # --------------------------------------------------------
    # Generate predictions
    # --------------------------------------------------------

    print()
    print(
        "Generating predictions..."
    )

    predictions = model.predict(
        X
    )

    # LightGBM may return probabilities depending
    # on configuration, so ensure integer class IDs.
    predictions = np.asarray(
        predictions
    )

    if predictions.ndim > 1:

        predictions = np.argmax(
            predictions,
            axis=1,
        )

    predictions = predictions.astype(
        int
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y,
        predictions,
    )

    macro_precision = precision_score(
        y,
        predictions,
        average="macro",
        zero_division=0,
    )

    macro_recall = recall_score(
        y,
        predictions,
        average="macro",
        zero_division=0,
    )

    macro_f1 = f1_score(
        y,
        predictions,
        average="macro",
        zero_division=0,
    )

    weighted_f1 = f1_score(
        y,
        predictions,
        average="weighted",
        zero_division=0,
    )

    micro_f1 = f1_score(
        y,
        predictions,
        average="micro",
        zero_division=0,
    )

    print()
    print("=" * 70)
    print("INDEPENDENT EVALUATION METRICS")
    print("=" * 70)

    print(
        f"Accuracy          : {accuracy:.4f}"
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
    # Per-class metrics
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("PER-CLASS METRICS")
    print("=" * 70)

    report = classification_report(
        y,
        predictions,
        labels=np.arange(
            len(label_encoder.classes_)
        ),
        target_names=label_encoder.classes_,
        zero_division=0,
    )

    print(report)

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    cm = confusion_matrix(
        y,
        predictions,
        labels=np.arange(
            len(label_encoder.classes_)
        ),
    )

    print("=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    print(
        "Rows = actual class"
    )

    print(
        "Columns = predicted class"
    )

    print()

    print(
        "Classes:"
    )

    for index, name in enumerate(
        label_encoder.classes_
    ):

        print(
            f"  {index}: {name}"
        )

    print()

    print(cm)

    # --------------------------------------------------------
    # Prediction distribution
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("PREDICTION DISTRIBUTION")
    print("=" * 70)

    for index, name in enumerate(
        label_encoder.classes_
    ):

        count = int(
            np.sum(
                predictions == index
            )
        )

        print(
            f"{name:<22}: {count}"
        )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    output_dir = Path(
        "models/lightgbm/independent_evaluation"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    metrics = {
        "evaluation_records":
            len(records),
        "features":
            len(feature_names),
        "accuracy":
            float(accuracy),
        "macro_precision":
            float(macro_precision),
        "macro_recall":
            float(macro_recall),
        "macro_f1":
            float(macro_f1),
        "weighted_f1":
            float(weighted_f1),
        "micro_f1":
            float(micro_f1),
    }

    metrics_file = (
        output_dir
        / "metrics.json"
    )

    with metrics_file.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            metrics,
            handle,
            indent=2,
        )

    confusion_file = (
        output_dir
        / "confusion_matrix.json"
    )

    with confusion_file.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            cm.tolist(),
            handle,
            indent=2,
        )

    predictions_file = (
        output_dir
        / "predictions.jsonl"
    )

    with predictions_file.open(
        "w",
        encoding="utf-8",
    ) as handle:

        for record, actual, predicted in zip(
            records,
            y_text,
            predictions,
        ):

            handle.write(
                json.dumps(
                    {
                        "session_id":
                            record[
                                "session_id"
                            ],
                        "run_id":
                            record[
                                "run_id"
                            ],
                        "actual":
                            str(actual),
                        "predicted":
                            label_encoder.classes_[
                                int(predicted)
                            ],
                    }
                )
                + "\n"
            )

    print()
    print("=" * 70)
    print("INDEPENDENT EVALUATION COMPLETE")
    print("=" * 70)

    print(
        f"Metrics: {metrics_file}"
    )

    print(
        f"Confusion matrix: "
        f"{confusion_file}"
    )

    print(
        f"Predictions: "
        f"{predictions_file}"
    )

    print()
    print(
        "STATUS: PASS"
    )


if __name__ == "__main__":
    main()