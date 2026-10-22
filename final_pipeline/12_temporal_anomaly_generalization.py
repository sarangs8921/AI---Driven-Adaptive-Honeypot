"""
Step 12 — Temporal Anomaly Generalization

Purpose
-------
Evaluate whether anomaly detection learned from historical
2021–2022 behavior can generalize to unseen 2024 sessions.

Primary experiment:

    2021–2022
        |
        | fit
        v
    Anomaly detector
        |
        | score unseen data
        v
      2024

Representations:

1. Aggregate
   Existing 23 behavioral features.

2. Sequence statistics
   Sequence-level behavioral statistics.

3. TF-IDF
   Command-sequence TF-IDF representation.

Primary detector:

    Isolation Forest

LOF is NOT used as the primary detector because Step 11 showed
very low agreement between Isolation Forest and LOF, especially
for TF-IDF.

Important:
-----------
The 2024 data is never used to fit the primary anomaly detector.

For TF-IDF:
    The vectorizer is fit only on 2021–2022.

For sequence statistics:
    Scaling is fit only on 2021–2022.

For aggregate features:
    The Step 04 transformed features are already available,
    but the script also performs a training-only scaler fit
    to ensure the temporal experiment does not accidentally
    depend on future statistics.

This is an anomaly-generalization experiment.

Anomaly != maliciousness
Anomaly != ATT&CK technique
Anomaly != attacker classification


Input
-----
data/final/train/behavior_features_raw.csv
data/final/train/behavior_features_transformed.csv
data/final/train/behavior_metadata.csv

data/final/source/sequence_representation/sequence_statistics.csv

Original command datasets:
data/datasets/external/sessions_2021_2022.jsonl
data/datasets/external/sessions_2024.jsonl


Output
------
data/final/source/temporal_anomaly_generalization/

    temporal_anomaly_scores.csv
    temporal_metrics.csv
    temporal_distribution.csv
    representation_comparison.csv
    top_2024_anomalies.csv
    temporal_summary.json

    tfidf/
        vectorizer vocabulary is saved through feature names


Interpretation
--------------
The important question is NOT:

    "Which model has the highest anomaly score?"

The important questions are:

1. Does the 2024 score distribution remain comparable?
2. Does the model produce a reasonable range of scores?
3. Are 2024 sessions concentrated at extreme scores?
4. Does sequence information reduce temporal distribution shift?
5. Are results stable across detector seeds?
6. Which representation behaves most consistently under
   genuine temporal holdout?


Next step
---------
After this experiment, evaluate the selected representation
against the independent 2025 SSH honeypot dataset and then
fresh Cowrie sessions.
"""


from __future__ import annotations

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

from scipy import sparse

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import RobustScaler
from sklearn.decomposition import TruncatedSVD


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

TRAIN_DIR = (
    PROJECT_ROOT
    / "data"
    / "final"
    / "train"
)

SEQUENCE_DIR = (
    PROJECT_ROOT
    / "data"
    / "final"
    / "source"
    / "sequence_representation"
)

DATASET_DIR = (
    PROJECT_ROOT
    / "data"
    / "datasets"
    / "external"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "final"
    / "source"
    / "temporal_anomaly_generalization"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# INPUT FILES
# ============================================================

RAW_FEATURES_FILE = (
    TRAIN_DIR
    / "behavior_features_raw.csv"
)

TRANSFORMED_FEATURES_FILE = (
    TRAIN_DIR
    / "behavior_features_transformed.csv"
)

BEHAVIOR_METADATA_FILE = (
    TRAIN_DIR
    / "behavior_metadata.csv"
)

SEQUENCE_STATS_FILE = (
    SEQUENCE_DIR
    / "sequence_statistics.csv"
)

SESSION_2021_2022_FILE = (
    DATASET_DIR
    / "sessions_2021_2022.jsonl"
)

SESSION_2024_FILE = (
    DATASET_DIR
    / "sessions_2024.jsonl"
)


# ============================================================
# CONFIGURATION
# ============================================================

IF_N_ESTIMATORS = 300

IF_CONTAMINATION = 0.05

RANDOM_SEEDS = [
    42,
    7,
    21,
    100,
    123,
]

# TF-IDF configuration.
TFIDF_NGRAM_RANGE = (3, 5)

TFIDF_MIN_DF = 2

TFIDF_MAX_DF = 0.95

TFIDF_MAX_FEATURES = 5000

TFIDF_SUBLINEAR_TF = True

# Maximum SVD components for optional diagnostic.
SVD_COMPONENTS = 100

TOP_N = 100


# ============================================================
# LOGGING
# ============================================================


def log(message: str) -> None:
    print(message, flush=True)


# ============================================================
# JSON SERIALIZATION
# ============================================================


def convert_to_python(value):

    if isinstance(value, dict):
        return {
            str(key): convert_to_python(val)
            for key, val in value.items()
        }

    if isinstance(value, list):
        return [
            convert_to_python(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            convert_to_python(item)
            for item in value
        ]

    if isinstance(value, np.integer):
        return int(value)

    if isinstance(value, np.floating):

        value = float(value)

        if not np.isfinite(value):
            return None

        return value

    if isinstance(value, np.bool_):
        return bool(value)

    if pd.isna(value):
        return None

    return value


def save_json(
    path: Path,
    data: dict,
) -> None:

    with path.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            convert_to_python(data),
            f,
            indent=2,
            allow_nan=False,
        )


# ============================================================
# SESSION LOADING
# ============================================================


def load_jsonl(
    path: Path,
) -> pd.DataFrame:

    rows = []

    if not path.exists():

        raise FileNotFoundError(
            f"Missing dataset:\n{path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1,
        ):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

            except json.JSONDecodeError as exc:

                raise ValueError(
                    f"Invalid JSON at "
                    f"{path}:{line_number}"
                ) from exc

            session_id = record.get(
                "session_id"
            )

            commands = record.get(
                "commands",
                [],
            )

            if session_id is None:
                continue

            if commands is None:
                commands = []

            if not isinstance(
                commands,
                list,
            ):
                commands = [commands]

            commands = [
                str(command).strip()
                for command in commands
                if str(command).strip()
            ]

            rows.append(
                {
                    "session_id": str(
                        session_id
                    ),
                    "commands": commands,
                }
            )

    return pd.DataFrame(
        rows
    )


# ============================================================
# COMMAND NORMALIZATION
# ============================================================


def normalize_command(
    command: str,
) -> str:

    command = str(
        command
    ).strip()

    if not command:
        return ""

    command = re.sub(
        r"\s+",
        " ",
        command,
    )

    command = re.sub(
        r"\b\d{3,}\b",
        "<NUM>",
        command,
    )

    return command


def normalize_sequence(
    commands: list[str],
) -> list[str]:

    result = []

    for command in commands:

        normalized = (
            normalize_command(
                command
            )
        )

        if normalized:
            result.append(
                normalized
            )

    return result


def tokenize_command(
    command: str,
) -> list[str]:

    return re.findall(
        r"""
        [A-Za-z_][A-Za-z0-9_.-]*
        |/[A-Za-z0-9_./-]+
        |-[A-Za-z0-9_-]+
        |&&
        |\|\|
        |\|
        |;
        |=
        """,
        command,
        flags=re.VERBOSE,
    )


def command_base_name(
    command: str,
) -> str:

    tokens = tokenize_command(
        command
    )

    if not tokens:
        return "<EMPTY>"

    return tokens[0]


def build_tfidf_document(
    commands: list[str],
) -> str:

    commands = normalize_sequence(
        commands
    )

    if not commands:
        return ""

    return " <CMD> ".join(
        commands
    )


# ============================================================
# SEQUENCE STATISTICS
# ============================================================


def make_ngrams(
    items: list[str],
    n: int,
):

    if len(items) < n:
        return []

    return [
        tuple(
            items[i:i + n]
        )
        for i in range(
            len(items) - n + 1
        )
    ]


def extract_sequence_statistics(
    commands: list[str],
) -> dict:

    commands = normalize_sequence(
        commands
    )

    command_count = len(
        commands
    )

    if command_count == 0:

        return {
            "sequence_command_count": 0,
            "sequence_unique_command_count": 0,
            "sequence_repetition_ratio": 0.0,
            "sequence_token_count": 0,
            "sequence_unique_token_count": 0,
            "sequence_vocabulary_size": 0,
            "sequence_token_diversity": 0.0,
            "mean_command_length_seq": 0.0,
            "median_command_length_seq": 0.0,
            "max_command_length_seq": 0.0,
            "std_command_length_seq": 0.0,
            "mean_command_token_count": 0.0,
            "max_command_token_count": 0.0,
            "command_transition_count": 0,
            "unique_command_transition_count": 0,
            "transition_diversity": 0.0,
            "bigram_count": 0,
            "unique_bigram_count": 0,
            "bigram_diversity": 0.0,
            "trigram_count": 0,
            "unique_trigram_count": 0,
            "trigram_diversity": 0.0,
            "unique_base_command_count": 0,
            "base_command_entropy": 0.0,
        }

    command_lengths = [
        len(command)
        for command in commands
    ]

    tokenized = [
        tokenize_command(
            command
        )
        for command in commands
    ]

    flat_tokens = [
        token
        for tokens in tokenized
        for token in tokens
    ]

    unique_commands = len(
        set(commands)
    )

    unique_tokens = len(
        set(flat_tokens)
    )

    repetition_ratio = (
        1.0
        - (
            unique_commands
            / command_count
        )
    )

    token_count = len(
        flat_tokens
    )

    token_diversity = (
        unique_tokens
        / token_count
        if token_count > 0
        else 0.0
    )

    base_commands = [
        command_base_name(
            command
        )
        for command in commands
    ]

    transitions = [
        (
            base_commands[i],
            base_commands[i + 1],
        )
        for i in range(
            command_count - 1
        )
    ]

    unique_transitions = len(
        set(transitions)
    )

    transition_diversity = (
        unique_transitions
        / len(transitions)
        if transitions
        else 0.0
    )

    bigrams = make_ngrams(
        base_commands,
        2,
    )

    trigrams = make_ngrams(
        base_commands,
        3,
    )

    unique_bigrams = len(
        set(bigrams)
    )

    unique_trigrams = len(
        set(trigrams)
    )

    bigram_diversity = (
        unique_bigrams
        / len(bigrams)
        if bigrams
        else 0.0
    )

    trigram_diversity = (
        unique_trigrams
        / len(trigrams)
        if trigrams
        else 0.0
    )

    # Entropy of base commands.
    counts = (
        pd.Series(
            base_commands
        )
        .value_counts()
    )

    total = counts.sum()

    entropy = 0.0

    for count in counts:

        p = count / total

        if p > 0:

            entropy -= (
                p
                * np.log2(p)
            )

    return {
        "sequence_command_count": command_count,

        "sequence_unique_command_count": unique_commands,

        "sequence_repetition_ratio": repetition_ratio,

        "sequence_token_count": token_count,

        "sequence_unique_token_count": unique_tokens,

        "sequence_vocabulary_size": unique_tokens,

        "sequence_token_diversity": token_diversity,

        "mean_command_length_seq": float(
            np.mean(
                command_lengths
            )
        ),

        "median_command_length_seq": float(
            np.median(
                command_lengths
            )
        ),

        "max_command_length_seq": float(
            np.max(
                command_lengths
            )
        ),

        "std_command_length_seq": float(
            np.std(
                command_lengths
            )
        ),

        "mean_command_token_count": float(
            np.mean(
                [
                    len(tokens)
                    for tokens in tokenized
                ]
            )
        ),

        "max_command_token_count": float(
            np.max(
                [
                    len(tokens)
                    for tokens in tokenized
                ]
            )
        ),

        "command_transition_count": len(
            transitions
        ),

        "unique_command_transition_count": (
            unique_transitions
        ),

        "transition_diversity": (
            transition_diversity
        ),

        "bigram_count": len(
            bigrams
        ),

        "unique_bigram_count": (
            unique_bigrams
        ),

        "bigram_diversity": (
            bigram_diversity
        ),

        "trigram_count": len(
            trigrams
        ),

        "unique_trigram_count": (
            unique_trigrams
        ),

        "trigram_diversity": (
            trigram_diversity
        ),

        "unique_base_command_count": len(
            set(base_commands)
        ),

        "base_command_entropy": float(
            entropy
        ),
    }


# ============================================================
# TRAIN ISOLATION FOREST
# ============================================================


def fit_isolation_forest(
    X_train,
    seed: int,
):

    model = IsolationForest(
        n_estimators=IF_N_ESTIMATORS,
        contamination=IF_CONTAMINATION,
        random_state=seed,
        n_jobs=-1,
    )

    model.fit(
        X_train
    )

    return model


def anomaly_scores(
    model,
    X,
):

    # sklearn:
    # higher score_samples = more normal
    #
    # invert:
    # higher = more anomalous

    raw_scores = (
        -model.score_samples(
            X
        )
    )

    return raw_scores


def normalize_using_training_range(
    train_scores,
    test_scores,
):

    train_scores = np.asarray(
        train_scores,
        dtype=np.float64,
    )

    test_scores = np.asarray(
        test_scores,
        dtype=np.float64,
    )

    minimum = np.min(
        train_scores
    )

    maximum = np.max(
        train_scores
    )

    denominator = (
        maximum
        - minimum
    )

    if denominator <= 1e-12:

        return (
            np.zeros_like(
                train_scores
            ),
            np.zeros_like(
                test_scores
            ),
        )

    train_normalized = (
        train_scores
        - minimum
    ) / denominator

    test_normalized = (
        test_scores
        - minimum
    ) / denominator

    return (
        train_normalized,
        test_normalized,
    )


# ============================================================
# FIT / SCORE ONE REPRESENTATION
# ============================================================


def run_temporal_experiment(
    name: str,
    X_train,
    X_test,
):

    log(
        "\n" + "=" * 70
    )

    log(
        f"REPRESENTATION: {name}"
    )

    log(
        "=" * 70
    )

    log(
        f"Training samples: "
        f"{X_train.shape[0]:,}"
    )

    log(
        f"Test samples: "
        f"{X_test.shape[0]:,}"
    )

    log(
        f"Features: "
        f"{X_train.shape[1]:,}"
    )

    # --------------------------------------------------------
    # Fit detector
    # --------------------------------------------------------

    model = fit_isolation_forest(
        X_train,
        seed=42,
    )

    train_raw_scores = (
        anomaly_scores(
            model,
            X_train,
        )
    )

    test_raw_scores = (
        anomaly_scores(
            model,
            X_test,
        )
    )

    (
        train_scores,
        test_scores,
    ) = normalize_using_training_range(
        train_raw_scores,
        test_raw_scores,
    )

    # --------------------------------------------------------
    # Training threshold
    # --------------------------------------------------------
    #
    # Important:
    # The 95th percentile is calculated from TRAINING
    # scores only.
    #
    # This gives us a threshold that does not inspect
    # the 2024 holdout distribution.
    # --------------------------------------------------------

    threshold_95 = np.percentile(
        train_scores,
        95,
    )

    threshold_99 = np.percentile(
        train_scores,
        99,
    )

    test_above_95 = (
        test_scores
        >= threshold_95
    )

    test_above_99 = (
        test_scores
        >= threshold_99
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    train_metrics = {
        "representation": name,

        "train_samples": int(
            len(train_scores)
        ),

        "test_samples": int(
            len(test_scores)
        ),

        "features": int(
            X_train.shape[1]
        ),

        "train_mean": float(
            np.mean(
                train_scores
            )
        ),

        "train_median": float(
            np.median(
                train_scores
            )
        ),

        "train_std": float(
            np.std(
                train_scores
            )
        ),

        "train_p90": float(
            np.percentile(
                train_scores,
                90,
            )
        ),

        "train_p95": float(
            np.percentile(
                train_scores,
                95,
            )
        ),

        "train_p99": float(
            np.percentile(
                train_scores,
                99,
            )
        ),

        "train_max": float(
            np.max(
                train_scores
            )
        ),

        "test_mean": float(
            np.mean(
                test_scores
            )
        ),

        "test_median": float(
            np.median(
                test_scores
            )
        ),

        "test_std": float(
            np.std(
                test_scores
            )
        ),

        "test_p90": float(
            np.percentile(
                test_scores,
                90,
            )
        ),

        "test_p95": float(
            np.percentile(
                test_scores,
                95,
            )
        ),

        "test_p99": float(
            np.percentile(
                test_scores,
                99,
            )
        ),

        "test_max": float(
            np.max(
                test_scores
            )
        ),

        "train_95_threshold": float(
            threshold_95
        ),

        "train_99_threshold": float(
            threshold_99
        ),

        "test_above_train_95": int(
            test_above_95.sum()
        ),

        "test_above_train_95_rate": float(
            test_above_95.mean()
        ),

        "test_above_train_99": int(
            test_above_99.sum()
        ),

        "test_above_train_99_rate": float(
            test_above_99.mean()
        ),
    }

    return (
        train_scores,
        test_scores,
        train_metrics,
    )


# ============================================================
# DISTRIBUTION COMPARISON
# ============================================================


def calculate_distribution_metrics(
    train_scores,
    test_scores,
):

    train_scores = np.asarray(
        train_scores
    )

    test_scores = np.asarray(
        test_scores
    )

    # Mean shift relative to training.
    mean_shift = (
        np.mean(test_scores)
        - np.mean(train_scores)
    )

    # Standardized mean shift.
    train_std = np.std(
        train_scores
    )

    standardized_shift = (
        mean_shift
        / train_std
        if train_std > 1e-12
        else 0.0
    )

    # Quantile differences.
    quantiles = [
        0.50,
        0.75,
        0.90,
        0.95,
        0.99,
    ]

    quantile_rows = []

    for q in quantiles:

        train_q = np.quantile(
            train_scores,
            q,
        )

        test_q = np.quantile(
            test_scores,
            q,
        )

        quantile_rows.append(
            {
                "quantile": q,
                "train": float(
                    train_q
                ),
                "test": float(
                    test_q
                ),
                "difference": float(
                    test_q
                    - train_q
                ),
            }
        )

    return (
        float(mean_shift),
        float(standardized_shift),
        quantile_rows,
    )


# ============================================================
# MAIN
# ============================================================


def main():

    log(
        "=" * 70
    )

    log(
        "STEP 12 — TEMPORAL ANOMALY GENERALIZATION"
    )

    log(
        "=" * 70
    )

    # ========================================================
    # 1. CHECK INPUTS
    # ========================================================

    log(
        "\n[1/9] Checking input files..."
    )

    required_files = [
        RAW_FEATURES_FILE,
        TRANSFORMED_FEATURES_FILE,
        BEHAVIOR_METADATA_FILE,
        SEQUENCE_STATS_FILE,
        SESSION_2021_2022_FILE,
        SESSION_2024_FILE,
    ]

    for path in required_files:

        if not path.exists():

            raise FileNotFoundError(
                f"Missing input:\n{path}"
            )

        log(
            f"  OK: {path}"
        )

    # ========================================================
    # 2. LOAD METADATA AND FEATURES
    # ========================================================

    log(
        "\n[2/9] Loading feature data..."
    )

    raw_features = pd.read_csv(
        RAW_FEATURES_FILE
    )

    transformed_features = pd.read_csv(
        TRANSFORMED_FEATURES_FILE
    )

    behavior_metadata = pd.read_csv(
        BEHAVIOR_METADATA_FILE
    )

    sequence_stats = pd.read_csv(
        SEQUENCE_STATS_FILE
    )

    log(
        f"  Raw features: "
        f"{raw_features.shape}"
    )

    log(
        f"  Transformed features: "
        f"{transformed_features.shape}"
    )

    log(
        f"  Behavior metadata: "
        f"{behavior_metadata.shape}"
    )

    log(
        f"  Sequence statistics: "
        f"{sequence_stats.shape}"
    )

    # ========================================================
    # 3. LOAD ORIGINAL SESSION COMMANDS
    # ========================================================

    log(
        "\n[3/9] Loading original session commands..."
    )

    sessions_2021 = load_jsonl(
        SESSION_2021_2022_FILE
    )

    sessions_2024 = load_jsonl(
        SESSION_2024_FILE
    )

    log(
        f"  2021–2022 sessions: "
        f"{len(sessions_2021):,}"
    )

    log(
        f"  2024 sessions: "
        f"{len(sessions_2024):,}"
    )

    # ========================================================
    # 4. VERIFY SESSION ALIGNMENT
    # ========================================================

    log(
        "\n[4/9] Verifying temporal alignment..."
    )

    all_session_ids = pd.concat(
        [
            sessions_2021[
                "session_id"
            ],
            sessions_2024[
                "session_id"
            ],
        ],
        ignore_index=True,
    ).astype(str)

    metadata_ids = (
        behavior_metadata[
            "session_id"
        ]
        .astype(str)
        .reset_index(drop=True)
    )

    if (
        all_session_ids.tolist()
        != metadata_ids.tolist()
    ):

        raise ValueError(
            "Original session ordering does not match "
            "behavior metadata."
        )

    sequence_ids = (
        sequence_stats[
            "session_id"
        ]
        .astype(str)
        .reset_index(drop=True)
    )

    if (
        all_session_ids.tolist()
        != sequence_ids.tolist()
    ):

        raise ValueError(
            "Original session ordering does not match "
            "sequence statistics."
        )

    log(
        "  Session alignment verified."
    )

    # Create temporal mask.
    n_train = len(
        sessions_2021
    )

    n_test = len(
        sessions_2024
    )

    train_mask = np.zeros(
        len(all_session_ids),
        dtype=bool,
    )

    train_mask[
        :n_train
    ] = True

    test_mask = ~train_mask

    log(
        f"  Training/reference: "
        f"{int(train_mask.sum()):,}"
    )

    log(
        f"  Temporal holdout: "
        f"{int(test_mask.sum()):,}"
    )

    # ========================================================
    # 5. PREPARE AGGREGATE REPRESENTATION
    # ========================================================

    log(
        "\n[5/9] Preparing aggregate representation..."
    )

    #
    # Fit scaling ONLY on 2021–2022.
    #
    # Even though Step 04 already produced transformed
    # features, this makes the temporal experiment
    # completely explicit.
    #

    aggregate_raw = (
        raw_features
        .to_numpy(
            dtype=np.float32
        )
    )

    aggregate_scaler = RobustScaler()

    aggregate_train = (
        aggregate_scaler.fit_transform(
            aggregate_raw[
                train_mask
            ]
        )
        .astype(np.float32)
    )

    aggregate_test = (
        aggregate_scaler.transform(
            aggregate_raw[
                test_mask
            ]
        )
        .astype(np.float32)
    )

    log(
        f"  Train: "
        f"{aggregate_train.shape}"
    )

    log(
        f"  Test: "
        f"{aggregate_test.shape}"
    )

    # ========================================================
    # 6. PREPARE SEQUENCE STATISTICS
    # ========================================================

    log(
        "\n[6/9] Preparing sequence statistics..."
    )

    sequence_columns = [
        column
        for column in sequence_stats.columns
        if column not in {
            "session_id",
            "period",
        }
    ]

    sequence_raw = (
        sequence_stats[
            sequence_columns
        ]
        .fillna(0.0)
        .to_numpy(
            dtype=np.float32
        )
    )

    sequence_scaler = (
        RobustScaler()
    )

    sequence_train = (
        sequence_scaler
        .fit_transform(
            sequence_raw[
                train_mask
            ]
        )
        .astype(
            np.float32
        )
    )

    sequence_test = (
        sequence_scaler
        .transform(
            sequence_raw[
                test_mask
            ]
        )
        .astype(
            np.float32
        )
    )

    log(
        f"  Train: "
        f"{sequence_train.shape}"
    )

    log(
        f"  Test: "
        f"{sequence_test.shape}"
    )

    # ========================================================
    # 7. PREPARE TF-IDF — TRAIN ONLY FIT
    # ========================================================

    log(
        "\n[7/9] Building temporal TF-IDF representation..."
    )

    log(
        "  Creating command documents..."
    )

    all_documents = []

    for index, commands in enumerate(
        pd.concat(
            [
                sessions_2021[
                    "commands"
                ],
                sessions_2024[
                    "commands"
                ],
            ],
            ignore_index=True,
        )
    ):

        all_documents.append(
            build_tfidf_document(
                commands
            )
        )

        if (
            index + 1
        ) % 2000 == 0:

            log(
                f"    "
                f"{index + 1:,}/"
                f"{len(all_session_ids):,}"
            )

    train_documents = [
        all_documents[i]
        for i in np.where(
            train_mask
        )[0]
    ]

    test_documents = [
        all_documents[i]
        for i in np.where(
            test_mask
        )[0]
    ]

    vectorizer = (
        TfidfVectorizer(
            analyzer="char",
            ngram_range=TFIDF_NGRAM_RANGE,
            min_df=TFIDF_MIN_DF,
            max_df=TFIDF_MAX_DF,
            max_features=TFIDF_MAX_FEATURES,
            sublinear_tf=TFIDF_SUBLINEAR_TF,
            lowercase=True,
            dtype=np.float32,
        )
    )

    log(
        "\n  Fitting TF-IDF ONLY on 2021–2022..."
    )

    tfidf_train = (
        vectorizer.fit_transform(
            train_documents
        )
    )

    log(
        f"  Train TF-IDF: "
        f"{tfidf_train.shape}"
    )

    log(
        "\n  Transforming 2024 using the "
        "training vocabulary..."
    )

    tfidf_test = (
        vectorizer.transform(
            test_documents
        )
    )

    log(
        f"  Test TF-IDF: "
        f"{tfidf_test.shape}"
    )

    # Save vocabulary information.
    tfidf_feature_names = (
        vectorizer.get_feature_names_out()
    )

    pd.DataFrame(
        {
            "feature_index": np.arange(
                len(
                    tfidf_feature_names
                )
            ),
            "feature": (
                tfidf_feature_names
            ),
        }
    ).to_csv(
        OUTPUT_DIR
        / "tfidf_temporal_feature_names.csv",
        index=False,
    )

    sparse.save_npz(
        OUTPUT_DIR
        / "tfidf_train.npz",
        tfidf_train,
    )

    sparse.save_npz(
        OUTPUT_DIR
        / "tfidf_2024.npz",
        tfidf_test,
    )

    # ========================================================
    # 8. RUN TEMPORAL EXPERIMENTS
    # ========================================================

    log(
        "\n[8/9] Running temporal anomaly experiments..."
    )

    representations = {
        "aggregate": (
            aggregate_train,
            aggregate_test,
        ),

        "sequence_stats": (
            sequence_train,
            sequence_test,
        ),

        "tfidf": (
            tfidf_train,
            tfidf_test,
        ),
    }

    score_rows = []
    metric_rows = []

    experiment_results = {}

    for name, (
        X_train,
        X_test,
    ) in representations.items():

        (
            train_scores,
            test_scores,
            metrics,
        ) = run_temporal_experiment(
            name,
            X_train,
            X_test,
        )

        experiment_results[
            name
        ] = {
            "train_scores": train_scores,
            "test_scores": test_scores,
            "metrics": metrics,
        }

        # ----------------------------------------------------
        # Store training scores
        # ----------------------------------------------------

        for i, score in enumerate(
            train_scores
        ):

            score_rows.append(
                {
                    "session_id": (
                        sessions_2021.iloc[
                            i
                        ][
                            "session_id"
                        ]
                    ),

                    "period": "2021_2022",

                    "dataset_role": "reference",

                    "representation": name,

                    "anomaly_score": float(
                        score
                    ),
                }
            )

        # ----------------------------------------------------
        # Store 2024 scores
        # ----------------------------------------------------

        for i, score in enumerate(
            test_scores
        ):

            score_rows.append(
                {
                    "session_id": (
                        sessions_2024.iloc[
                            i
                        ][
                            "session_id"
                        ]
                    ),

                    "period": "2024",

                    "dataset_role": "temporal_holdout",

                    "representation": name,

                    "anomaly_score": float(
                        score
                    ),
                }
            )

        metric_rows.append(
            metrics
        )

        # ----------------------------------------------------
        # Distribution analysis
        # ----------------------------------------------------

        (
            mean_shift,
            standardized_shift,
            quantile_rows,
        ) = calculate_distribution_metrics(
            train_scores,
            test_scores,
        )

        metrics[
            "mean_shift_test_minus_train"
        ] = mean_shift

        metrics[
            "standardized_mean_shift"
        ] = standardized_shift

        metrics[
            "quantile_comparison"
        ] = quantile_rows

    # --------------------------------------------------------
    # Save score table
    # --------------------------------------------------------

    scores_df = pd.DataFrame(
        score_rows
    )

    scores_df.to_csv(
        OUTPUT_DIR
        / "temporal_anomaly_scores.csv",
        index=False,
    )

    # --------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------

    metrics_df = pd.DataFrame(
        [
            {
                key: value
                for key, value in metrics.items()
                if key
                != "quantile_comparison"
            }
            for metrics in metric_rows
        ]
    )

    metrics_df.to_csv(
        OUTPUT_DIR
        / "temporal_metrics.csv",
        index=False,
    )

    # --------------------------------------------------------
    # Quantile distribution table
    # --------------------------------------------------------

    distribution_rows = []

    for name, result in (
        experiment_results.items()
    ):

        train_scores = result[
            "train_scores"
        ]

        test_scores = result[
            "test_scores"
        ]

        for q in [
            0.50,
            0.75,
            0.90,
            0.95,
            0.99,
        ]:

            train_q = np.quantile(
                train_scores,
                q,
            )

            test_q = np.quantile(
                test_scores,
                q,
            )

            distribution_rows.append(
                {
                    "representation": name,

                    "quantile": q,

                    "train_value": float(
                        train_q
                    ),

                    "test_2024_value": float(
                        test_q
                    ),

                    "difference": float(
                        test_q
                        - train_q
                    ),
                }
            )

    distribution_df = (
        pd.DataFrame(
            distribution_rows
        )
    )

    distribution_df.to_csv(
        OUTPUT_DIR
        / "temporal_distribution.csv",
        index=False,
    )

    # ========================================================
    # 2024 TOP ANOMALIES
    # ========================================================

    log(
        "\n  Extracting top 2024 anomalies..."
    )

    top_rows = []

    for name, result in (
        experiment_results.items()
    ):

        test_scores = result[
            "test_scores"
        ]

        order = np.argsort(
            test_scores
        )[::-1]

        for rank, index in enumerate(
            order[
                :TOP_N
            ],
            start=1,
        ):

            top_rows.append(
                {
                    "representation": name,

                    "rank": rank,

                    "session_id": (
                        sessions_2024.iloc[
                            index
                        ][
                            "session_id"
                        ]
                    ),

                    "anomaly_score": float(
                        test_scores[
                            index
                        ]
                    ),

                    "command_count": len(
                        sessions_2024.iloc[
                            index
                        ][
                            "commands"
                        ]
                    ),

                    "commands_preview": (
                        " | ".join(
                            normalize_sequence(
                                sessions_2024.iloc[
                                    index
                                ][
                                    "commands"
                                ]
                            )[
                                :5
                            ]
                        )
                    ),
                }
            )

    top_df = pd.DataFrame(
        top_rows
    )

    top_df.to_csv(
        OUTPUT_DIR
        / "top_2024_anomalies.csv",
        index=False,
    )

    # ========================================================
    # REPRESENTATION COMPARISON
    # ========================================================

    log(
        "\n  Comparing 2024 anomaly rankings..."
    )

    test_score_table = (
        scores_df[
            scores_df[
                "dataset_role"
            ]
            == "temporal_holdout"
        ]
        .pivot(
            index="session_id",
            columns="representation",
            values="anomaly_score",
        )
    )

    ranking_correlation = (
        test_score_table.corr(
            method="spearman"
        )
    )

    ranking_correlation.to_csv(
        OUTPUT_DIR
        / "representation_comparison.csv"
    )

    # ========================================================
    # SAVE SUMMARY
    # ========================================================

    log(
        "\n[9/9] Creating summary..."
    )

    summary = {
        "step": 12,

        "name": (
            "temporal_anomaly_generalization"
        ),

        "training_period": (
            "2021_2022"
        ),

        "holdout_period": (
            "2024"
        ),

        "training_sessions": int(
            len(sessions_2021)
        ),

        "holdout_sessions": int(
            len(sessions_2024)
        ),

        "representations": [
            "aggregate",
            "sequence_stats",
            "tfidf",
        ],

        "detector": (
            "IsolationForest"
        ),

        "configuration": {
            "n_estimators": (
                IF_N_ESTIMATORS
            ),

            "contamination": (
                IF_CONTAMINATION
            ),

            "random_seed": 42,

            "tfidf_ngram_range": (
                list(
                    TFIDF_NGRAM_RANGE
                )
            ),

            "tfidf_min_df": (
                TFIDF_MIN_DF
            ),

            "tfidf_max_df": (
                TFIDF_MAX_DF
            ),

            "tfidf_max_features": (
                TFIDF_MAX_FEATURES
            ),
        },

        "temporal_metrics": (
            metrics_df.to_dict(
                orient="records"
            )
        ),

        "ranking_correlation_2024": (
            ranking_correlation.to_dict()
        ),

        "important_constraints": [
            (
                "The 2024 holdout was not used "
                "to fit Isolation Forest."
            ),

            (
                "The 2024 holdout was not used "
                "to fit RobustScaler."
            ),

            (
                "The 2024 holdout was not used "
                "to fit the TF-IDF vocabulary."
            ),
        ],

        "interpretation": [
            (
                "A temporal holdout is not a "
                "classification accuracy test because "
                "there is no anomaly ground truth here."
            ),

            (
                "A large score distribution shift "
                "can indicate temporal/domain shift."
            ),

            (
                "A small distribution shift does not "
                "prove that anomaly detection is correct."
            ),

            (
                "High anomaly scores do not establish "
                "maliciousness."
            ),
        ],

        "next_step": (
            "Validate the temporally evaluated "
            "representation on the independent 2025 "
            "SSH honeypot dataset and fresh Cowrie "
            "sessions before building the final "
            "risk engine."
        ),
    }

    save_json(
        OUTPUT_DIR
        / "temporal_summary.json",
        summary,
    )

    # ========================================================
    # FINAL CONSOLE OUTPUT
    # ========================================================

    log(
        "\n" + "=" * 70
    )

    log(
        "STEP 12 COMPLETE"
    )

    log(
        "=" * 70
    )

    log(
        "\nTemporal metrics:"
    )

    display_columns = [
        "representation",
        "features",
        "train_mean",
        "test_mean",
        "mean_shift_test_minus_train",
        "standardized_mean_shift",
        "train_p95",
        "test_p95",
        "test_above_train_95_rate",
        "test_above_train_99_rate",
    ]

    print(
        metrics_df[
            display_columns
        ].to_string(
            index=False
        )
    )

    log(
        "\n2024 representation ranking correlation:"
    )

    print(
        ranking_correlation.to_string()
    )

    log(
        "\nOutputs saved to:"
    )

    log(
        f"  {OUTPUT_DIR}"
    )

    log(
        "\nIMPORTANT:"
    )

    log(
        "2024 was treated as an unseen temporal holdout."
    )

    log(
        "Do not build the risk engine yet."
    )

    log(
        "Next: external validation using independent "
        "2025 SSH honeypot behavior."
    )


if __name__ == "__main__":
    main()