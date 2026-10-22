import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd


MANIFEST_PATH = Path(
    "data/generated/scenario_manifest.jsonl"
)

SESSIONS_PATH = Path(
    "data/processed/sessions/sessions.jsonl"
)

VALIDATED_DATASET_PATH = Path(
    "data/generated/validated_ml_dataset.jsonl"
)

AUDIT_REPORT_PATH = Path(
    "data/generated/dataset_diversity_audit.json"
)


# =============================================================
# LOAD JSONL
# =============================================================

def load_jsonl(path):

    records = []

    if not path.exists():

        print(
            f"ERROR: File not found: {path}"
        )

        return records

    with path.open(
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:

                records.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:

                pass

    return records


# =============================================================
# SCENARIO LABEL
# =============================================================

def get_scenario(record):

    return (
        record.get("scenario_label")
        or record.get("scenario_id")
        or record.get("scenario")
        or record.get("attack_type")
        or "unknown"
    )


# =============================================================
# COMMAND EXTRACTION
# =============================================================

def get_commands(record):

    commands = record.get(
        "commands",
        []
    )

    if isinstance(
        commands,
        list
    ):

        result = []

        for command in commands:

            if isinstance(
                command,
                str
            ):

                result.append(
                    command.strip()
                )

            elif isinstance(
                command,
                dict
            ):

                value = (
                    command.get("command")
                    or command.get("input")
                    or command.get("cmd")
                )

                if value:

                    result.append(
                        str(value).strip()
                    )

        return [
            command
            for command in result
            if command
        ]

    return []


# =============================================================
# MAIN
# =============================================================

def main():

    print("=" * 80)
    print("COMBINED DATASET DIVERSITY + ML AUDIT")
    print("=" * 80)

    # ---------------------------------------------------------
    # Load data
    # ---------------------------------------------------------

    manifest = load_jsonl(
        MANIFEST_PATH
    )

    sessions = load_jsonl(
        SESSIONS_PATH
    )

    validated = load_jsonl(
        VALIDATED_DATASET_PATH
    )

    print(
        f"\nManifest records       : "
        f"{len(manifest)}"
    )

    print(
        f"Cowrie sessions        : "
        f"{len(sessions)}"
    )

    print(
        f"Validated ML records   : "
        f"{len(validated)}"
    )

    if not manifest:

        print(
            "\nERROR: Manifest is empty."
        )

        return

    if not validated:

        print(
            "\nERROR: Validated ML dataset is empty."
        )

        return

    # =========================================================
    # 1. SCENARIO DISTRIBUTION
    # =========================================================

    scenario_counter = Counter()

    for record in manifest:

        scenario = get_scenario(
            record
        )

        scenario_counter[
            scenario
        ] += 1

    print("\n" + "-" * 80)
    print("1. SCENARIO DISTRIBUTION")
    print("-" * 80)

    for scenario, count in sorted(
        scenario_counter.items()
    ):

        print(
            f"{scenario:30} {count}"
        )

    # =========================================================
    # 2. VALIDATED DATASET CLASS DISTRIBUTION
    # =========================================================

    validated_labels = [
        get_scenario(record)
        for record in validated
    ]

    validated_class_counter = Counter(
        validated_labels
    )

    print("\n" + "-" * 80)
    print("2. VALIDATED ML DATASET CLASS DISTRIBUTION")
    print("-" * 80)

    for scenario, count in sorted(
        validated_class_counter.items()
    ):

        print(
            f"{scenario:30} {count}"
        )

    # =========================================================
    # 3. COMMAND SEQUENCE DIVERSITY
    # =========================================================

    sequences = []

    all_commands = []

    for record in manifest:

        commands = get_commands(
            record
        )

        if not commands:

            generated = record.get(
                "generated_commands"
            )

            if isinstance(
                generated,
                list
            ):

                commands = [
                    str(x).strip()
                    for x in generated
                    if str(x).strip()
                ]

        sequence = tuple(
            commands
        )

        sequences.append(
            sequence
        )

        all_commands.extend(
            commands
        )

    unique_sequences = set(
        sequences
    )

    print("\n" + "-" * 80)
    print("3. COMMAND SEQUENCE DIVERSITY")
    print("-" * 80)

    print(
        f"Total sessions              : "
        f"{len(sequences)}"
    )

    print(
        f"Unique command sequences    : "
        f"{len(unique_sequences)}"
    )

    sequence_diversity_ratio = 0.0

    if sequences:

        sequence_diversity_ratio = (
            len(unique_sequences)
            /
            len(sequences)
        )

        print(
            f"Sequence diversity ratio    : "
            f"{sequence_diversity_ratio:.3f}"
        )

    # =========================================================
    # 4. COMMAND DIVERSITY
    # =========================================================

    command_counter = Counter(
        all_commands
    )

    print("\n" + "-" * 80)
    print("4. COMMAND DIVERSITY")
    print("-" * 80)

    print(
        f"Total command executions    : "
        f"{len(all_commands)}"
    )

    print(
        f"Unique commands             : "
        f"{len(command_counter)}"
    )

    print(
        "\nMost common commands:"
    )

    for command, count in (
        command_counter.most_common(20)
    ):

        print(
            f"{count:4}  {command}"
        )

    # =========================================================
    # 5. SESSION LENGTH
    # =========================================================

    lengths = [
        len(sequence)
        for sequence in sequences
    ]

    print("\n" + "-" * 80)
    print("5. SESSION LENGTH")
    print("-" * 80)

    if lengths:

        print(
            f"Minimum commands/session    : "
            f"{min(lengths)}"
        )

        print(
            f"Maximum commands/session    : "
            f"{max(lengths)}"
        )

        print(
            f"Average commands/session    : "
            f"{statistics.mean(lengths):.2f}"
        )

        print(
            f"Median commands/session     : "
            f"{statistics.median(lengths):.2f}"
        )

        distribution = Counter(
            lengths
        )

        print(
            "\nSession length distribution:"
        )

        for length, count in sorted(
            distribution.items()
        ):

            print(
                f"{length:3} commands : {count}"
            )

    # =========================================================
    # 6. EXACT DUPLICATE SEQUENCES
    # =========================================================

    duplicate_groups = defaultdict(
        list
    )

    for index, sequence in enumerate(
        sequences
    ):

        duplicate_groups[
            sequence
        ].append(index)

    duplicates = {
        sequence: indexes
        for sequence, indexes
        in duplicate_groups.items()
        if len(indexes) > 1
    }

    print("\n" + "-" * 80)
    print("6. DUPLICATE COMMAND SEQUENCES")
    print("-" * 80)

    print(
        f"Duplicate sequence groups   : "
        f"{len(duplicates)}"
    )

    duplicated_sessions = sum(
        len(indexes)
        for indexes in duplicates.values()
    )

    print(
        f"Sessions in duplicate groups: "
        f"{duplicated_sessions}"
    )

    if duplicates:

        print(
            "\nTop duplicate groups:"
        )

        duplicate_list = sorted(
            duplicates.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )

        for sequence, indexes in (
            duplicate_list[:10]
        ):

            print(
                f"\nRepeated {len(indexes)} times:"
            )

            for command in sequence:

                print(
                    f"    {command}"
                )

    # =========================================================
    # 7. UNIQUE COMMANDS PER SCENARIO
    # =========================================================

    scenario_commands = defaultdict(
        set
    )

    for record in manifest:

        scenario = get_scenario(
            record
        )

        commands = get_commands(
            record
        )

        if not commands:

            generated = record.get(
                "generated_commands"
            )

            if isinstance(
                generated,
                list
            ):

                commands = [
                    str(x).strip()
                    for x in generated
                    if str(x).strip()
                ]

        scenario_commands[
            scenario
        ].update(
            commands
        )

    print("\n" + "-" * 80)
    print("7. UNIQUE COMMANDS PER SCENARIO")
    print("-" * 80)

    for scenario in sorted(
        scenario_commands
    ):

        commands = scenario_commands[
            scenario
        ]

        print(
            f"{scenario:30} "
            f"{len(commands):3} unique commands"
        )

        for command in sorted(
            commands
        ):

            print(
                f"    {command}"
            )

    # =========================================================
    # 8. UNIQUE SEQUENCES PER SCENARIO
    # =========================================================

    scenario_sequences = defaultdict(
        set
    )

    for record, sequence in zip(
        manifest,
        sequences
    ):

        scenario = get_scenario(
            record
        )

        scenario_sequences[
            scenario
        ].add(
            sequence
        )

    print("\n" + "-" * 80)
    print("8. UNIQUE SEQUENCES PER SCENARIO")
    print("-" * 80)

    scenario_sequence_counts = {}

    for scenario in sorted(
        scenario_sequences
    ):

        count = len(
            scenario_sequences[
                scenario
            ]
        )

        scenario_sequence_counts[
            scenario
        ] = count

        print(
            f"{scenario:30} "
            f"{count:4} unique sequences"
        )

    # =========================================================
    # 9. VALIDATED DATASET STRUCTURE
    # =========================================================

    print("\n" + "-" * 80)
    print("9. VALIDATED ML DATASET STRUCTURE")
    print("-" * 80)

    session_ids = [
        record.get(
            "session_id"
        )
        for record in validated
    ]

    run_ids = [
        record.get(
            "run_id"
        )
        for record in validated
    ]

    unique_session_ids = len(
        set(session_ids)
    )

    unique_run_ids = len(
        set(run_ids)
    )

    print(
        f"Validated records           : "
        f"{len(validated)}"
    )

    print(
        f"Unique session IDs          : "
        f"{unique_session_ids}"
    )

    print(
        f"Unique run IDs              : "
        f"{unique_run_ids}"
    )

    duplicate_session_ids = (
        len(session_ids)
        -
        unique_session_ids
    )

    duplicate_run_ids = (
        len(run_ids)
        -
        unique_run_ids
    )

    print(
        f"Duplicate session IDs       : "
        f"{duplicate_session_ids}"
    )

    print(
        f"Duplicate run IDs           : "
        f"{duplicate_run_ids}"
    )

    # =========================================================
    # 10. FEATURE SCHEMA
    # =========================================================

    print("\n" + "-" * 80)
    print("10. FEATURE SCHEMA")
    print("-" * 80)

    feature_schema_sets = []

    for record in validated:

        features = record.get(
            "features",
            {}
        )

        feature_schema_sets.append(
            set(features.keys())
        )

    schema_sizes = [
        len(schema)
        for schema in feature_schema_sets
    ]

    common_schema = (
        sorted(
            feature_schema_sets[0]
        )
        if feature_schema_sets
        else []
    )

    schema_consistent = all(
        schema == feature_schema_sets[0]
        for schema in feature_schema_sets
    ) if feature_schema_sets else False

    print(
        f"Minimum features/record     : "
        f"{min(schema_sizes)}"
    )

    print(
        f"Maximum features/record     : "
        f"{max(schema_sizes)}"
    )

    print(
        f"Unique schema sizes          : "
        f"{sorted(set(schema_sizes))}"
    )

    print(
        f"Schema identical across all : "
        f"{schema_consistent}"
    )

    print(
        "\nFeature names:"
    )

    for index, feature in enumerate(
        common_schema,
        start=1
    ):

        print(
            f"{index:2}. {feature}"
        )

    # =========================================================
    # 11. BUILD FEATURE DATAFRAME
    # =========================================================

    rows = []

    for record in validated:

        row = dict(
            record.get(
                "features",
                {}
            )
        )

        row["label"] = get_scenario(
            record
        )

        row["session_id"] = record.get(
            "session_id"
        )

        rows.append(
            row
        )

    df = pd.DataFrame(
        rows
    )

    feature_names = [
        column
        for column in common_schema
        if column in df.columns
    ]

    feature_df = df[
        feature_names
    ].apply(
        pd.to_numeric,
        errors="coerce"
    )

    # =========================================================
    # 12. MISSING / INVALID VALUES
    # =========================================================

    print("\n" + "-" * 80)
    print("11. MISSING / INVALID FEATURE VALUES")
    print("-" * 80)

    total_missing = int(
        feature_df.isna()
        .sum()
        .sum()
    )

    print(
        f"Total missing/invalid values: "
        f"{total_missing}"
    )

    invalid_columns = []

    for feature in feature_names:

        count = int(
            feature_df[
                feature
            ].isna().sum()
        )

        if count > 0:

            invalid_columns.append(
                (
                    feature,
                    count
                )
            )

    if invalid_columns:

        for feature, count in (
            invalid_columns
        ):

            print(
                f"  {feature}: {count}"
            )

    else:

        print(
            "No missing or invalid feature values."
        )

    # =========================================================
    # 13. CONSTANT FEATURES
    # =========================================================

    print("\n" + "-" * 80)
    print("12. CONSTANT FEATURES")
    print("-" * 80)

    constant_features = []

    for feature in feature_names:

        unique_count = (
            feature_df[
                feature
            ]
            .nunique(
                dropna=False
            )
        )

        if unique_count <= 1:

            constant_features.append(
                feature
            )

    if constant_features:

        for feature in constant_features:

            print(
                f"  - {feature}"
            )

    else:

        print(
            "No constant features."
        )

    # =========================================================
    # 14. NEAR-CONSTANT FEATURES
    # =========================================================

    print("\n" + "-" * 80)
    print("13. NEAR-CONSTANT FEATURES")
    print("-" * 80)

    near_constant_features = []

    for feature in feature_names:

        values = feature_df[
            feature
        ].dropna()

        if len(values) == 0:

            continue

        frequencies = (
            values
            .value_counts(
                normalize=True
            )
        )

        top_frequency = float(
            frequencies.iloc[0]
        )

        if top_frequency >= 0.995:

            near_constant_features.append(
                (
                    feature,
                    top_frequency
                )
            )

    if near_constant_features:

        for feature, frequency in (
            near_constant_features
        ):

            print(
                f"  - {feature}: "
                f"{frequency:.4f}"
            )

    else:

        print(
            "No near-constant features "
            "(>=99.5% same value)."
        )

    # =========================================================
    # 15. DUPLICATE FEATURE VECTORS
    # =========================================================

    print("\n" + "-" * 80)
    print("14. DUPLICATE FEATURE VECTORS")
    print("-" * 80)

    duplicate_mask = feature_df.duplicated(
        keep=False
    )

    duplicate_record_count = int(
        duplicate_mask.sum()
    )

    duplicate_group_count = int(
        feature_df[
            duplicate_mask
        ]
        .drop_duplicates()
        .shape[0]
    )

    print(
        f"Records involved            : "
        f"{duplicate_record_count}"
    )

    print(
        f"Duplicate vector groups     : "
        f"{duplicate_group_count}"
    )

    # =========================================================
    # 16. CONFLICTING DUPLICATE VECTORS
    # =========================================================

    print("\n" + "-" * 80)
    print("15. DUPLICATE FEATURES WITH CONFLICTING LABELS")
    print("-" * 80)

    conflicting_groups = 0
    conflicting_records = 0

    grouped = df.groupby(
        feature_names,
        dropna=False
    )

    for _, group in grouped:

        unique_labels = (
            group["label"]
            .nunique()
        )

        if unique_labels > 1:

            conflicting_groups += 1

            conflicting_records += (
                len(group)
            )

    print(
        f"Conflicting groups          : "
        f"{conflicting_groups}"
    )

    print(
        f"Records involved             : "
        f"{conflicting_records}"
    )

    # =========================================================
    # 17. PER-CLASS FEATURE VARIATION
    # =========================================================

    print("\n" + "-" * 80)
    print("16. PER-CLASS FEATURE VARIATION")
    print("-" * 80)

    per_class_zero_variance = {}

    for label in sorted(
        validated_class_counter
    ):

        class_df = feature_df[
            df["label"] == label
        ]

        zero_variance_features = []

        for feature in feature_names:

            if (
                class_df[
                    feature
                ]
                .nunique(
                    dropna=False
                )
                <= 1
            ):

                zero_variance_features.append(
                    feature
                )

        per_class_zero_variance[
            label
        ] = zero_variance_features

        print(
            f"{label:30} "
            f"{len(zero_variance_features)} "
            f"zero-variance features"
        )

        if zero_variance_features:

            for feature in (
                zero_variance_features
            ):

                print(
                    f"    - {feature}"
                )

    # =========================================================
    # 18. FEATURE / LABEL CORRELATION
    # =========================================================

    print("\n" + "-" * 80)
    print("17. FEATURE / CLASS SEPARATION CHECK")
    print("-" * 80)

    label_codes = pd.Categorical(
        df["label"]
    ).codes

    correlations = []

    for feature in feature_names:

        values = feature_df[
            feature
        ].to_numpy(
            dtype=float
        )

        if (
            len(values) == 0
            or np.std(values) == 0
        ):

            continue

        correlation = np.corrcoef(
            values,
            label_codes
        )[0, 1]

        if math.isnan(
            correlation
        ):

            continue

        correlations.append(
            (
                feature,
                abs(correlation),
                correlation
            )
        )

    correlations.sort(
        key=lambda x: x[1],
        reverse=True
    )

    print(
        "\nTop feature/class correlations:"
    )

    for (
        feature,
        absolute_corr,
        correlation
    ) in correlations[:20]:

        print(
            f"{feature:30} "
            f"abs={absolute_corr:.4f} "
            f"corr={correlation:.4f}"
        )

    # =========================================================
    # 19. FEATURE STATISTICS
    # =========================================================

    print("\n" + "-" * 80)
    print("18. FEATURE STATISTICS")
    print("-" * 80)

    statistics_rows = []

    for feature in feature_names:

        values = feature_df[
            feature
        ].dropna()

        statistics_rows.append(
            {
                "feature":
                    feature,

                "min":
                    values.min(),

                "max":
                    values.max(),

                "mean":
                    values.mean(),

                "std":
                    values.std(),

                "unique":
                    values.nunique()
            }
        )

    statistics_df = pd.DataFrame(
        statistics_rows
    )

    print(
        statistics_df.to_string(
            index=False
        )
    )

    # =========================================================
    # 20. FINAL ASSESSMENT
    # =========================================================

    print("\n" + "=" * 80)
    print("FINAL DATASET AUDIT")
    print("=" * 80)

    # ---------------------------------------------------------
    # Structural checks
    # ---------------------------------------------------------

    expected_records = 5040

    expected_classes = 9

    expected_records_per_class = 560

    structural_pass = (
        len(validated) == expected_records
        and
        len(validated_class_counter)
        == expected_classes
        and
        all(
            count
            == expected_records_per_class
            for count
            in validated_class_counter.values()
        )
        and
        unique_session_ids
        == len(validated)
        and
        duplicate_session_ids == 0
        and
        duplicate_run_ids == 0
        and
        schema_consistent
        and
        min(schema_sizes) == 33
        and
        max(schema_sizes) == 33
    )

    # ---------------------------------------------------------
    # Feature quality checks
    # ---------------------------------------------------------

    feature_quality_pass = (
        total_missing == 0
        and
        len(constant_features) == 0
    )

    # ---------------------------------------------------------
    # Diversity check
    # ---------------------------------------------------------

    diversity_pass = (
        sequence_diversity_ratio >= 0.80
        and
        len(command_counter) >= 30
    )

    # ---------------------------------------------------------
    # Conflicting duplicate vectors
    # ---------------------------------------------------------

    conflict_pass = (
        conflicting_groups == 0
    )

    # ---------------------------------------------------------
    # Overall status
    # ---------------------------------------------------------

    print(
        f"\nStructural checks : "
        f"{'PASS' if structural_pass else 'FAIL'}"
    )

    print(
        f"Feature checks    : "
        f"{'PASS' if feature_quality_pass else 'FAIL'}"
    )

    print(
        f"Diversity checks  : "
        f"{'PASS' if diversity_pass else 'REVIEW'}"
    )

    print(
        f"Duplicate-label check : "
        f"{'PASS' if conflict_pass else 'REVIEW'}"
    )

    if (
        structural_pass
        and
        feature_quality_pass
        and
        diversity_pass
        and
        conflict_pass
    ):

        overall_assessment = (
            "DATASET STRUCTURALLY READY "
            "FOR MODEL EVALUATION"
        )

    elif (
        structural_pass
        and
        feature_quality_pass
    ):

        overall_assessment = (
            "DATASET VALID BUT "
            "REQUIRES DIVERSITY REVIEW"
        )

    else:

        overall_assessment = (
            "DATASET REQUIRES CORRECTION "
            "BEFORE ML TRAINING"
        )

    print(
        f"\nAssessment: "
        f"{overall_assessment}"
    )

    print(
        "\nImportant:"
    )

    print(
        "This audit checks structural integrity, "
        "feature quality, duplicates and basic "
        "diversity. It does NOT prove that the "
        "dataset is realistic or free from "
        "shortcut learning."
    )

    # =========================================================
    # SAVE REPORT
    # =========================================================

    report = {

        "manifest_records":
            len(manifest),

        "cowrie_sessions":
            len(sessions),

        "validated_records":
            len(validated),

        "manifest_scenario_distribution":
            dict(
                sorted(
                    scenario_counter.items()
                )
            ),

        "validated_class_distribution":
            dict(
                sorted(
                    validated_class_counter.items()
                )
            ),

        "unique_sequences":
            len(unique_sequences),

        "sequence_diversity_ratio":
            sequence_diversity_ratio,

        "total_command_executions":
            len(all_commands),

        "unique_commands":
            len(command_counter),

        "minimum_commands_per_session":
            min(lengths)
            if lengths
            else 0,

        "maximum_commands_per_session":
            max(lengths)
            if lengths
            else 0,

        "average_commands_per_session":
            statistics.mean(lengths)
            if lengths
            else 0,

        "median_commands_per_session":
            statistics.median(lengths)
            if lengths
            else 0,

        "duplicate_sequence_groups":
            len(duplicates),

        "duplicated_sessions":
            duplicated_sessions,

        "scenario_unique_sequence_counts":
            scenario_sequence_counts,

        "unique_session_ids":
            unique_session_ids,

        "unique_run_ids":
            unique_run_ids,

        "duplicate_session_ids":
            duplicate_session_ids,

        "duplicate_run_ids":
            duplicate_run_ids,

        "feature_count":
            len(feature_names),

        "feature_schema_consistent":
            schema_consistent,

        "missing_or_invalid_values":
            total_missing,

        "constant_features":
            constant_features,

        "near_constant_features":
            [
                {
                    "feature":
                        feature,

                    "top_frequency":
                        frequency
                }

                for feature, frequency
                in near_constant_features
            ],

        "duplicate_feature_records":
            duplicate_record_count,

        "duplicate_feature_groups":
            duplicate_group_count,

        "conflicting_duplicate_groups":
            conflicting_groups,

        "conflicting_duplicate_records":
            conflicting_records,

        "per_class_zero_variance":
            per_class_zero_variance,

        "top_feature_class_correlations":
            [
                {
                    "feature":
                        feature,

                    "absolute_correlation":
                        absolute_corr,

                    "correlation":
                        correlation
                }

                for (
                    feature,
                    absolute_corr,
                    correlation
                )
                in correlations[:20]
            ],

        "structural_pass":
            structural_pass,

        "feature_quality_pass":
            feature_quality_pass,

        "diversity_pass":
            diversity_pass,

        "conflict_pass":
            conflict_pass,

        "assessment":
            overall_assessment
    }

    AUDIT_REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with AUDIT_REPORT_PATH.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=2
        )

    print(
        f"\nAudit report saved to:"
        f"\n{AUDIT_REPORT_PATH}"
    )

    print(
        "\n" + "=" * 80
    )
    print(
        "AUDIT COMPLETE"
    )
    print(
        "=" * 80
    )


if __name__ == "__main__":
    main()