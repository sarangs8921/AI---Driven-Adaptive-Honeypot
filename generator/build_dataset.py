from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from collections import Counter

# ============================================================
# FILES
# ============================================================

MANIFEST_FILE = Path(
    "data/generated/scenario_manifest.jsonl"
)

SESSIONS_FILE = Path(
    "data/processed/sessions/sessions.jsonl"
)

FEATURES_FILE = Path(
    "data/generated/dataset_features.jsonl"
)

OUTPUT_FILE = Path(
    "data/generated/validated_dataset.jsonl"
)


# ============================================================
# LOAD JSONL
# ============================================================

def load_jsonl(path: Path) -> list[dict]:
    """
    Load a JSONL file.
    """

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    records = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1,
        ):

            line = line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )

            except json.JSONDecodeError as exc:

                raise ValueError(
                    f"Invalid JSON in {path} "
                    f"at line {line_number}: {exc}"
                )

    return records


# ============================================================
# TIMESTAMP HELPER
# ============================================================

def session_sort_key(session: dict):
    """
    Return a deterministic timestamp key.

    Newer sessions should sort after older sessions.

    Supports common timestamp fields used by the collector.
    """

    candidates = [
        session.get("end_time"),
        session.get("start_time"),
        session.get("timestamp"),
        session.get("created_at"),
    ]

    for value in candidates:

        if not value:
            continue

        if isinstance(value, (int, float)):
            return float(value)

        if isinstance(value, str):

            text = value.strip()

            # ISO timestamp
            try:
                normalized = text.replace(
                    "Z",
                    "+00:00",
                )

                return datetime.fromisoformat(
                    normalized
                ).timestamp()

            except ValueError:
                pass

            # Numeric string
            try:
                return float(text)

            except ValueError:
                pass

    # If no usable timestamp exists,
    # preserve file order as a fallback.
    return 0.0


# ============================================================
# FIND DATASET MARKER
# ============================================================

def extract_run_id_from_session(
    session: dict,
):
    """
    Search all commands in a reconstructed Cowrie
    session for:

        echo DATASET_RUN_<run_id>

    Returns the run_id if found.
    """

    commands = session.get(
        "commands",
        []
    )

    prefix = "echo DATASET_RUN_"

    for command_record in commands:

        if isinstance(
            command_record,
            dict,
        ):

            command = command_record.get(
                "command",
                ""
            )

        else:

            command = str(
                command_record
            )

        command = command.strip()

        if command.startswith(prefix):

            run_id = command[
                len(prefix):
            ].strip()

            if run_id:
                return run_id

    return None


# ============================================================
# BUILD RUN-ID → SESSION MAP
# ============================================================

def build_marker_session_map(
    sessions: list[dict],
):
    """
    Create:

        run_id -> newest Cowrie session

    If the same dataset marker appears in multiple sessions,
    the newest session is selected.

    This is important because the Cowrie log contains historical
    sessions from previous dataset-generation runs.
    """

    candidates = {}

    for index, session in enumerate(
        sessions
    ):

        run_id = (
            extract_run_id_from_session(
                session
            )
        )

        if run_id is None:
            continue

        session_id = session.get(
            "session_id"
        )

        if not session_id:
            continue

        candidates.setdefault(
            run_id,
            []
        ).append(
            (
                session_sort_key(
                    session
                ),
                index,
                session,
            )
        )

    mapping = {}

    duplicate_markers = []

    for run_id, session_candidates in candidates.items():

        if len(session_candidates) > 1:

            duplicate_markers.append(
                run_id
            )

        # Sort by timestamp first, then original
        # file position.
        session_candidates.sort(
            key=lambda item: (
                item[0],
                item[1],
            )
        )

        # Last = newest.
        mapping[run_id] = (
            session_candidates[-1][2]
        )

    return (
        mapping,
        duplicate_markers,
    )


# ============================================================
# BUILD SESSION-ID → FEATURE MAP
# ============================================================

def build_feature_map(
    features: list[dict],
):
    """
    Create:

        session_id -> feature record
    """

    mapping = {}

    duplicate_sessions = []

    for feature in features:

        session_id = feature.get(
            "session_id"
        )

        if not session_id:
            continue

        if session_id in mapping:

            duplicate_sessions.append(
                session_id
            )

            continue

        mapping[session_id] = feature

    return (
        mapping,
        duplicate_sessions,
    )


# ============================================================
# BUILD DATASET
# ============================================================

def main():

    print("=" * 60)
    print("DETERMINISTIC DATASET BUILDER")
    print("=" * 60)

    # --------------------------------------------------------
    # Load files
    # --------------------------------------------------------

    manifest = load_jsonl(
        MANIFEST_FILE
    )

    sessions = load_jsonl(
        SESSIONS_FILE
    )

    features = load_jsonl(
        FEATURES_FILE
    )

    print(
        f"Manifest records : "
        f"{len(manifest)}"
    )

    print(
        f"Cowrie sessions  : "
        f"{len(sessions)}"
    )

    print(
        f"Feature records  : "
        f"{len(features)}"
    )

    # --------------------------------------------------------
    # Build marker map
    # --------------------------------------------------------

    (
        marker_session_map,
        duplicate_markers,
    ) = build_marker_session_map(
        sessions
    )

    print(
        f"Sessions with dataset markers: "
        f"{len(marker_session_map)}"
    )

    if duplicate_markers:

        print(
            f"WARNING: duplicate dataset markers: "
            f"{len(duplicate_markers)}"
        )

        print(
            "Duplicate markers are resolved by selecting "
            "the newest matching session."
        )

    # --------------------------------------------------------
    # Build feature map
    # --------------------------------------------------------

    (
        feature_map,
        duplicate_features,
    ) = build_feature_map(
        features
    )

    if duplicate_features:

        print(
            f"WARNING: duplicate feature session IDs: "
            f"{len(duplicate_features)}"
        )

    # --------------------------------------------------------
    # Match manifest → session → feature
    # --------------------------------------------------------

    validated_records = []

    unmatched_manifest = []

    missing_features = []

    for record in manifest:

        # ----------------------------------------------------
        # Only completed scenarios
        # ----------------------------------------------------

        status = record.get(
            "status",
            "completed",
        )

        if status not in {
            "completed",
            "success",
            "successful",
        }:

            continue

        run_id = record.get(
            "run_id"
        )

        if not run_id:
            unmatched_manifest.append(
                (
                    record,
                    "missing_run_id",
                )
            )

            continue

        # ----------------------------------------------------
        # Find Cowrie session
        # ----------------------------------------------------

        session = marker_session_map.get(
            run_id
        )

        if session is None:

            unmatched_manifest.append(
                (
                    record,
                    "no_matching_session",
                )
            )

            continue

        session_id = session.get(
            "session_id"
        )

        if not session_id:

            unmatched_manifest.append(
                (
                    record,
                    "session_missing_id",
                )
            )

            continue

        # ----------------------------------------------------
        # Find feature record
        # ----------------------------------------------------

        feature = feature_map.get(
            session_id
        )

        if feature is None:

            missing_features.append(
                (
                    run_id,
                    session_id,
                )
            )

            continue

        # ----------------------------------------------------
        # Extract expected behavior information
        # ----------------------------------------------------

        expected_behaviors = record.get(
            "expected_behaviors",
            []
        )

        scenario_label = record.get(
            "scenario_label"
        )

        # ----------------------------------------------------
        # Combine feature record + dataset metadata
        # ----------------------------------------------------

        combined = dict(
            feature
        )

        combined[
            "scenario_label"
        ] = scenario_label

        combined[
            "expected_behaviors"
        ] = expected_behaviors

        combined[
            "run_id"
        ] = run_id

        combined[
            "random_seed"
        ] = record.get(
            "random_seed"
        )

        combined[
            "repetition"
        ] = record.get(
            "repetition"
        )

        combined[
            "session_id"
        ] = session_id

        combined[
            "dataset_marker"
        ] = (
            f"echo DATASET_RUN_{run_id}"
        )

        validated_records.append(
            combined
        )

    # ========================================================
    # WRITE OUTPUT
    # ========================================================

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        for record in validated_records:

            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print(
        f"Matched   : "
        f"{len(validated_records)}"
    )

    print(
        f"Unmatched : "
        f"{len(unmatched_manifest)}"
    )

    print(
        f"Missing features: "
        f"{len(missing_features)}"
    )

    print()

    # --------------------------------------------------------
    # Scenario distribution
    # --------------------------------------------------------

    scenario_counts = Counter(
        record.get(
            "scenario_label"
        )
        for record in validated_records
    )

    print(
        "Scenario distribution:"
    )

    for scenario, count in sorted(
        scenario_counts.items()
    ):

        print(
            f"  {scenario} "
            f"{count}"
        )

    # --------------------------------------------------------
    # Print unmatched details
    # --------------------------------------------------------

    if unmatched_manifest:

        print()
        print(
            "Unmatched manifest records:"
        )

        for record, reason in (
            unmatched_manifest
        ):

            print(
                f"  run_id="
                f"{record.get('run_id')} "
                f"reason={reason}"
            )

    # --------------------------------------------------------
    # Print missing feature details
    # --------------------------------------------------------

    if missing_features:

        print()
        print(
            "Missing feature records:"
        )

        for run_id, session_id in (
            missing_features
        ):

            print(
                f"  run_id={run_id} "
                f"session_id={session_id}"
            )

    print()
    print(
        f"Output: {OUTPUT_FILE}"
    )

    print(
        "Dataset build complete."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()