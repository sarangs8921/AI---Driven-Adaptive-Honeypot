from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


INPUT_FILE = Path(
    "data/processed/sessions/risk_sessions.jsonl"
)

OUTPUT_FILE = Path(
    "data/generated/dataset_features.jsonl"
)


BEHAVIORS = [
    "account_discovery",
    "system_discovery",
    "file_discovery",
    "process_discovery",
    "network_discovery",
    "credential_access",
    "file_access",
    "execution",
    "file_transfer",
    "privilege_activity",
    "persistence",
    "file_modification",
    "defense_evasion",
]


# ============================================================
# LOAD SESSIONS
# ============================================================

def load_sessions():
    sessions = []

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            sessions.append(
                json.loads(line)
            )

    return sessions


# ============================================================
# EXTRACT FEATURES
# ============================================================

def extract_features(
    session: dict,
) -> dict:

    commands = session.get(
        "commands",
        []
    )

    analyzed_commands = session.get(
        "analyzed_commands",
        []
    )

    behavior_counts = session.get(
        "behavior_counts",
        {}
    )

    # --------------------------------------------------------
    # Command text
    # --------------------------------------------------------

    command_texts = [
        item.get(
            "command",
            ""
        ).strip()

        for item in commands

        if isinstance(item, dict)
        and item.get("command")
    ]

    command_counter = Counter(
        command_texts
    )

    # --------------------------------------------------------
    # Base session features
    # --------------------------------------------------------

    features = {

        "session_id":
            session.get(
                "session_id"
            ),

        # ----------------------------------------------------
        # Session-level features
        # ----------------------------------------------------

        "duration_ms":
            session.get(
                "duration_ms",
                0,
            ),

        "event_count":
            session.get(
                "event_count",
                0,
            ),

        "command_count":
            len(commands),

        "unique_command_count":
            len(
                set(command_texts)
            ),

        "empty_command_count":
            session.get(
                "empty_command_count",
                0,
            ),

        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        "successful_auth":
            int(
                session.get(
                    "authentication",
                    {},
                ).get(
                    "successful",
                    False,
                )
            ),

        "failed_attempts":
            session.get(
                "authentication",
                {},
            ).get(
                "failed_attempts",
                0,
            ),

        # ----------------------------------------------------
        # Command statistics
        # ----------------------------------------------------

        "repeated_command_count":
            sum(
                count - 1
                for count in command_counter.values()
                if count > 1
            ),

        "max_command_frequency":
            (
                max(
                    command_counter.values()
                )
                if command_counter
                else 0
            ),
    }

    # ========================================================
    # BEHAVIOR FEATURES
    # ========================================================

    for behavior in BEHAVIORS:

        features[
            f"{behavior}_count"
        ] = behavior_counts.get(
            behavior,
            0,
        )

    # --------------------------------------------------------
    # Distinct behavior count
    # --------------------------------------------------------

    detected_behaviors = [
        behavior

        for behavior in BEHAVIORS

        if behavior_counts.get(
            behavior,
            0
        ) > 0
    ]

    features[
        "distinct_behavior_count"
    ] = len(
        detected_behaviors
    )

    # --------------------------------------------------------
    # Commands that triggered behaviors
    # --------------------------------------------------------

    behavior_triggered_commands = 0

    for command in analyzed_commands:

        if not isinstance(
            command,
            dict,
        ):
            continue

        if command.get(
            "behaviors"
        ):

            behavior_triggered_commands += 1

    features[
        "behavior_triggered_command_count"
    ] = behavior_triggered_commands

    # ========================================================
    # EXPLICIT BEHAVIOR METADATA
    # ========================================================
    #
    # These fields are NOT intended to be used blindly as
    # ML input features.
    #
    # They preserve the analyzer's output so that we can
    # audit:
    #
    # expected behavior vs detected behavior
    #
    # ========================================================

    features[
        "behaviors"
    ] = detected_behaviors

    features[
        "behavior_counts"
    ] = behavior_counts

    # --------------------------------------------------------
    # ATT&CK technique IDs detected by analyzer
    # --------------------------------------------------------

    technique_ids = session.get(
        "technique_ids",
        []
    )

    features[
        "technique_ids"
    ] = technique_ids

    # ========================================================
    # RISK INFORMATION
    # ========================================================

    risk = session.get(
        "risk",
        {}
    )

    features[
        "risk_score"
    ] = risk.get(
        "score",
        0,
    )

    features[
        "risk_behavior_score"
    ] = risk.get(
        "behavior_score",
        0,
    )

    features[
        "risk_progression_score"
    ] = risk.get(
        "progression_score",
        0,
    )

    features[
        "risk_authentication_score"
    ] = risk.get(
        "authentication_score",
        0,
    )

    features[
        "risk_state"
    ] = risk.get(
        "state",
        "LOW",
    )

    return features


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("DATASET FEATURE EXTRACTOR")
    print("=" * 60)

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"Input file not found: "
            f"{INPUT_FILE}"
        )

    sessions = load_sessions()

    print(
        f"Sessions loaded: "
        f"{len(sessions)}"
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as f:

        for session in sessions:

            features = extract_features(
                session
            )

            f.write(
                json.dumps(
                    features,
                    ensure_ascii=False,
                )
                + "\n"
            )

    print(
        f"Features generated: "
        f"{len(sessions)}"
    )

    print(
        f"Output: "
        f"{OUTPUT_FILE}"
    )

    print()
    print(
        "Feature extraction complete."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()