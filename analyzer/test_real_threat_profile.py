import json
from pathlib import Path

from analyzer.threat_profiler import ThreatProfiler


RISK_FILE = Path(
    "data/processed/sessions/risk_sessions.jsonl"
)

FEATURE_FILE = Path(
    "data/generated/ml_features.jsonl"
)


def load_jsonl(path):
    records = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            records.append(
                json.loads(line)
            )

    return records


def main():

    print("=" * 70)
    print("REAL THREAT PROFILE INTEGRATION TEST")
    print("=" * 70)

    # --------------------------------------------------------
    # Check files
    # --------------------------------------------------------

    if not RISK_FILE.exists():

        raise FileNotFoundError(
            f"Risk dataset not found: {RISK_FILE}"
        )

    if not FEATURE_FILE.exists():

        raise FileNotFoundError(
            f"ML feature dataset not found: {FEATURE_FILE}"
        )

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    risk_records = load_jsonl(
        RISK_FILE
    )

    feature_records = load_jsonl(
        FEATURE_FILE
    )

    print(
        f"Risk records loaded    : "
        f"{len(risk_records)}"
    )

    print(
        f"Feature records loaded : "
        f"{len(feature_records)}"
    )

    # --------------------------------------------------------
    # Index ML features by session ID
    # --------------------------------------------------------

    feature_index = {}

    for record in feature_records:

        session_id = record.get(
            "session_id"
        )

        if session_id:

            feature_index[
                session_id
            ] = record

    print(
        f"Indexed ML sessions    : "
        f"{len(feature_index)}"
    )

    # --------------------------------------------------------
    # Find a session with useful behavior
    # --------------------------------------------------------

    selected = None

    for session in risk_records:

        behaviors = session.get(
            "behaviors",
            [],
        )

        if behaviors:

            session_id = session.get(
                "session_id"
            )

            if session_id in feature_index:

                selected = session

                break

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    if selected is None:

        raise RuntimeError(
            "Could not find a risk session "
            "with matching ML features."
        )

    session_id = selected[
        "session_id"
    ]

    feature_record = feature_index[
        session_id
    ]

    features = feature_record[
        "features"
    ]

    # --------------------------------------------------------
    # Display source information
    # --------------------------------------------------------

    print()
    print("SELECTED SESSION")
    print("-" * 70)

    print(
        f"Session ID : {session_id}"
    )

    print(
        "Behaviors:"
    )

    for behavior in selected.get(
        "behaviors",
        [],
    ):

        print(
            f"  - {behavior}"
        )

    print()
    print(
        "Behavior counts:"
    )

    for behavior, count in selected.get(
        "behavior_counts",
        {},
    ).items():

        print(
            f"  {behavior:<25} {count}"
        )

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    print()
    print("Authentication:")

    print(
        json.dumps(
            selected.get(
                "authentication",
                {},
            ),
            indent=2,
        )
    )

    # --------------------------------------------------------
    # Run profiler
    # --------------------------------------------------------

    profiler = ThreatProfiler()

    profile = profiler.profile_session(

        session_id=session_id,

        features=features,

        observed_behaviors=selected.get(
            "behaviors",
            [],
        ),

        behavior_counts=selected.get(
            "behavior_counts",
            {},
        ),

        authentication=selected.get(
            "authentication",
            {},
        ),
    )

    # --------------------------------------------------------
    # Display ML result
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("ML THREAT PROFILE")
    print("=" * 70)

    print(
        f"Predicted class : "
        f"{profile['predicted_class']}"
    )

    print(
        f"Confidence      : "
        f"{profile['prediction_confidence']:.4f}"
    )

    # --------------------------------------------------------
    # Display risk result
    # --------------------------------------------------------

    risk = profile[
        "risk"
    ]

    print()
    print("=" * 70)
    print("RISK ASSESSMENT")
    print("=" * 70)

    print(
        f"Risk score             : "
        f"{risk['score']}"
    )

    print(
        f"Risk state             : "
        f"{risk['state']}"
    )

    print(
        f"Behavior score         : "
        f"{risk['behavior_score']}"
    )

    print(
        f"Progression score     : "
        f"{risk['progression_score']}"
    )

    print(
        f"Authentication score : "
        f"{risk['authentication_score']}"
    )

    # --------------------------------------------------------
    # Risk reasons
    # --------------------------------------------------------

    print()
    print("Risk reasons:")

    if risk["reasons"]:

        for reason in risk[
            "reasons"
        ]:

            print(
                f"  - {reason}"
            )

    else:

        print(
            "  None"
        )

    # --------------------------------------------------------
    # SHAP
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("TOP SHAP EXPLANATIONS")
    print("=" * 70)

    for item in profile[
        "top_shap_features"
    ]:

        print(
            f"{item['feature']:<35} "
            f"{item['shap_value']:+.6f}"
        )

    # --------------------------------------------------------
    # Final JSON
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("COMPLETE PROFILE")
    print("=" * 70)

    print(
        json.dumps(
            profile,
            indent=2,
        )
    )

    print()
    print("=" * 70)
    print("REAL INTEGRATION TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":

    main()