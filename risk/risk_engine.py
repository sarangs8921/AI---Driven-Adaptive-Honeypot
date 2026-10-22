import json
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

INPUT_FILE = Path(
    "data/processed/sessions/analyzed_sessions.jsonl"
)

OUTPUT_FILE = Path(
    "data/processed/sessions/risk_sessions.jsonl"
)


# ============================================================
# Base behavior weights
# ============================================================

BEHAVIOR_WEIGHTS = {
    "account_discovery": 5,
    "system_discovery": 5,
    "file_discovery": 5,
    "process_discovery": 5,
    "network_discovery": 5,

    "file_access": 5,

    "credential_access": 15,

    "execution": 10,

    "file_transfer": 10,

    "privilege_activity": 15,

    "file_modification": 10,

    "persistence": 20,

    "defense_evasion": 15,
}


# ============================================================
# Risk thresholds
# ============================================================

def get_risk_state(score):
    """
    Convert a numerical score into a threat state.
    """

    if score >= 70:
        return "CRITICAL"

    if score >= 45:
        return "HIGH"

    if score >= 20:
        return "MEDIUM"

    return "LOW"


# ============================================================
# Calculate behavioral score
# ============================================================

def calculate_behavior_score(behavior_counts):
    """
    Calculate a base score from detected behaviors.

    Each behavior category contributes according to its
    predefined weight.

    Multiple repetitions are deliberately limited so that
    repeating one harmless command cannot dominate the score.
    """

    score = 0
    contributions = {}

    for behavior, count in behavior_counts.items():

        weight = BEHAVIOR_WEIGHTS.get(behavior, 0)

        if weight == 0:
            continue

        # Limit repetition impact.
        effective_count = min(count, 3)

        contribution = weight * effective_count

        score += contribution

        contributions[behavior] = contribution

    return score, contributions


# ============================================================
# Detect behavioral progression
# ============================================================

def calculate_progression_bonus(behaviors):
    """
    Reward the presence of multiple stages in a session.

    This is not an ATT&CK classifier. It simply identifies
    whether the session progressed through several different
    behavioral categories.
    """

    bonus = 0
    reasons = []

    behavior_set = set(behaviors)

    discovery_behaviors = {
        "account_discovery",
        "system_discovery",
        "file_discovery",
        "process_discovery",
        "network_discovery",
    }

    has_discovery = bool(
        behavior_set.intersection(discovery_behaviors)
    )

    has_credential = (
        "credential_access" in behavior_set
    )

    has_transfer = (
        "file_transfer" in behavior_set
    )

    has_execution = (
        "execution" in behavior_set
    )

    has_persistence = (
        "persistence" in behavior_set
    )

    # Discovery → credential access
    if has_discovery and has_credential:
        bonus += 10
        reasons.append(
            "Discovery followed by credential-related activity"
        )

    # Transfer → execution
    if has_transfer and has_execution:
        bonus += 10
        reasons.append(
            "File transfer combined with execution"
        )

    # Credential → persistence
    if has_credential and has_persistence:
        bonus += 15
        reasons.append(
            "Credential access combined with persistence"
        )

    # Multi-stage behavior
    if len(behavior_set) >= 4:
        bonus += 10
        reasons.append(
            "Multiple distinct behavioral stages observed"
        )

    return bonus, reasons


# ============================================================
# Authentication contribution
# ============================================================

def calculate_authentication_score(authentication):
    """
    Add a small contribution for repeated failed authentication.
    """

    failed_attempts = authentication.get(
        "failed_attempts",
        0,
    )

    if failed_attempts >= 10:
        return 15, "High number of failed authentication attempts"

    if failed_attempts >= 5:
        return 10, "Repeated failed authentication attempts"

    if failed_attempts >= 2:
        return 5, "Multiple failed authentication attempts"

    return 0, None


# ============================================================
# Analyze one session
# ============================================================

def analyze_risk(session):

    behavior_counts = session.get(
        "behavior_counts",
        {},
    )

    behaviors = session.get(
        "behaviors",
        [],
    )

    authentication = session.get(
        "authentication",
        {},
    )

    # --------------------------------------------------------
    # Base behavioral score
    # --------------------------------------------------------

    behavior_score, contributions = (
        calculate_behavior_score(
            behavior_counts
        )
    )

    # --------------------------------------------------------
    # Progression score
    # --------------------------------------------------------

    progression_score, progression_reasons = (
        calculate_progression_bonus(
            behaviors
        )
    )

    # --------------------------------------------------------
    # Authentication score
    # --------------------------------------------------------

    authentication_score, authentication_reason = (
        calculate_authentication_score(
            authentication
        )
    )

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    raw_score = (
        behavior_score
        + progression_score
        + authentication_score
    )

    # Keep score within 0–100.
    risk_score = min(raw_score, 100)

    risk_state = get_risk_state(
        risk_score
    )

    # --------------------------------------------------------
    # Build explanations
    # --------------------------------------------------------

    reasons = []

    for behavior, contribution in contributions.items():

        reasons.append(
            f"{behavior}: +{contribution}"
        )

    reasons.extend(
        progression_reasons
    )

    if authentication_reason:
        reasons.append(
            authentication_reason
        )

    # --------------------------------------------------------
    # Add result
    # --------------------------------------------------------

    result = dict(session)

    result["risk"] = {
        "score": risk_score,
        "state": risk_state,
        "behavior_score": behavior_score,
        "progression_score": progression_score,
        "authentication_score": authentication_score,
        "reasons": reasons,
    }

    return result


# ============================================================
# Load sessions
# ============================================================

def load_sessions():

    sessions = []

    if not INPUT_FILE.exists():

        print(
            f"ERROR: Input file not found: "
            f"{INPUT_FILE}"
        )

        return sessions

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                sessions.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:

                print(
                    "WARNING: Invalid JSON skipped."
                )

    return sessions


# ============================================================
# Save sessions
# ============================================================

def save_sessions(sessions):

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        for session in sessions:

            file.write(
                json.dumps(
                    session,
                    ensure_ascii=False,
                )
                + "\n"
            )


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 60)
    print("THREAT / RISK ENGINE")
    print("=" * 60)

    sessions = load_sessions()

    print(
        f"Sessions loaded: {len(sessions)}"
    )

    results = []

    for session in sessions:

        result = analyze_risk(
            session
        )

        results.append(result)

        risk = result["risk"]

        print(
            f"\nSession: "
            f"{session.get('session_id')}"
        )

        print(
            f"Risk Score: "
            f"{risk['score']}"
        )

        print(
            f"Threat State: "
            f"{risk['state']}"
        )

    save_sessions(results)

    print(
        f"\nSaved results to: "
        f"{OUTPUT_FILE}"
    )

    print("\nRisk analysis complete.")


if __name__ == "__main__":
    main()