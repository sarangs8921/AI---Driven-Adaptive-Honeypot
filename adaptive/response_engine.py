import json
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

INPUT_FILE = Path(
    "data/processed/sessions/risk_sessions.jsonl"
)

OUTPUT_FILE = Path(
    "data/processed/sessions/adaptive_sessions.jsonl"
)


# ============================================================
# Response profiles
# ============================================================

RESPONSE_PROFILES = {

    "LOW": {
        "mode": "normal",
        "monitoring_level": "standard",
        "deception_level": "none",
        "actions": [
            "Maintain normal honeypot behavior",
            "Continue standard session logging",
        ],
    },

    "MEDIUM": {
        "mode": "observe",
        "monitoring_level": "elevated",
        "deception_level": "low",
        "actions": [
            "Increase session monitoring",
            "Record detailed command activity",
            "Maintain believable environment",
        ],
    },

    "HIGH": {
        "mode": "deceive",
        "monitoring_level": "enhanced",
        "deception_level": "medium",
        "actions": [
            "Enable enhanced session monitoring",
            "Prepare behavior-specific decoy content",
            "Record detailed attacker activity",
            "Preserve session artifacts",
        ],
    },

    "CRITICAL": {
        "mode": "maximum_deception",
        "monitoring_level": "maximum",
        "deception_level": "high",
        "actions": [
            "Enable maximum session monitoring",
            "Deploy behavior-specific deception",
            "Expose controlled decoy resources",
            "Preserve complete session artifacts",
            "Track subsequent attacker behavior",
        ],
    },
}


# ============================================================
# Behavior-specific responses
# ============================================================

BEHAVIOR_RESPONSES = {

    "account_discovery": {
        "response": "account_discovery_deception",
        "description": (
            "Prepare believable decoy account information."
        ),
    },

    "system_discovery": {
        "response": "system_discovery_deception",
        "description": (
            "Maintain a believable system fingerprint."
        ),
    },

    "file_discovery": {
        "response": "file_discovery_deception",
        "description": (
            "Expose controlled decoy files and directories."
        ),
    },

    "process_discovery": {
        "response": "process_deception",
        "description": (
            "Maintain believable process information."
        ),
    },

    "network_discovery": {
        "response": "network_deception",
        "description": (
            "Maintain believable network configuration information."
        ),
    },

    "credential_access": {
        "response": "credential_deception",
        "description": (
            "Prepare controlled decoy credentials or honeytokens."
        ),
    },

    "file_access": {
        "response": "file_access_monitoring",
        "description": (
            "Increase monitoring of accessed files."
        ),
    },

    "execution": {
        "response": "execution_monitoring",
        "description": (
            "Increase monitoring of command execution behavior."
        ),
    },

    "file_transfer": {
        "response": "transfer_monitoring",
        "description": (
            "Increase monitoring of file-transfer activity."
        ),
    },

    "privilege_activity": {
        "response": "privilege_monitoring",
        "description": (
            "Increase monitoring of privilege-related activity."
        ),
    },

    "persistence": {
        "response": "persistence_deception",
        "description": (
            "Monitor and prepare controlled persistence-related decoys."
        ),
    },

    "file_modification": {
        "response": "file_modification_monitoring",
        "description": (
            "Increase monitoring of file modification activity."
        ),
    },

    "defense_evasion": {
        "response": "evasion_monitoring",
        "description": (
            "Preserve additional evidence around possible evasion behavior."
        ),
    },
}


# ============================================================
# Determine behavior-specific responses
# ============================================================

def get_behavior_responses(behaviors):

    responses = []

    for behavior in behaviors:

        response_info = BEHAVIOR_RESPONSES.get(
            behavior
        )

        if not response_info:
            continue

        responses.append(
            {
                "behavior": behavior,
                "response": response_info["response"],
                "description": response_info["description"],
            }
        )

    return responses


# ============================================================
# Determine adaptive response
# ============================================================

def create_response_plan(session):

    risk = session.get(
        "risk",
        {},
    )

    score = risk.get(
        "score",
        0,
    )

    state = risk.get(
        "state",
        "LOW",
    )

    behaviors = session.get(
        "behaviors",
        [],
    )

    profile = RESPONSE_PROFILES.get(
        state,
        RESPONSE_PROFILES["LOW"],
    )

    behavior_responses = (
        get_behavior_responses(
            behaviors
        )
    )

    response_plan = {
        "mode": profile["mode"],
        "monitoring_level": profile["monitoring_level"],
        "deception_level": profile["deception_level"],
        "actions": list(profile["actions"]),
        "behavior_responses": behavior_responses,
    }

    # --------------------------------------------------------
    # Multi-stage escalation
    # --------------------------------------------------------

    if len(behaviors) >= 4:

        response_plan["actions"].append(
            "Track multi-stage behavioral progression"
        )

    # --------------------------------------------------------
    # Credential access escalation
    # --------------------------------------------------------

    if "credential_access" in behaviors:

        response_plan["actions"].append(
            "Activate credential-focused deception"
        )

    # --------------------------------------------------------
    # Persistence escalation
    # --------------------------------------------------------

    if "persistence" in behaviors:

        response_plan["actions"].append(
            "Activate persistence-focused deception"
        )

    # --------------------------------------------------------
    # File transfer + execution
    # --------------------------------------------------------

    if (
        "file_transfer" in behaviors
        and "execution" in behaviors
    ):

        response_plan["actions"].append(
            "Increase monitoring of transferred execution activity"
        )

    # Remove duplicate actions while preserving order.

    response_plan["actions"] = list(
        dict.fromkeys(
            response_plan["actions"]
        )
    )

    return {
        "risk_score": score,
        "threat_state": state,
        "response": response_plan,
    }


# ============================================================
# Process one session
# ============================================================

def process_session(session):

    result = dict(session)

    response = create_response_plan(
        session
    )

    result["adaptive_response"] = response

    return result


# ============================================================
# Load risk sessions
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

        for line_number, line in enumerate(
            file,
            start=1,
        ):

            line = line.strip()

            if not line:
                continue

            try:

                sessions.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:

                print(
                    f"WARNING: Invalid JSON at "
                    f"line {line_number}"
                )

    return sessions


# ============================================================
# Save adaptive results
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
    print("ADAPTIVE RESPONSE ENGINE")
    print("=" * 60)

    sessions = load_sessions()

    print(
        f"Sessions loaded: {len(sessions)}"
    )

    results = []

    for session in sessions:

        result = process_session(
            session
        )

        results.append(result)

    save_sessions(results)

    print(
        f"Response plans generated: "
        f"{len(results)}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    response_modes = {}

    for session in results:

        mode = (
            session
            .get("adaptive_response", {})
            .get("response", {})
            .get("mode", "unknown")
        )

        response_modes[mode] = (
            response_modes.get(mode, 0) + 1
        )

    print("\nResponse mode summary:")

    for mode, count in response_modes.items():

        print(
            f"  {mode}: {count}"
        )

    print("\nAdaptive response analysis complete.")


if __name__ == "__main__":
    main()