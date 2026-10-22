import json
from pathlib import Path


INPUT_FILE = Path(
    "data/processed/sessions/analyzed_sessions.jsonl"
)

OUTPUT_FILE = Path(
    "data/processed/sessions/live_state_sessions.jsonl"
)


# =========================================================
# THREAT STATE CONFIGURATION
# =========================================================

STATE_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def determine_state(score):
    """
    Convert the current incremental risk score
    into a threat state.
    """

    if score >= 70:
        return "CRITICAL"

    if score >= 45:
        return "HIGH"

    if score >= 20:
        return "MEDIUM"

    return "LOW"


# =========================================================
# BEHAVIOR RISK WEIGHTS
# =========================================================

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


# =========================================================
# BEHAVIOR-SPECIFIC ADAPTIVE RESPONSES
# =========================================================

BEHAVIOR_RESPONSES = {

    "account_discovery":
        "enable_account_discovery_monitoring",

    "system_discovery":
        "enable_system_discovery_monitoring",

    "file_discovery":
        "expose_safe_decoy_files",

    "process_discovery":
        "provide_safe_decoy_process_information",

    "network_discovery":
        "provide_safe_decoy_network_information",

    "credential_access":
        "activate_credential_deception",

    "file_access":
        "increase_file_access_monitoring",

    "execution":
        "increase_command_execution_monitoring",

    "file_transfer":
        "increase_file_transfer_monitoring",

    "privilege_activity":
        "activate_privilege_activity_monitoring",

    "file_modification":
        "monitor_decoy_file_modification",

    "persistence":
        "activate_persistence_deception",

    "defense_evasion":
        "increase_evasion_monitoring",
}


# =========================================================
# STATE-BASED ADAPTIVE RESPONSES
# =========================================================

STATE_RESPONSES = {

    "LOW": {
        "mode": "normal",
        "monitoring": "standard",
        "deception": "none",
    },

    "MEDIUM": {
        "mode": "observe",
        "monitoring": "elevated",
        "deception": "low",
    },

    "HIGH": {
        "mode": "deceive",
        "monitoring": "enhanced",
        "deception": "medium",
    },

    "CRITICAL": {
        "mode": "maximum_deception",
        "monitoring": "maximum",
        "deception": "high",
    },
}


# =========================================================
# STATE TRANSITION
# =========================================================

def determine_transition(
    previous_state,
    current_state
):

    previous_level = STATE_ORDER[
        previous_state
    ]

    current_level = STATE_ORDER[
        current_state
    ]

    if current_level > previous_level:
        return "ESCALATED"

    if current_level < previous_level:
        return "DEESCALATED"

    return "UNCHANGED"


# =========================================================
# LOAD ANALYZED SESSIONS
# =========================================================

def load_sessions():

    sessions = []

    with INPUT_FILE.open(
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            sessions.append(
                json.loads(line)
            )

    return sessions


# =========================================================
# CALCULATE COMMAND RISK
# =========================================================

def calculate_command_risk(
    behaviors,
    seen_behaviors
):
    """
    Calculate the risk contribution of the current command.

    New behaviors receive their full weight.

    Repeated behaviors receive one-third of their
    original weight.

    Commands with no behaviors receive zero risk.
    """

    score = 0

    reasons = []

    new_behaviors = []

    for behavior in behaviors:

        weight = BEHAVIOR_WEIGHTS.get(
            behavior,
            0
        )

        if weight == 0:
            continue

        # -------------------------------------------------
        # First occurrence
        # -------------------------------------------------

        if behavior not in seen_behaviors:

            score += weight

            new_behaviors.append(
                behavior
            )

            reasons.append(
                f"{behavior}: +{weight}"
            )

        # -------------------------------------------------
        # Repeated occurrence
        # -------------------------------------------------

        else:

            repeat_weight = max(
                1,
                weight // 3
            )

            score += repeat_weight

            reasons.append(
                f"{behavior} (repeat): "
                f"+{repeat_weight}"
            )

    return (
        score,
        new_behaviors,
        reasons
    )


# =========================================================
# PROGRESSION BONUSES
# =========================================================

def calculate_progression_bonus(
    seen_behaviors,
    current_behaviors
):
    """
    Apply progression bonuses only when a NEW
    behavioral stage appears.

    This prevents the same progression bonus
    from being repeatedly added on later commands.
    """

    bonus = 0

    reasons = []

    previous = set(
        seen_behaviors
    )

    current = set(
        current_behaviors
    )

    combined = previous | current

    discovery_behaviors = {
        "account_discovery",
        "system_discovery",
        "file_discovery",
        "process_discovery",
        "network_discovery",
    }

    # -----------------------------------------------------
    # Discovery -> Credential Access
    # -----------------------------------------------------

    if (
        "credential_access" in current
        and "credential_access" not in previous
        and bool(
            previous & discovery_behaviors
        )
    ):

        bonus += 10

        reasons.append(
            "Discovery followed by "
            "credential-related activity: +10"
        )

    # -----------------------------------------------------
    # File Transfer -> Execution
    # -----------------------------------------------------

    if (
        "execution" in current
        and "execution" not in previous
        and "file_transfer" in previous
    ):

        bonus += 10

        reasons.append(
            "File transfer followed by "
            "execution: +10"
        )

    # -----------------------------------------------------
    # Credential Access -> Persistence
    # -----------------------------------------------------

    if (
        "persistence" in current
        and "persistence" not in previous
        and "credential_access" in previous
    ):

        bonus += 15

        reasons.append(
            "Credential access followed by "
            "persistence: +15"
        )

    # -----------------------------------------------------
    # Four distinct behavioral stages
    # -----------------------------------------------------

    previous_count = len(
        previous
    )

    combined_count = len(
        combined
    )

    if (
        previous_count < 4
        and combined_count >= 4
    ):

        bonus += 10

        reasons.append(
            "Four or more distinct behavioral "
            "stages observed: +10"
        )

    return (
        bonus,
        reasons
    )


# =========================================================
# ADAPTIVE ACTION GENERATOR
# =========================================================

def generate_adaptive_action(
    state,
    behaviors,
    transition
):
    """
    Generate the response plan for the current
    threat state and observed behaviors.

    These are planning actions only.
    They do not modify Cowrie yet.
    """

    state_config = STATE_RESPONSES[
        state
    ]

    actions = []

    # -----------------------------------------------------
    # State-level actions
    # -----------------------------------------------------

    actions.append(
        f"monitoring="
        f"{state_config['monitoring']}"
    )

    actions.append(
        f"deception="
        f"{state_config['deception']}"
    )

    # -----------------------------------------------------
    # Behavior-specific actions
    # -----------------------------------------------------

    for behavior in behaviors:

        response = BEHAVIOR_RESPONSES.get(
            behavior
        )

        if response:

            actions.append(
                response
            )

    # -----------------------------------------------------
    # Escalation
    # -----------------------------------------------------

    if transition == "ESCALATED":

        actions.append(
            "increase_adaptive_response"
        )

    # -----------------------------------------------------
    # Multi-stage behavior
    # -----------------------------------------------------

    if len(behaviors) >= 4:

        actions.append(
            "track_multi_stage_progression"
        )

    # -----------------------------------------------------
    # Critical state
    # -----------------------------------------------------

    if state == "CRITICAL":

        actions.append(
            "activate_maximum_safe_deception"
        )

        actions.append(
            "enable_complete_session_monitoring"
        )

    return actions


# =========================================================
# PROCESS ONE SESSION
# =========================================================

def process_session(session):

    session_id = session.get(
        "session_id"
    )

    commands = session.get(
        "analyzed_commands",
        []
    )

    current_score = 0

    current_state = "LOW"

    seen_behaviors = set()

    timeline = []

    # =====================================================
    # Process commands chronologically
    # =====================================================

    for index, command_data in enumerate(
        commands,
        start=1
    ):

        command = command_data.get(
            "command",
            ""
        )

        timestamp = command_data.get(
            "timestamp"
        )

        behaviors = command_data.get(
            "behaviors",
            []
        )

        # -------------------------------------------------
        # State before this command
        # -------------------------------------------------

        previous_state = current_state

        # -------------------------------------------------
        # Command risk
        # -------------------------------------------------

        (
            command_score,
            new_behaviors,
            reasons
        ) = calculate_command_risk(
            behaviors,
            seen_behaviors
        )

        # -------------------------------------------------
        # Progression bonus
        # -------------------------------------------------

        (
            progression_bonus,
            progression_reasons
        ) = calculate_progression_bonus(
            seen_behaviors,
            behaviors
        )

        # Add progression bonus
        command_score += (
            progression_bonus
        )

        # -------------------------------------------------
        # Update cumulative risk
        # -------------------------------------------------

        current_score += command_score

        # Keep score between 0 and 100
        current_score = min(
            max(current_score, 0),
            100
        )

        # -------------------------------------------------
        # Determine new state
        # -------------------------------------------------

        current_state = determine_state(
            current_score
        )

        # -------------------------------------------------
        # State transition
        # -------------------------------------------------

        transition = determine_transition(
            previous_state,
            current_state
        )

        # -------------------------------------------------
        # Adaptive response
        # -------------------------------------------------

        adaptive_actions = (
            generate_adaptive_action(
                current_state,
                behaviors,
                transition
            )
        )

        # -------------------------------------------------
        # Update known behaviors AFTER
        # calculations
        # -------------------------------------------------

        seen_behaviors.update(
            behaviors
        )

        # -------------------------------------------------
        # Save timeline event
        # -------------------------------------------------

        timeline.append({

            "step": index,

            "timestamp": timestamp,

            "command": command,

            "behaviors": behaviors,

            "new_behaviors": new_behaviors,

            "command_risk": command_score,

            "cumulative_risk": current_score,

            "previous_state": previous_state,

            "current_state": current_state,

            "state_transition": transition,

            "risk_reasons": (
                reasons
                + progression_reasons
            ),

            "adaptive_actions": (
                adaptive_actions
            ),

        })

    # =====================================================
    # Final session record
    # =====================================================

    return {

        "session_id": session_id,

        "final_risk_score": current_score,

        "final_state": current_state,

        "behaviors_observed": sorted(
            seen_behaviors
        ),

        "command_count": len(
            commands
        ),

        "timeline": timeline,

    }


# =========================================================
# MAIN
# =========================================================

def main():

    if not INPUT_FILE.exists():

        print(
            f"ERROR: Input file not found: "
            f"{INPUT_FILE}"
        )

        return

    sessions = load_sessions()

    results = []

    print()
    print(
        "LIVE STATE ENGINE"
    )

    print(
        "=" * 60
    )

    print(
        f"Sessions loaded: "
        f"{len(sessions)}"
    )

    # -----------------------------------------------------
    # Process every session
    # -----------------------------------------------------

    for session in sessions:

        result = process_session(
            session
        )

        results.append(
            result
        )

    # -----------------------------------------------------
    # Write output
    # -----------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as f:

        for result in results:

            f.write(
                json.dumps(result)
                + "\n"
            )

    # -----------------------------------------------------
    # State distribution
    # -----------------------------------------------------

    state_counts = {

        "LOW": 0,

        "MEDIUM": 0,

        "HIGH": 0,

        "CRITICAL": 0,

    }

    for result in results:

        state = result[
            "final_state"
        ]

        state_counts[state] += 1

    print()
    print(
        "FINAL STATE DISTRIBUTION"
    )

    print(
        "-" * 40
    )

    for state in [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]:

        print(
            f"{state:<10}: "
            f"{state_counts[state]}"
        )

    print()

    print(
        f"Output: "
        f"{OUTPUT_FILE}"
    )

    # =====================================================
    # Display known example session
    # =====================================================

    example = None

    for result in results:

        if result[
            "session_id"
        ] == "950f3a03c073":

            example = result

            break

    if example:

        print()
        print(
            "EXAMPLE SESSION"
        )

        print(
            "-" * 60
        )

        print(
            f"Session: "
            f"{example['session_id']}"
        )

        print(
            f"Final risk: "
            f"{example['final_risk_score']}"
        )

        print(
            f"Final state: "
            f"{example['final_state']}"
        )

        print()

        for step in example[
            "timeline"
        ]:

            print(
                f"[{step['step']}] "
                f"{step['command']}"
            )

            print(
                f"    Behaviors: "
                f"{step['behaviors']}"
            )

            print(
                f"    Command risk: "
                f"{step['command_risk']}"
            )

            print(
                f"    Cumulative risk: "
                f"{step['cumulative_risk']}"
            )

            print(
                f"    State: "
                f"{step['previous_state']} "
                f"-> "
                f"{step['current_state']}"
            )

            print(
                f"    Transition: "
                f"{step['state_transition']}"
            )

            print(
                f"    Actions: "
                f"{step['adaptive_actions']}"
            )

            print()


if __name__ == "__main__":
    main()