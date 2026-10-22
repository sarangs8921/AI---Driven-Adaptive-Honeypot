import json
from pathlib import Path


INPUT_FILE = Path(
    "data/processed/sessions/live_state_sessions.jsonl"
)

OUTPUT_FILE = Path(
    "data/processed/sessions/adaptive_state_sessions.jsonl"
)


# =========================================================
# STATE ORDER
# =========================================================

STATE_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


# =========================================================
# RESPONSE CONFIGURATION
# =========================================================

STATE_CONFIG = {

    "LOW": {
        "monitoring_level": "standard",
        "deception_level": "none",
    },

    "MEDIUM": {
        "monitoring_level": "elevated",
        "deception_level": "low",
    },

    "HIGH": {
        "monitoring_level": "enhanced",
        "deception_level": "medium",
    },

    "CRITICAL": {
        "monitoring_level": "maximum",
        "deception_level": "high",
    },
}


# =========================================================
# BEHAVIOR → DECEPTION
# =========================================================

BEHAVIOR_DECEPTIONS = {

    "account_discovery":
        "account_discovery_deception",

    "system_discovery":
        "system_discovery_deception",

    "file_discovery":
        "decoy_file_environment",

    "process_discovery":
        "decoy_process_environment",

    "network_discovery":
        "decoy_network_environment",

    "credential_access":
        "credential_deception",

    "file_access":
        "sensitive_file_monitoring",

    "execution":
        "command_execution_monitoring",

    "file_transfer":
        "file_transfer_monitoring",

    "privilege_activity":
        "privilege_activity_monitoring",

    "file_modification":
        "decoy_file_modification_monitoring",

    "persistence":
        "persistence_deception",

    "defense_evasion":
        "evasion_monitoring",
}


# =========================================================
# LOAD JSONL
# =========================================================

def load_records():

    records = []

    with INPUT_FILE.open(
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            records.append(
                json.loads(line)
            )

    return records


# =========================================================
# ADD DECEPTION
# =========================================================

def activate_deception(
    active_deceptions,
    behavior
):
    """
    Activate a deception associated with a behavior.

    Existing deceptions are not duplicated.
    """

    deception = BEHAVIOR_DECEPTIONS.get(
        behavior
    )

    if deception is None:
        return

    if deception not in active_deceptions:

        active_deceptions.append(
            deception
        )


# =========================================================
# RESPONSE CONTROLLER
# =========================================================

def process_session(session):

    session_id = session.get(
        "session_id"
    )

    timeline = session.get(
        "timeline",
        []
    )

    active_deceptions = []

    tracked_behaviors = []

    response_timeline = []

    current_monitoring = "standard"

    current_deception = "none"

    previous_state = "LOW"

    # =====================================================
    # Process the session chronologically
    # =====================================================

    for event in timeline:

        current_state = event.get(
            "current_state",
            "LOW"
        )

        behaviors = event.get(
            "behaviors",
            []
        )

        transition = event.get(
            "state_transition",
            "UNCHANGED"
        )

        # -------------------------------------------------
        # Update tracked behaviors
        # -------------------------------------------------

        for behavior in behaviors:

            if behavior not in tracked_behaviors:

                tracked_behaviors.append(
                    behavior
                )

        # -------------------------------------------------
        # Update monitoring level
        # -------------------------------------------------

        state_config = STATE_CONFIG[
            current_state
        ]

        current_monitoring = (
            state_config[
                "monitoring_level"
            ]
        )

        current_deception = (
            state_config[
                "deception_level"
            ]
        )

        # -------------------------------------------------
        # Activate behavior-specific deception
        # -------------------------------------------------

        for behavior in behaviors:

            activate_deception(
                active_deceptions,
                behavior
            )

        # -------------------------------------------------
        # Escalation handling
        # -------------------------------------------------

        escalation_actions = []

        if transition == "ESCALATED":

            escalation_actions.append(
                "increase_monitoring"
            )

            escalation_actions.append(
                "increase_deception"
            )

        # -------------------------------------------------
        # Critical state
        # -------------------------------------------------

        if current_state == "CRITICAL":

            escalation_actions.append(
                "maximum_session_monitoring"
            )

            escalation_actions.append(
                "maximum_safe_deception"
            )

        # -------------------------------------------------
        # Multi-stage behavior
        # -------------------------------------------------

        if len(tracked_behaviors) >= 4:

            escalation_actions.append(
                "track_multi_stage_attack"
            )

        # -------------------------------------------------
        # Build response record
        # -------------------------------------------------

        response_record = {

            "step": event.get(
                "step"
            ),

            "timestamp": event.get(
                "timestamp"
            ),

            "command": event.get(
                "command"
            ),

            "behaviors": behaviors,

            "risk": event.get(
                "cumulative_risk"
            ),

            "previous_state": previous_state,

            "current_state": current_state,

            "state_transition": transition,

            "monitoring_level":
                current_monitoring,

            "deception_level":
                current_deception,

            "tracked_behaviors":
                list(tracked_behaviors),

            "active_deceptions":
                list(active_deceptions),

            "actions":
                escalation_actions,

        }

        response_timeline.append(
            response_record
        )

        previous_state = current_state

    # =====================================================
    # Final session response state
    # =====================================================

    final_state = (
        timeline[-1]["current_state"]
        if timeline
        else "LOW"
    )

    return {

        "session_id": session_id,

        "final_state": final_state,

        "final_risk": (
            timeline[-1]["cumulative_risk"]
            if timeline
            else 0
        ),

        "monitoring_level":
            current_monitoring,

        "deception_level":
            current_deception,

        "tracked_behaviors":
            tracked_behaviors,

        "active_deceptions":
            active_deceptions,

        "timeline":
            response_timeline,

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

    sessions = load_records()

    results = []

    print()
    print(
        "ADAPTIVE RESPONSE CONTROLLER"
    )

    print(
        "=" * 60
    )

    print(
        f"Sessions loaded: "
        f"{len(sessions)}"
    )

    # -----------------------------------------------------
    # Process sessions
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

    print()
    print(
        f"Output written to:"
    )

    print(
        OUTPUT_FILE
    )

    # =====================================================
    # Example session
    # =====================================================

    example = None

    for result in results:

        if result.get(
            "session_id"
        ) == "950f3a03c073":

            example = result

            break

    if example:

        print()
        print(
            "EXAMPLE ADAPTIVE SESSION"
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
            f"{example['final_risk']}"
        )

        print(
            f"Final state: "
            f"{example['final_state']}"
        )

        print(
            f"Monitoring: "
            f"{example['monitoring_level']}"
        )

        print(
            f"Deception: "
            f"{example['deception_level']}"
        )

        print()
        print(
            "Active deceptions:"
        )

        for deception in (
            example["active_deceptions"]
        ):

            print(
                f"  - {deception}"
            )

        print()
        print(
            "Response timeline:"
        )

        for event in (
            example["timeline"]
        ):

            print(
                f"\n[{event['step']}] "
                f"{event['command']}"
            )

            print(
                f"    State: "
                f"{event['previous_state']} "
                f"-> "
                f"{event['current_state']}"
            )

            print(
                f"    Risk: "
                f"{event['risk']}"
            )

            print(
                f"    Monitoring: "
                f"{event['monitoring_level']}"
            )

            print(
                f"    Deception: "
                f"{event['deception_level']}"
            )

            print(
                f"    Active deception: "
                f"{event['active_deceptions']}"
            )

            if event["actions"]:

                print(
                    f"    Actions: "
                    f"{event['actions']}"
                )


if __name__ == "__main__":
    main()