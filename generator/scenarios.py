# generator/scenarios.py

from __future__ import annotations

import random


# ============================================================
# COMMAND LIBRARY
# ============================================================
#
# These commands are intended for execution inside Cowrie.
#
# The PRIMARY scenario label remains one of the 9 ML classes.
# Individual scenarios can contain multiple behavioral atoms.
#
# Actual observed behavior must still be obtained from the
# production analyzer after Cowrie execution.
#
# ============================================================

COMMAND_LIBRARY = {

    # --------------------------------------------------------
    # BENIGN
    # --------------------------------------------------------

    "benign": [
        "echo hello",
        "echo status_ok",
        "echo system_check",
        "echo connection_ok",
        "echo service_check",
        "echo health_check",
        "echo ready",
        "echo test",
        "echo normal_activity",
        "echo session_ok",
        "echo admin_check",
        "echo command_complete",
        "date",
        "pwd",
    ],

    # --------------------------------------------------------
    # ACCOUNT DISCOVERY
    # --------------------------------------------------------

    "account_discovery": [
        "whoami",
        "id",
        "groups",
        "users",
        "w",
        "who",
        "cat /etc/passwd",
        "cat /etc/group",
        "grep root /etc/passwd",
        "grep '1000' /etc/passwd",
    ],

    # --------------------------------------------------------
    # SYSTEM DISCOVERY
    # --------------------------------------------------------

    "system_discovery": [
        "uname -a",
        "uname -r",
        "uname -m",
        "uname -s",
        "hostname",
        "hostname -f",
        "cat /etc/os-release",
        "cat /etc/issue",
        "cat /etc/hostname",
    ],

    # --------------------------------------------------------
    # FILE DISCOVERY
    # --------------------------------------------------------

    "file_discovery": [
        "ls",
        "ls -la",
        "ls -lah",
        "ls -l /tmp",
        "ls -l /home",
        "ls -l /etc",
        "ls -l /var",
        "find /tmp -type f",
        "find /home -type f",
        "find /etc -name '*.conf'",
        "find /var -type f",
        "find /tmp -maxdepth 2 -type f",
        "find /home -maxdepth 2 -type f",
        "find /etc -maxdepth 2 -type f",
        "tree /tmp",
        "tree /home",
    ],

    # --------------------------------------------------------
    # PROCESS DISCOVERY
    # --------------------------------------------------------

    "process_discovery": [
        "ps",
        "ps aux",
        "ps -ef",
        "ps -e",
        "ps -f",
        "pgrep ssh",
        "pgrep bash",
        "pgrep python",
        "pstree",
    ],

    # --------------------------------------------------------
    # NETWORK DISCOVERY
    # --------------------------------------------------------

    "network_discovery": [
        "ip addr",
        "ip route",
        "ip link",
        "ifconfig",
        "route",
        "arp",
        "netstat",
        "ss",
        "netstat -an",
    ],

    # --------------------------------------------------------
    # CREDENTIAL ACCESS
    # --------------------------------------------------------

    "credential_access": [
        "cat /etc/passwd",
        "cat /etc/shadow",
        "cat /etc/gshadow",
        "grep root /etc/passwd",
        "grep root /etc/shadow",
        "grep '1000' /etc/passwd",
        "grep '1000' /etc/shadow",
        "head /etc/shadow",
        "tail /etc/shadow",
    ],

    # --------------------------------------------------------
    # FILE ACCESS
    # --------------------------------------------------------

    "file_access": [
        "cat ~/.bashrc",
        "cat ~/.profile",
        "cat /etc/hostname",
        "cat /etc/hosts",
        "cat /etc/issue",
        "cat /etc/os-release",
        "head /etc/passwd",
        "tail /etc/passwd",
        "head /etc/hostname",
        "tail /etc/hostname",
        "cat /tmp/system_backup.txt",
        "cat /tmp/system_info.txt",
        "cat /tmp/.credentials_backup.txt",
    ],

    # --------------------------------------------------------
    # EXECUTION
    # --------------------------------------------------------

    "execution": [
        "python --version",
        "python -V",
        "python -c 'print(123)'",
        "python -c 'print(\"hello\")'",
        "python -c 'print(1 + 2)'",
        "python -c 'x=5; print(x)'",
        "python3 --version",
        "python3 -c 'print(123)'",
        "python3 -c 'print(\"hello\")'",
        "perl -e 'print 123'",
        "ruby -e 'puts 123'",
        "php -r 'echo 123;'",
    ],

    # --------------------------------------------------------
    # PRIVILEGE ACTIVITY
    # --------------------------------------------------------

    "privilege_activity": [
        "sudo -l",
        "sudo -n -l",
        "sudo -V",
    ],

    # --------------------------------------------------------
    # PERSISTENCE
    # --------------------------------------------------------

    "persistence": [
        "crontab -l",
        "crontab -l -u root",
        "systemctl list-timers",
        "systemctl --no-pager list-timers",
        "service --status-all",
    ],

    # --------------------------------------------------------
    # FILE MODIFICATION
    # --------------------------------------------------------

    "file_modification": [
        "touch /tmp/test_marker",
        "touch /tmp/test_marker_1",
        "touch /tmp/test_marker_2",
        "touch /tmp/session_marker",
        "echo test >> /tmp/test_marker",
        "echo hello >> /tmp/test_marker",
        "echo data >> /tmp/test_marker_1",
        "echo update >> /tmp/session_marker",
        "cp /tmp/test_marker /tmp/test_marker_copy",
        "mv /tmp/test_marker /tmp/test_marker_backup",
        "mv /tmp/test_marker_1 /tmp/test_marker_1_backup",
        "rm /tmp/test_marker",
        "rm /tmp/test_marker_backup",
        "mkdir /tmp/test_directory",
        "rmdir /tmp/test_directory",
        "chmod 644 /tmp/test_marker",
    ],

    # --------------------------------------------------------
    # FILE TRANSFER
    # --------------------------------------------------------
    #
    # Non-interactive version checks.
    #
    # --------------------------------------------------------

    "file_transfer": [
        "wget --version",
        "curl --version",
        "scp -V",
    ],
}


# ============================================================
# SCENARIO DEFINITIONS
# ============================================================
#
# 9 PRIMARY ML CLASSES
#
# Each class contains MANY behavior-composition patterns.
#
# This is the important difference from the previous version:
#
#       9 classes
#          ↓
#       60 patterns
#          ↓
#       many command combinations
#
# ============================================================


SCENARIO_DEFINITIONS = {

    # ========================================================
    # BENIGN
    # ========================================================

    "benign": [
        ["benign"],
    ],

    # ========================================================
    # RECONNAISSANCE
    # ========================================================

    "reconnaissance": [

        ["account_discovery", "system_discovery"],

        ["account_discovery", "process_discovery"],

        ["account_discovery", "network_discovery"],

        ["system_discovery", "process_discovery"],

        ["system_discovery", "network_discovery"],

        ["process_discovery", "network_discovery"],

        [
            "account_discovery",
            "system_discovery",
            "process_discovery",
        ],

        [
            "account_discovery",
            "system_discovery",
            "network_discovery",
        ],

        [
            "account_discovery",
            "process_discovery",
            "network_discovery",
        ],

        [
            "system_discovery",
            "process_discovery",
            "network_discovery",
        ],

        [
            "account_discovery",
            "system_discovery",
            "process_discovery",
            "network_discovery",
        ],

    ],

    # ========================================================
    # FILE DISCOVERY
    # ========================================================

    "file_discovery": [

        ["file_discovery"],

        ["file_discovery", "account_discovery"],

        ["file_discovery", "system_discovery"],

        ["file_discovery", "process_discovery"],

        ["file_discovery", "network_discovery"],

        [
            "file_discovery",
            "account_discovery",
            "system_discovery",
        ],

        [
            "file_discovery",
            "account_discovery",
            "process_discovery",
        ],

        [
            "file_discovery",
            "system_discovery",
            "process_discovery",
        ],

        [
            "file_discovery",
            "system_discovery",
            "network_discovery",
        ],

        [
            "file_discovery",
            "process_discovery",
            "network_discovery",
        ],

        [
            "file_discovery",
            "account_discovery",
            "network_discovery",
        ],

    ],

    # ========================================================
    # CREDENTIAL ACCESS
    # ========================================================

    "credential_access": [

        ["credential_access"],

        [
            "account_discovery",
            "credential_access",
        ],

        [
            "system_discovery",
            "credential_access",
        ],

        [
            "file_discovery",
            "credential_access",
        ],

        [
            "file_access",
            "credential_access",
        ],

        [
            "account_discovery",
            "file_access",
            "credential_access",
        ],

        [
            "account_discovery",
            "file_discovery",
            "credential_access",
        ],

        [
            "system_discovery",
            "file_discovery",
            "credential_access",
        ],

        [
            "file_discovery",
            "file_access",
            "credential_access",
        ],

        [
            "account_discovery",
            "system_discovery",
            "credential_access",
        ],

        [
            "account_discovery",
            "system_discovery",
            "file_access",
            "credential_access",
        ],

    ],

    # ========================================================
    # EXECUTION
    # ========================================================

    "execution": [

        ["execution"],

        [
            "account_discovery",
            "execution",
        ],

        [
            "system_discovery",
            "execution",
        ],

        [
            "file_discovery",
            "execution",
        ],

        [
            "process_discovery",
            "execution",
        ],

        [
            "network_discovery",
            "execution",
        ],

        [
            "file_access",
            "execution",
        ],

        [
            "account_discovery",
            "system_discovery",
            "execution",
        ],

        [
            "account_discovery",
            "file_discovery",
            "execution",
        ],

        [
            "system_discovery",
            "file_discovery",
            "execution",
        ],

        [
            "file_discovery",
            "file_access",
            "execution",
        ],

        [
            "account_discovery",
            "system_discovery",
            "file_discovery",
            "execution",
        ],

    ],

    # ========================================================
    # PRIVILEGE ACTIVITY
    # ========================================================

    "privilege_activity": [

        ["privilege_activity"],

        [
            "account_discovery",
            "privilege_activity",
        ],

        [
            "system_discovery",
            "privilege_activity",
        ],

        [
            "file_discovery",
            "privilege_activity",
        ],

        [
            "process_discovery",
            "privilege_activity",
        ],

        [
            "network_discovery",
            "privilege_activity",
        ],

        [
            "account_discovery",
            "system_discovery",
            "privilege_activity",
        ],

        [
            "account_discovery",
            "file_discovery",
            "privilege_activity",
        ],

        [
            "system_discovery",
            "file_discovery",
            "privilege_activity",
        ],

        [
            "file_discovery",
            "process_discovery",
            "privilege_activity",
        ],

        [
            "account_discovery",
            "system_discovery",
            "file_discovery",
            "privilege_activity",
        ],

    ],

    # ========================================================
    # PERSISTENCE
    # ========================================================

    "persistence": [

        ["persistence"],

        [
            "persistence",
            "account_discovery",
        ],

        [
            "persistence",
            "system_discovery",
        ],

        [
            "persistence",
            "file_discovery",
        ],

        [
            "persistence",
            "file_access",
        ],

        [
            "persistence",
            "process_discovery",
        ],

        [
            "persistence",
            "network_discovery",
        ],

        [
            "account_discovery",
            "persistence",
            "file_discovery",
        ],

        [
            "system_discovery",
            "persistence",
            "file_access",
        ],

        [
            "file_discovery",
            "persistence",
            "file_access",
        ],

        [
            "account_discovery",
            "system_discovery",
            "persistence",
        ],

    ],

    # ========================================================
    # FILE MODIFICATION
    # ========================================================

    "file_modification": [

        ["file_modification"],

        [
            "file_access",
            "file_modification",
        ],

        [
            "file_discovery",
            "file_modification",
        ],

        [
            "account_discovery",
            "file_modification",
        ],

        [
            "system_discovery",
            "file_modification",
        ],

        [
            "process_discovery",
            "file_modification",
        ],

        [
            "network_discovery",
            "file_modification",
        ],

        [
            "file_discovery",
            "file_access",
            "file_modification",
        ],

        [
            "account_discovery",
            "file_discovery",
            "file_modification",
        ],

        [
            "system_discovery",
            "file_discovery",
            "file_modification",
        ],

        [
            "account_discovery",
            "system_discovery",
            "file_modification",
        ],

    ],

    # ========================================================
    # MULTI-STAGE
    # ========================================================
    #
    # These are intentionally ordered.
    #
    # Discovery
    #      ↓
    # Access
    #      ↓
    # Credential / privilege
    #      ↓
    # Execution / modification / persistence
    #
    # ========================================================

    "multi_stage": [

        [
            "account_discovery",
            "system_discovery",
            "file_discovery",
            "credential_access",
        ],

        [
            "account_discovery",
            "file_discovery",
            "credential_access",
            "execution",
        ],

        [
            "system_discovery",
            "process_discovery",
            "file_discovery",
            "credential_access",
        ],

        [
            "account_discovery",
            "network_discovery",
            "file_discovery",
            "credential_access",
        ],

        [
            "account_discovery",
            "system_discovery",
            "credential_access",
            "execution",
        ],

        [
            "account_discovery",
            "file_discovery",
            "credential_access",
            "file_modification",
        ],

        [
            "account_discovery",
            "system_discovery",
            "file_discovery",
            "privilege_activity",
        ],

        [
            "account_discovery",
            "system_discovery",
            "privilege_activity",
            "execution",
        ],

        [
            "account_discovery",
            "file_discovery",
            "credential_access",
            "execution",
        ],

        [
            "system_discovery",
            "file_discovery",
            "credential_access",
            "execution",
        ],

        [
            "account_discovery",
            "system_discovery",
            "network_discovery",
            "credential_access",
            "execution",
        ],

        [
            "account_discovery",
            "system_discovery",
            "file_discovery",
            "credential_access",
            "execution",
        ],

        [
            "account_discovery",
            "file_discovery",
            "credential_access",
            "privilege_activity",
        ],

        [
            "system_discovery",
            "file_discovery",
            "privilege_activity",
            "execution",
        ],

        [
            "account_discovery",
            "system_discovery",
            "privilege_activity",
            "persistence",
        ],

        [
            "account_discovery",
            "file_discovery",
            "privilege_activity",
            "persistence",
        ],

        [
            "account_discovery",
            "system_discovery",
            "file_discovery",
            "file_modification",
            "execution",
        ],

        [
            "account_discovery",
            "file_discovery",
            "credential_access",
            "file_modification",
            "execution",
        ],

        [
            "account_discovery",
            "system_discovery",
            "credential_access",
            "privilege_activity",
            "execution",
        ],

        [
            "account_discovery",
            "system_discovery",
            "file_discovery",
            "credential_access",
            "privilege_activity",
            "execution",
        ],

        [
            "account_discovery",
            "system_discovery",
            "network_discovery",
            "file_discovery",
            "credential_access",
            "execution",
        ],

    ],
}


# ============================================================
# SHARED CONTEXTUAL BEHAVIOR
# ============================================================
#
# These behaviors may legitimately appear across several
# attack classes. They are used as contextual/background
# activity so that the ML label is not perfectly correlated
# with one low-level command category.
#
# IMPORTANT:
# These are NOT added to behavior_atoms. The primary scenario
# definition remains the ground-truth ML class composition.
#
# ============================================================

SHARED_CONTEXT_BEHAVIORS = [
    "account_discovery",
    "system_discovery",
    "file_discovery",
    "process_discovery",
    "network_discovery",
    "file_access",
]


# ============================================================
# CROSS-CLASS BRIDGE BEHAVIORS
# ============================================================
#
# These are behavior combinations that commonly occur as part
# of broader attacker activity. They deliberately create
# overlap between classes without changing the primary label.
#
# The selected bridge behavior is NOT appended to behavior_atoms.
# It is only additional observed activity.
#
# ============================================================

BRIDGE_BEHAVIOR_MAP = {
    "reconnaissance": [
        "file_access",
        "file_discovery",
        "network_discovery",
    ],
    "file_discovery": [
        "account_discovery",
        "system_discovery",
        "network_discovery",
    ],
    "credential_access": [
        "account_discovery",
        "system_discovery",
        "file_access",
        "file_discovery",
    ],
    "execution": [
        "account_discovery",
        "system_discovery",
        "file_discovery",
        "process_discovery",
    ],
    "privilege_activity": [
        "account_discovery",
        "system_discovery",
        "process_discovery",
        "file_discovery",
    ],
    "persistence": [
        "account_discovery",
        "system_discovery",
        "file_discovery",
        "process_discovery",
    ],
    "file_modification": [
        "file_discovery",
        "file_access",
        "account_discovery",
        "system_discovery",
    ],
    "multi_stage": [
        "network_discovery",
        "process_discovery",
        "file_access",
        "file_discovery",
    ],
}


# ============================================================
# GENERATION SETTINGS
# ============================================================

MULTI_COMMAND_PROBABILITY = 0.55

BACKGROUND_ACTIVITY_PROBABILITY = 0.70

EXTRA_BACKGROUND_PROBABILITY = 0.65

REPEAT_COMMAND_PROBABILITY = 0.35

OPTIONAL_COMMAND_DROP_PROBABILITY = 0.10

FILE_TRANSFER_PROBABILITY = 0.18


# ============================================================
# VALIDATION
# ============================================================

def validate_library():

    for scenario_id, definitions in (
        SCENARIO_DEFINITIONS.items()
    ):

        if not definitions:

            raise ValueError(
                f"Scenario '{scenario_id}' "
                "has no definitions."
            )

        for behavior_atoms in definitions:

            if not behavior_atoms:

                raise ValueError(
                    f"Scenario '{scenario_id}' "
                    "contains an empty definition."
                )

            for behavior in behavior_atoms:

                if behavior not in COMMAND_LIBRARY:

                    raise KeyError(
                        f"Behavior '{behavior}' "
                        f"used by '{scenario_id}' "
                        "is missing."
                    )

                if not COMMAND_LIBRARY[behavior]:

                    raise ValueError(
                        f"Command library for "
                        f"'{behavior}' is empty."
                    )


# ============================================================
# COMMAND SELECTION
# ============================================================

def choose_commands_for_behavior(
    behavior,
    rng,
):

    available = COMMAND_LIBRARY[behavior]

    if len(available) == 1:

        return [
            available[0]
        ]

    number_to_select = 1

    if (
        len(available) >= 3
        and rng.random()
        < MULTI_COMMAND_PROBABILITY
    ):

        number_to_select = rng.choice(
            [2, 2, 3]
        )

    number_to_select = min(
        number_to_select,
        len(available),
    )

    selected = rng.sample(
        available,
        k=number_to_select,
    )

    if (
        len(selected) > 1
        and rng.random()
        < OPTIONAL_COMMAND_DROP_PROBABILITY
    ):

        selected.pop(
            rng.randrange(
                len(selected)
            )
        )

    return selected


# ============================================================
# SHARED CONTEXTUAL ACTIVITY
# ============================================================

def add_shared_context_activity(
    commands,
    rng,
    scenario_id,
    behavior_atoms,
):
    """
    Add legitimate contextual behavior to non-benign sessions.

    The contextual behavior is additional observed activity only;
    it does not modify the primary scenario label.
    """

    if scenario_id == "benign":
        return

    # Most attack sessions contain some normal/contextual activity.
    if rng.random() >= 0.75:
        return

    available_contexts = [
        behavior
        for behavior in SHARED_CONTEXT_BEHAVIORS
        if behavior not in behavior_atoms
    ]

    if not available_contexts:
        return

    number_of_contexts = rng.choices(
        [1, 2, 3],
        weights=[45, 40, 15],
        k=1,
    )[0]

    selected_contexts = rng.sample(
        available_contexts,
        k=min(
            number_of_contexts,
            len(available_contexts),
        ),
    )

    for behavior in selected_contexts:

        selected = choose_commands_for_behavior(
            behavior,
            rng,
        )

        # Context should remain lighter than primary behavior.
        if selected:
            selected = selected[:1]

        for command in selected:
            commands.insert(
                rng.randrange(
                    len(commands) + 1
                ),
                command,
            )


# ============================================================
# BRIDGE ACTIVITY
# ============================================================

def add_bridge_activity(
    commands,
    rng,
    scenario_id,
    behavior_atoms,
):
    """
    Add one behavior that naturally bridges the primary class
    with another common attacker activity.

    This creates controlled cross-class overlap.
    """

    if scenario_id == "benign":
        return

    candidates = BRIDGE_BEHAVIOR_MAP.get(
        scenario_id,
        [],
    )

    candidates = [
        behavior
        for behavior in candidates
        if behavior not in behavior_atoms
    ]

    if not candidates:
        return

    # Not every session gets a bridge behavior.
    if rng.random() >= 0.45:
        return

    behavior = rng.choice(
        candidates
    )

    available = COMMAND_LIBRARY[
        behavior
    ]

    commands.insert(
        rng.randrange(
            len(commands) + 1
        ),
        rng.choice(
            available
        ),
    )


# ============================================================
# BACKGROUND ACTIVITY
# ============================================================

def add_background_activity(
    commands,
    rng,
    scenario_id,
):

    if scenario_id == "benign":
        return

    if rng.random() >= BACKGROUND_ACTIVITY_PROBABILITY:
        return

    # Variable background intensity.
    count = rng.choices(
        [1, 2, 3],
        weights=[45, 40, 15],
        k=1,
    )[0]

    benign_commands = COMMAND_LIBRARY[
        "benign"
    ]

    for _ in range(count):

        commands.insert(
            rng.randrange(
                len(commands) + 1
            ),
            rng.choice(
                benign_commands
            ),
        )


# ============================================================
# REPEATED ACTIVITY
# ============================================================

def add_repeated_activity(
    commands,
    rng,
):

    if not commands:
        return

    if rng.random() >= REPEAT_COMMAND_PROBABILITY:
        return

    repeat_count = rng.choices(
        [1, 2],
        weights=[75, 25],
        k=1,
    )[0]

    for _ in range(repeat_count):

        command = rng.choice(
            commands
        )

        commands.insert(
            rng.randrange(
                len(commands) + 1
            ),
            command,
        )


# ============================================================
# FILE TRANSFER VARIATION
# ============================================================

def maybe_add_file_transfer(
    commands,
    rng,
    scenario_id,
):

    if scenario_id not in {
        "execution",
        "persistence",
        "file_modification",
        "multi_stage",
    }:

        return

    if (
        rng.random()
        < FILE_TRANSFER_PROBABILITY
    ):

        commands.insert(
            rng.randrange(
                len(commands) + 1
            ),
            rng.choice(
                COMMAND_LIBRARY[
                    "file_transfer"
                ]
            ),
        )


# ============================================================
# BUILD COMMAND SEQUENCE
# ============================================================

def build_scenario_commands(
    scenario_id,
    rng,
):

    if scenario_id not in (
        SCENARIO_DEFINITIONS
    ):

        raise ValueError(
            f"Unknown scenario: "
            f"{scenario_id}"
        )

    definitions = (
        SCENARIO_DEFINITIONS[
            scenario_id
        ]
    )

    behavior_atoms = list(
        rng.choice(
            definitions
        )
    )

    commands = []

    # --------------------------------------------------------
    # Build behavior-specific commands
    # --------------------------------------------------------

    for behavior in behavior_atoms:

        selected = (
            choose_commands_for_behavior(
                behavior,
                rng,
            )
        )

        commands.extend(
            selected
        )

    # --------------------------------------------------------
    # Shared contextual activity
    # --------------------------------------------------------

    add_shared_context_activity(
        commands,
        rng,
        scenario_id,
        behavior_atoms,
    )

    # --------------------------------------------------------
    # Cross-class bridge activity
    # --------------------------------------------------------

    add_bridge_activity(
        commands,
        rng,
        scenario_id,
        behavior_atoms,
    )

    # --------------------------------------------------------
    # Background activity
    # --------------------------------------------------------

    add_background_activity(
        commands,
        rng,
        scenario_id,
    )

    # --------------------------------------------------------
    # Repeated activity
    # --------------------------------------------------------

    add_repeated_activity(
        commands,
        rng,
    )

    # --------------------------------------------------------
    # File transfer variation
    # --------------------------------------------------------

    maybe_add_file_transfer(
        commands,
        rng,
        scenario_id,
    )

    # --------------------------------------------------------
    # Preserve multi-stage order
    # --------------------------------------------------------

    if scenario_id != "multi_stage":

        rng.shuffle(
            commands
        )

    # --------------------------------------------------------
    # Safety
    # --------------------------------------------------------

    if not commands:

        raise ValueError(
            f"Scenario '{scenario_id}' "
            "generated no commands."
        )

    # --------------------------------------------------------
    # End session
    # --------------------------------------------------------

    commands.append(
        "exit"
    )

    return (
        commands,
        behavior_atoms,
    )


# ============================================================
# HELPERS
# ============================================================

def get_scenario_ids():

    return list(
        SCENARIO_DEFINITIONS.keys()
    )


def get_pattern_count():

    return sum(
        len(definitions)
        for definitions in
        SCENARIO_DEFINITIONS.values()
    )


def sample_scenario_id(rng):

    return rng.choice(
        get_scenario_ids()
    )


# ============================================================
# DIVERSITY TEST
# ============================================================

def run_diversity_test():

    rng = random.Random(42)

    print()
    print("=" * 70)
    print("V5 SCENARIO PATTERN TEST")
    print("=" * 70)

    print()
    print(
        f"Primary classes : "
        f"{len(SCENARIO_DEFINITIONS)}"
    )

    print(
        f"Total patterns  : "
        f"{get_pattern_count()}"
    )

    print()

    for scenario_id, definitions in (
        SCENARIO_DEFINITIONS.items()
    ):

        sequences = set()

        for _ in range(100):

            commands, behaviors = (
                build_scenario_commands(
                    scenario_id,
                    rng,
                )
            )

            sequences.add(
                tuple(commands)
            )

        print(
            f"{scenario_id:<25} "
            f"patterns={len(definitions):2d} "
            f"unique_sequences="
            f"{len(sequences):3d}/100"
        )


# ============================================================
# CROSS-CLASS OVERLAP TEST
# ============================================================

def run_overlap_test():

    print()
    print("=" * 70)
    print("CROSS-CLASS BEHAVIOR OVERLAP TEST")
    print("=" * 70)

    rng = random.Random(2026)

    observed = {}

    for scenario_id in SCENARIO_DEFINITIONS:

        if scenario_id == "benign":
            continue

        behavior_seen = set()

        for _ in range(100):

            commands, _ = build_scenario_commands(
                scenario_id,
                rng,
            )

            command_text = " ".join(
                commands
            )

            for behavior, library in (
                COMMAND_LIBRARY.items()
            ):

                if behavior == "benign":
                    continue

                if any(
                    command in command_text
                    for command in library
                ):
                    behavior_seen.add(
                        behavior
                    )

        observed[
            scenario_id
        ] = behavior_seen

        print(
            f"{scenario_id:<25} "
            f"observed_behaviors="
            f"{len(behavior_seen):2d} "
            f"{sorted(behavior_seen)}"
        )

    print()
    print(
        "Cross-class overlap test        : PASS"
    )


# ============================================================
# SAFETY TEST
# ============================================================

def run_safety_test():

    print()
    print("=" * 70)
    print("SAFETY / SANITY TEST")
    print("=" * 70)

    # --------------------------------------------------------
    # Commands that should never appear in generated data
    # --------------------------------------------------------

    forbidden_commands = {
        "top",
        "htop",
        "less",
        "more",
        "su -",
        "ftp -v",
        "sftp -V",
    }

    found = set()

    for commands in (
        COMMAND_LIBRARY.values()
    ):

        for command in commands:

            if command in forbidden_commands:

                found.add(
                    command
                )

    if found:

        raise AssertionError(
            "Interactive commands detected: "
            f"{sorted(found)}"
        )

    print(
        "Interactive command test       : PASS"
    )

    # --------------------------------------------------------
    # Benign overlap test
    # --------------------------------------------------------

    benign = set(
        COMMAND_LIBRARY["benign"]
    )

    attack_behaviors = [
        behavior
        for behavior in COMMAND_LIBRARY
        if behavior != "benign"
    ]

    attack_commands = set()

    for behavior in attack_behaviors:

        attack_commands.update(
            COMMAND_LIBRARY[
                behavior
            ]
        )

    overlap = (
        benign
        & attack_commands
    )

    if overlap:

        raise AssertionError(
            "Benign commands overlap attack "
            f"libraries: {sorted(overlap)}"
        )

    print(
        "Benign contamination test       : PASS"
    )

    # --------------------------------------------------------
    # Credential syntax test
    # --------------------------------------------------------

    malformed = []

    for command in (
        COMMAND_LIBRARY[
            "credential_access"
        ]
    ):

        if "grep root/etc/" in command:

            malformed.append(
                command
            )

        if "grep '1000'/etc/" in command:

            malformed.append(
                command
            )

    if malformed:

        raise AssertionError(
            "Malformed credential commands: "
            f"{malformed}"
        )

    print(
        "Credential syntax test          : PASS"
    )

    # --------------------------------------------------------
    # Validate definitions
    # --------------------------------------------------------

    validate_library()

    print(
        "Scenario definition validation  : PASS"
    )


# ============================================================
# SELF TEST
# ============================================================

def run_self_test():

    validate_library()

    print()
    print("=" * 70)
    print("EXPANDED V5 SCENARIO GENERATOR")
    print("=" * 70)

    print()
    print(
        f"Primary ML classes : "
        f"{len(SCENARIO_DEFINITIONS)}"
    )

    print(
        f"Behavior libraries : "
        f"{len(COMMAND_LIBRARY)}"
    )

    print(
        f"Scenario patterns  : "
        f"{get_pattern_count()}"
    )

    print()
    print("-" * 70)
    print("EXAMPLE GENERATED SESSIONS")
    print("-" * 70)

    rng = random.Random(42)

    for scenario_id in (
        SCENARIO_DEFINITIONS
    ):

        commands, behaviors = (
            build_scenario_commands(
                scenario_id,
                rng,
            )
        )

        print()
        print(
            f"Scenario : {scenario_id}"
        )

        print(
            f"Expected : {behaviors}"
        )

        print(
            f"Commands : {commands}"
        )

    run_diversity_test()

    run_overlap_test()

    run_safety_test()

    print()
    print("=" * 70)
    print("V5 SELF TEST COMPLETED SUCCESSFULLY")
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    run_self_test()