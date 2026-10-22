from __future__ import annotations

import re
from typing import Dict, List


# ============================================================
# BEHAVIOR DETECTION RULES
# ============================================================

BEHAVIOR_RULES = {

    # --------------------------------------------------------
    # Account Discovery
    # ATT&CK: T1033 - System Owner/User Discovery
    # --------------------------------------------------------
    "account_discovery": [
        r"^\s*whoami\b",
        r"^\s*id\b",
        r"^\s*groups\b",
        r"^\s*users\b",
        r"^\s*w\b",
        r"^\s*who\b",
        r"^\s*cat\s+/etc/passwd\b",
        r"^\s*cat\s+/etc/group\b",
        r"^\s*grep\b.*?/etc/passwd\b",
        r"^\s*grep\b.*?/etc/group\b",
    ],

    # --------------------------------------------------------
    # System Discovery
    # ATT&CK: T1082 - System Information Discovery
    # --------------------------------------------------------
    "system_discovery": [
    r"^\s*uname\b",
    r"^\s*hostname\b",
    r"^\s*hostnamectl\b",
    r"^\s*cat\s+/etc/os-release\b",
    r"^\s*cat\s+/etc/issue\b",
    r"^\s*cat\s+/etc/hostname\b",
],

    # --------------------------------------------------------
    # File and Directory Discovery
    # ATT&CK: T1083 - File and Directory Discovery
    # --------------------------------------------------------
    "file_discovery": [
        r"^\s*ls\b",
        r"^\s*find\b",
        r"^\s*locate\b",
        r"^\s*tree\b",
        r"^\s*dir\b",
    ],

    # --------------------------------------------------------
    # Process Discovery
    # ATT&CK: T1057 - Process Discovery
    # --------------------------------------------------------
    "process_discovery": [
        r"^\s*ps\b",
        r"^\s*top\b",
        r"^\s*htop\b",
        r"^\s*pgrep\b",
        r"^\s*pstree\b",
    ],

    # --------------------------------------------------------
    # Network Discovery
    # ATT&CK: T1016 - System Network Configuration Discovery
    # --------------------------------------------------------
    "network_discovery": [
    r"^\s*ip\s+addr\b",
    r"^\s*ip\s+route\b",
    r"^\s*ip\s+link\b",
    r"^\s*ifconfig\b",
    r"^\s*route\b",
    r"^\s*arp\b",
    r"^\s*netstat\b",
    r"^\s*ss\b",
],

    # --------------------------------------------------------
    # Credential Access
    # ATT&CK: T1003 - OS Credential Dumping
    # --------------------------------------------------------
    "credential_access": [
    r"^\s*cat\s+/etc/passwd\b",
    r"^\s*cat\s+/etc/shadow\b",
    r"^\s*cat\s+/etc/gshadow\b",

    r"^\s*grep\b.*?/etc/passwd\b",
    r"^\s*grep\b.*?/etc/shadow\b",
    r"^\s*grep\b.*?/etc/gshadow\b",

    r"^\s*head\s+/etc/shadow\b",
    r"^\s*tail\s+/etc/shadow\b",

    r"^\s*passwd\b",
    r"^\s*chpasswd\b",
],

    # --------------------------------------------------------
    # File Access
    # --------------------------------------------------------
    "file_access": [
        r"^\s*cat\b",
        r"^\s*less\b",
        r"^\s*more\b",
        r"^\s*head\b",
        r"^\s*tail\b",
        r"^\s*cp\b",
        r"^\s*mv\b",
    ],

    # --------------------------------------------------------
    # Execution
    # --------------------------------------------------------
    "execution": [
        r"^\s*python\b",
        r"^\s*python[0-9.]*\b",
        r"^\s*perl\b",
        r"^\s*ruby\b",
        r"^\s*php\b",
        r"^\s*bash\b",
        r"^\s*sh\b",
        r"^\s*zsh\b",
    ],

    # --------------------------------------------------------
    # File Transfer
    # ATT&CK: T1105 - Ingress Tool Transfer
    # --------------------------------------------------------
    "file_transfer": [
        r"^\s*wget\b",
        r"^\s*curl\b",
        r"^\s*scp\b",
        r"^\s*sftp\b",
        r"^\s*ftp\b",
        r"^\s*tftp\b",
    ],

    # --------------------------------------------------------
    # Privilege Activity
    # ATT&CK: T1548 - Abuse Elevation Control Mechanism
    # --------------------------------------------------------
    "privilege_activity": [
        r"^\s*sudo\b",
        r"^\s*su\b",
        r"^\s*doas\b",
    ],

    # --------------------------------------------------------
    # Persistence
    # ATT&CK: T1053 - Scheduled Task/Job
    # --------------------------------------------------------
    "persistence": [
        r"^\s*crontab\b",
        r"^\s*at\b",
        r"^\s*systemctl\b",
        r"^\s*service\b",
    ],

    # --------------------------------------------------------
    # File Modification
    # --------------------------------------------------------
    "file_modification": [
        r"^\s*touch\b",
        r"^\s*rm\b",
        r"^\s*mv\b",
        r"^\s*cp\b",
        r"^\s*mkdir\b",
        r"^\s*rmdir\b",
        r"^\s*chmod\b",
        r"^\s*chown\b",
        r">",
        r">>",
    ],

    # --------------------------------------------------------
    # Defense Evasion
    # ATT&CK: T1070 - Indicator Removal
    # --------------------------------------------------------
    "defense_evasion": [
        r"^\s*history\s+-c\b",
        r"^\s*unset\s+HISTFILE\b",
        r"^\s*rm\s+.*log\b",
        r"^\s*truncate\b",
        r"^\s*clear\b",
    ],
}


# ============================================================
# ATT&CK MAPPING
# ============================================================

BEHAVIOR_ATTACK_MAPPING = {

    "account_discovery": {
        "technique_id": "T1033",
        "technique_name": "System Owner/User Discovery",
    },

    "system_discovery": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
    },

    "file_discovery": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
    },

    "process_discovery": {
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
    },

    "network_discovery": {
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
    },

    "credential_access": {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
    },

    "file_transfer": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
    },

    "privilege_activity": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
    },

    "persistence": {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
    },

    "defense_evasion": {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
    },
}


# ============================================================
# BEHAVIOR DETECTION
# ============================================================

def detect_behaviors(command: str) -> List[str]:
    """
    Detect all behaviors represented by a single command.

    A single command may legitimately trigger multiple
    behavior categories.
    """

    if not command:
        return []

    command = command.strip()

    if not command:
        return []

    detected = []

    for behavior, patterns in BEHAVIOR_RULES.items():

        for pattern in patterns:

            try:
                if re.search(
                    pattern,
                    command,
                    flags=re.IGNORECASE
                ):
                    detected.append(behavior)
                    break

            except re.error:
                # Ignore malformed rules instead of stopping
                # the entire analyzer.
                continue

    return detected


# ============================================================
# ATT&CK LOOKUP
# ============================================================

def get_attack_mapping(behavior: str) -> Dict[str, str]:
    """
    Return ATT&CK information associated with a behavior.
    """

    return BEHAVIOR_ATTACK_MAPPING.get(
        behavior,
        {
            "technique_id": "UNKNOWN",
            "technique_name": "Unknown",
        },
    )


# ============================================================
# ATT&CK CONTEXT
# ============================================================

def get_attack_context(behavior: str) -> Dict[str, str]:
    """
    Return ATT&CK context for a detected behavior.

    This function is used by behavior_analyzer.py.
    """

    mapping = get_attack_mapping(behavior)

    return {
        "technique_id": mapping["technique_id"],
        "technique_name": mapping["technique_name"],
    }


# ============================================================
# ATT&CK TECHNIQUE ID
# ============================================================

def get_technique_id(behavior: str) -> str:
    """
    Return the ATT&CK technique ID associated with a behavior.
    """

    mapping = get_attack_mapping(behavior)

    return mapping["technique_id"]


# ============================================================
# ATT&CK TECHNIQUE NAME
# ============================================================

def get_technique_name(behavior: str) -> str:
    """
    Return the ATT&CK technique name associated with a behavior.
    """

    mapping = get_attack_mapping(behavior)

    return mapping["technique_name"]


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":

    test_commands = [
        "whoami",
        "id",
        "groups",
        "users",
        "who",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "uname -a",
        "hostname",
        "ls -la",
        "find /tmp -type f",
        "ps aux",
        "ip addr",
        "sudo -l",
        "crontab -l",
        "python --version",
        "wget http://example.com/file",
        "touch /tmp/test_marker",
        "rm /tmp/test_marker",
    ]

    print("=" * 70)
    print("BEHAVIOR RULE SELF TEST")
    print("=" * 70)

    for command in test_commands:

        behaviors = detect_behaviors(command)

        print()
        print("Command :", command)
        print(
            "Behaviors:",
            behaviors if behaviors else "none"
        )

        for behavior in behaviors:

            context = get_attack_context(behavior)

            print(
                f"  {behavior} -> "
                f"{context['technique_id']} "
                f"({context['technique_name']})"
            )