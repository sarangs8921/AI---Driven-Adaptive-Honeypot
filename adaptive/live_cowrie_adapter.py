from __future__ import annotations

import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# BEHAVIOR RULES
# ============================================================

BEHAVIOR_RULES = {
    "account_discovery": [
        r"^\s*whoami\b",
        r"^\s*id\b",
        r"^\s*users\b",
        r"^\s*w\b",
        r"^\s*last\b",
        r"^\s*cat\s+/etc/passwd\b",
    ],

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

    "system_discovery": [
        r"^\s*uname\b",
        r"^\s*hostname\b",
        r"^\s*hostnamectl\b",
        r"^\s*cat\s+/etc/os-release\b",
        r"^\s*cat\s+/etc/issue\b",
        r"^\s*cat\s+/etc/hostname\b",
    ],

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

    "file_discovery": [
        r"^\s*ls\b",
        r"^\s*find\b",
        r"^\s*locate\b",
        r"^\s*pwd\b",
        r"^\s*tree\b",
        r"^\s*dir\b",
    ],

    "file_access": [
        r"^\s*cat\b",
        r"^\s*less\b",
        r"^\s*more\b",
        r"^\s*head\b",
        r"^\s*tail\b",
        r"^\s*cp\b",
        r"^\s*mv\b",
    ],

    "process_discovery": [
        r"^\s*ps\b",
        r"^\s*top\b",
        r"^\s*htop\b",
        r"^\s*pgrep\b",
    ],

    "execution": [
        r"^\s*python\b",
        r"^\s*python3\b",
        r"^\s*perl\b",
        r"^\s*ruby\b",
        r"^\s*php\b",
        r"^\s*bash\b",
        r"^\s*sh\b",
    ],

    "privilege_activity": [
        r"^\s*sudo\b",
        r"^\s*su\b",
        r"^\s*chmod\b",
        r"^\s*chown\b",
    ],

    "file_transfer": [
        r"^\s*wget\b",
        r"^\s*curl\b",
        r"^\s*scp\b",
        r"^\s*sftp\b",
        r"^\s*ftp\b",
    ],

    "persistence": [
        r"^\s*crontab\b",
        r"^\s*systemctl\b",
        r"^\s*service\b",
        r"^\s*at\b",
    ],

    "file_modification": [
        r"^\s*rm\b",
        r"^\s*touch\b",
        r"^\s*mkdir\b",
        r"^\s*chmod\b",
        r"^\s*chown\b",
    ],
}


BEHAVIOR_WEIGHTS = {
    "account_discovery": 5,
    "system_discovery": 5,
    "network_discovery": 5,
    "file_discovery": 5,
    "file_access": 5,
    "process_discovery": 5,
    "credential_access": 15,
    "execution": 10,
    "file_transfer": 10,
    "privilege_activity": 15,
    "persistence": 20,
    "file_modification": 10,
}


# ============================================================
# HELPERS
# ============================================================

def detect_behaviors(command: str) -> list[str]:

    detected = []

    for behavior, patterns in BEHAVIOR_RULES.items():

        for pattern in patterns:

            if re.search(
                pattern,
                command,
                re.IGNORECASE,
            ):
                detected.append(behavior)
                break

    return detected


def get_risk_state(score: int) -> str:

    if score >= 70:
        return "CRITICAL"

    if score >= 45:
        return "HIGH"

    if score >= 20:
        return "MEDIUM"

    return "LOW"


# ============================================================
# ADAPTER
# ============================================================

class LiveCowrieAdapter:

    def __init__(self, protocol):

        self.protocol = protocol
        self.fs = protocol.fs

        self.session_id = (
            self._get_session_id()
        )

        self.risk_score = 0

        self.behavior_counts = {}

        self.created_decoys = set()

        self.executed_actions = set()

        self.command_count = 0

        self.start_time = (
            datetime.now(timezone.utc)
        )

        print(
            "[ADAPTIVE] "
            f"Session {self.session_id} "
            "initialized"
        )

    # --------------------------------------------------------
    # SESSION ID
    # --------------------------------------------------------

    def _get_session_id(self):

        try:

            transport = (
                self.protocol.getProtoTransport()
            )

            transport_id = getattr(
                transport,
                "transportId",
                None,
            )

            if transport_id:
                return str(transport_id)

        except Exception as exc:

            print(
                "[ADAPTIVE] "
                f"Session ID error: {exc}"
            )

        return uuid.uuid4().hex[:12]

    # --------------------------------------------------------
    # COMMAND OBSERVATION
    # --------------------------------------------------------

    def observe_command(
        self,
        command: str,
        args: str = "",
    ):

        command = str(
            command or ""
        ).strip()

        args = str(
            args or ""
        ).strip()

        if args:

            full_command = (
                f"{command} {args}"
            )

        else:

            full_command = command

        if not full_command:
            return None

        self.command_count += 1

        behaviors = detect_behaviors(
            full_command
        )

        risk_added = 0

        actions = []

        # ----------------------------------------------------
        # BEHAVIOR PROCESSING
        # ----------------------------------------------------

        for behavior in behaviors:

            count = (
                self.behavior_counts.get(
                    behavior,
                    0,
                )
                + 1
            )

            self.behavior_counts[
                behavior
            ] = count

            # -----------------------------------------------
            # Only first 3 occurrences contribute risk.
            # -----------------------------------------------

            if count <= 3:

                risk_added += (
                    BEHAVIOR_WEIGHTS.get(
                        behavior,
                        0,
                    )
                )

            # -----------------------------------------------
            # Adaptive deception
            # -----------------------------------------------

            if behavior == "file_discovery":

                path = (
                    "/tmp/system_backup.txt"
                )

                if path not in (
                    self.created_decoys
                ):

                    self._create_decoy(
                        path,
                        "file_discovery_decoy",
                        (
                            "SYSTEM BACKUP INDEX\n"
                            "===================\n"
                            "backup-2026-09.tar.gz\n"
                            "system-config.tar.gz\n"
                            "home-data.tar.gz\n"
                        ),
                    )

                    actions.append(
                        "file_discovery_deception"
                    )

            elif behavior == "credential_access":

                path = (
                    "/tmp/.credentials_backup.txt"
                )

                if path not in (
                    self.created_decoys
                ):

                    self._create_decoy(
                        path,
                        "credential_deception",
                        (
                            "# Backup credentials "
                            "(redacted)\n"
                            "admin=REDACTED\n"
                            "backup=REDACTED\n"
                            "database=REDACTED\n"
                        ),
                    )

                    actions.append(
                        "credential_deception"
                    )

            elif behavior == "system_discovery":

                path = (
                    "/tmp/system_info.txt"
                )

                if path not in (
                    self.created_decoys
                ):

                    self._create_decoy(
                        path,
                        "system_discovery_decoy",
                        (
                            "System Information\n"
                            "==================\n"
                            "Hostname: backup-server\n"
                            "OS: Ubuntu Server 22.04\n"
                            "Kernel: 5.15.0-honeypot\n"
                            "Architecture: x86_64\n"
                        ),
                    )

                    actions.append(
                        "system_discovery_deception"
                    )

        # ----------------------------------------------------
        # UPDATE RISK
        # ----------------------------------------------------

        old_score = self.risk_score

        self.risk_score = min(
            100,
            self.risk_score + risk_added,
        )

        actual_added = (
            self.risk_score - old_score
        )

        risk_state = get_risk_state(
            self.risk_score
        )

        # ----------------------------------------------------
        # STATE MONITORING
        # ----------------------------------------------------

        state_action = (
            f"{risk_state.lower()}"
            "_threat_monitoring"
        )

        if state_action not in (
            self.executed_actions
        ):

            self.executed_actions.add(
                state_action
            )

            actions.append(
                state_action
            )

        print(
            "[ADAPTIVE] "
            f"Command: {full_command}"
        )

        print(
            "[ADAPTIVE] "
            f"Behaviors: {behaviors}"
        )

        print(
            "[ADAPTIVE] "
            f"Risk: {self.risk_score} "
            f"({risk_state})"
        )

        if actions:

            print(
                "[ADAPTIVE] "
                f"Actions: {actions}"
            )

        return {
            "session_id":
                self.session_id,

            "command":
                full_command,

            "behaviors":
                behaviors,

            "risk_added":
                actual_added,

            "risk_score":
                self.risk_score,

            "risk_state":
                risk_state,

            "adaptive_actions":
                actions,
        }

    # --------------------------------------------------------
    # DECOY
    # --------------------------------------------------------

    def _create_decoy(
        self,
        virtual_path: str,
        decoy_type: str,
        contents: str,
    ):

        try:

            parent = str(
                Path(virtual_path).parent
            )

            if parent != "/":

                try:

                    self.fs.mkdir(
                        parent,
                        uid=0,
                        gid=0,
                        mode=0o755,
                    )

                except Exception:
                    pass

            self.fs.mkfile(
                virtual_path,
                uid=0,
                gid=0,
                size=len(contents),
                mode=0o644,
            )

            backing_file = (
                tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    delete=False,
                )
            )

            backing_file.write(
                contents
            )

            backing_file.flush()
            backing_file.close()

            self.fs.update_realfile(
                virtual_path,
                backing_file.name,
            )

            self.created_decoys.add(
                virtual_path
            )

            print(
                "[ADAPTIVE] "
                f"Decoy created: "
                f"{virtual_path}"
            )

        except Exception as exc:

            print(
                "[ADAPTIVE] "
                f"Decoy creation failed: "
                f"{exc}"
            )

    # --------------------------------------------------------
    # CLOSE
    # --------------------------------------------------------

    def close(self):

        print(
            "[ADAPTIVE] "
            f"Session {self.session_id} "
            "closed"
        )