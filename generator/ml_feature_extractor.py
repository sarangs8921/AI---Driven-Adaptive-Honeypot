import json
import re
from datetime import datetime
from pathlib import Path
from statistics import mean, pstdev


INPUT_FILE = Path("data/processed/sessions/sessions.jsonl")
OUTPUT_FILE = Path("data/generated/ml_features.jsonl")


def safe_mean(values):
    return mean(values) if values else 0.0


def safe_std(values):
    return pstdev(values) if len(values) > 1 else 0.0


def parse_timestamp(timestamp):
    """
    Parse Cowrie ISO-8601 timestamps.

    Example:
        2026-09-29T06:26:42.969047Z

    Returns:
        datetime object or None
    """

    if not timestamp:
        return None

    if isinstance(timestamp, datetime):
        return timestamp

    if not isinstance(timestamp, str):
        return None

    try:
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return None


def command_category(command):
    """
    Categorize commands using lexical characteristics.

    These categories are NOT the final behavior labels.
    They are used only as ML input features.
    """

    cmd = command.strip().lower()

    if not cmd:
        return "empty"

    first = cmd.split()[0]

    if first in {"whoami", "id", "groups"}:
        return "identity"

    if first in {"uname", "hostname"}:
        return "system"

    if first in {"ls", "pwd", "find", "locate"}:
        return "filesystem"

    if first in {"ps", "top"}:
        return "process"

    if first in {
        "ip",
        "ifconfig",
        "route",
        "netstat",
    }:
        return "network"

    if first in {
        "cat",
        "head",
        "tail",
        "less",
        "more",
    }:
        return "read"

    if first in {
        "python",
        "python3",
        "perl",
        "ruby",
    }:
        return "interpreter"

    if first in {
        "sudo",
        "su",
    }:
        return "privilege"

    if first in {
        "touch",
        "mv",
        "cp",
        "rm",
    }:
        return "file_modify"

    if first in {
        "wget",
        "curl",
        "ftp",
        "scp",
    }:
        return "transfer"

    if first in {
        "crontab",
        "at",
    }:
        return "persistence"

    if first in {
        "echo",
        "printf",
    }:
        return "output"

    if first in {
        "exit",
        "logout",
    }:
        return "session_control"

    return "other"


def extract_features(session):
    """
    Extract ML features from a reconstructed Cowrie session.

    IMPORTANT:
    This function intentionally does NOT use:
        - behavior labels
        - behavior counts
        - risk score
        - risk state
        - ATT&CK technique IDs

    Those belong to the rule/ground-truth/risk pipeline.
    """

    commands = session.get("commands", [])

    command_texts = []
    timestamps = []

    for item in commands:

        if isinstance(item, dict):

            command = str(
                item.get("command", "")
            ).strip()

            timestamp = item.get("timestamp")

        else:

            command = str(item).strip()
            timestamp = None

        if command:
            command_texts.append(command)

        if timestamp:
            timestamps.append(timestamp)

    # ---------------------------------------------------------
    # Basic command statistics
    # ---------------------------------------------------------

    command_lengths = [
        len(command)
        for command in command_texts
    ]

    command_count = len(command_texts)

    unique_commands = set(command_texts)

    unique_command_count = len(
        unique_commands
    )

    # ---------------------------------------------------------
    # Command categories
    # ---------------------------------------------------------

    categories = [
        command_category(command)
        for command in command_texts
    ]

    category_counts = {}

    for category in categories:

        category_counts[category] = (
            category_counts.get(category, 0) + 1
        )

    # ---------------------------------------------------------
    # Command transitions
    # ---------------------------------------------------------

    transitions = []

    for i in range(len(categories) - 1):

        transitions.append(
            f"{categories[i]}->{categories[i + 1]}"
        )

    unique_transitions = set(transitions)

    # ---------------------------------------------------------
    # Repeated commands
    # ---------------------------------------------------------

    command_frequency = {}

    for command in command_texts:

        command_frequency[command] = (
            command_frequency.get(command, 0) + 1
        )

    repeated_command_count = sum(
        count - 1
        for count in command_frequency.values()
        if count > 1
    )

    # ---------------------------------------------------------
    # Parse Cowrie timestamps
    # ---------------------------------------------------------

    parsed_timestamps = []

    for timestamp in timestamps:

        parsed = parse_timestamp(timestamp)

        if parsed is not None:
            parsed_timestamps.append(parsed)

    # ---------------------------------------------------------
    # Command timing
    # ---------------------------------------------------------

    time_gaps = []

    for i in range(
        len(parsed_timestamps) - 1
    ):

        try:

            gap = (
                parsed_timestamps[i + 1]
                - parsed_timestamps[i]
            ).total_seconds()

            if gap >= 0:
                time_gaps.append(gap)

        except (TypeError, ValueError):
            pass

    # ---------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------

    successful_auth = session.get(
        "successful_auth"
    )

    failed_attempts = session.get(
        "failed_attempts"
    )

    # Cowrie session reconstruction may not
    # currently provide these values.
    #
    # Do NOT fabricate them.
    #
    # Use 0 only when the field genuinely exists
    # and contains a numeric/boolean value.

    if successful_auth is None:
        successful_auth_value = 0
    else:
        successful_auth_value = int(
            bool(successful_auth)
        )

    if failed_attempts is None:
        failed_attempts_value = 0
    else:
        try:
            failed_attempts_value = int(
                failed_attempts
            )
        except (TypeError, ValueError):
            failed_attempts_value = 0

    # ---------------------------------------------------------
    # Shell syntax features
    # ---------------------------------------------------------

    shell_metacharacter_count = 0

    redirection_count = 0

    absolute_path_count = 0

    option_count = 0

    for command in command_texts:

        # Shell operators
        shell_metacharacter_count += sum(
            command.count(operator)
            for operator in [
                ";",
                "&&",
                "||",
                "|",
            ]
        )

        # Redirection
        redirection_count += sum(
            command.count(operator)
            for operator in [
                ">",
                "<",
            ]
        )

        # Absolute paths
        absolute_path_count += len(
            re.findall(
                r"/[A-Za-z0-9_.~/-]+",
                command,
            )
        )

        # Command options
        option_count += len(
            re.findall(
                r"(?:^|\s)-{1,2}[A-Za-z0-9_-]+",
                command,
            )
        )

    # ---------------------------------------------------------
    # ML feature dictionary
    # ---------------------------------------------------------

    features = {

        # -----------------------------------------------------
        # Session-level features
        # -----------------------------------------------------

        "duration_ms": session.get(
            "duration_ms",
            0,
        ) or 0,

        "event_count": session.get(
            "event_count",
            0,
        ) or 0,

        "command_count": command_count,

        "unique_command_count":
            unique_command_count,

        # -----------------------------------------------------
        # Command statistics
        # -----------------------------------------------------

        "avg_command_length":
            safe_mean(command_lengths),

        "std_command_length":
            safe_std(command_lengths),

        "max_command_length":
            max(
                command_lengths,
                default=0,
            ),

        "min_command_length":
            min(
                command_lengths,
                default=0,
            ),

        "repeated_command_count":
            repeated_command_count,

        "command_diversity":
            (
                unique_command_count
                / command_count
                if command_count > 0
                else 0.0
            ),

        # -----------------------------------------------------
        # Timing features
        # -----------------------------------------------------

        "avg_command_gap":
            safe_mean(time_gaps),

        "std_command_gap":
            safe_std(time_gaps),

        "max_command_gap":
            max(
                time_gaps,
                default=0,
            ),

        # -----------------------------------------------------
        # Authentication
        # -----------------------------------------------------

        "successful_auth":
            successful_auth_value,

        "failed_attempts":
            failed_attempts_value,

        # -----------------------------------------------------
        # Command syntax
        # -----------------------------------------------------

        "shell_metacharacter_count":
            shell_metacharacter_count,

        "redirection_count":
            redirection_count,

        "absolute_path_count":
            absolute_path_count,

        "option_count":
            option_count,

        # -----------------------------------------------------
        # Command-category distribution
        # -----------------------------------------------------

        "identity_command_count":
            category_counts.get(
                "identity",
                0,
            ),

        "system_command_count":
            category_counts.get(
                "system",
                0,
            ),

        "filesystem_command_count":
            category_counts.get(
                "filesystem",
                0,
            ),

        "process_command_count":
            category_counts.get(
                "process",
                0,
            ),

        "network_command_count":
            category_counts.get(
                "network",
                0,
            ),

        "read_command_count":
            category_counts.get(
                "read",
                0,
            ),

        "interpreter_command_count":
            category_counts.get(
                "interpreter",
                0,
            ),

        "privilege_command_count":
            category_counts.get(
                "privilege",
                0,
            ),

        "file_modify_command_count":
            category_counts.get(
                "file_modify",
                0,
            ),

        "transfer_command_count":
            category_counts.get(
                "transfer",
                0,
            ),

        "persistence_command_count":
            category_counts.get(
                "persistence",
                0,
            ),

        # -----------------------------------------------------
        # Sequence complexity
        # -----------------------------------------------------

        "unique_category_count":
            len(set(categories)),

        "transition_count":
            len(transitions),

        "unique_transition_count":
            len(unique_transitions),
    }

    return features


def main():

    print("=" * 60)
    print("ML FEATURE EXTRACTION")
    print("=" * 60)

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    sessions = []

    with INPUT_FILE.open(
        encoding="utf-8"
    ) as f:

        for line in f:

            if line.strip():

                sessions.append(
                    json.loads(line)
                )

    print(
        f"Sessions loaded: {len(sessions)}"
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as out:

        for session in sessions:

            record = {
                "session_id":
                    session["session_id"],

                "features":
                    extract_features(session),
            }

            out.write(
                json.dumps(record)
                + "\n"
            )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    if sessions:

        sample_features = extract_features(
            sessions[0]
        )

        print(
            f"Features generated: "
            f"{len(sample_features)}"
        )

        print(
            f"Output: {OUTPUT_FILE}"
        )

        print(
            "\nFeature names:"
        )

        for i, name in enumerate(
            sample_features.keys(),
            1,
        ):

            print(
                f"{i:2}. {name}"
            )

    print(
        "\nML feature extraction complete."
    )


if __name__ == "__main__":
    main()