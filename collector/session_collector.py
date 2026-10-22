import json
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path


OUTPUT_FILE = Path(
    "data/processed/sessions/sessions.jsonl"
)

COWRIE_CONTAINER = "cowrie"

COWRIE_LOG = (
    "/cowrie/cowrie-git/var/log/cowrie/cowrie.json.2026-09-30"
)

COWRIE_PYTHON = (
    "/cowrie/cowrie-env/bin/python"
)


def read_cowrie_log():
    """
    Read Cowrie JSON log from inside the Docker container.
    """

    script = f"""
import json

path = "{COWRIE_LOG}"

with open(path, encoding="utf-8") as f:
    for line in f:
        if line.strip():
            print(line.rstrip())
"""

    result = subprocess.run(
        [
            "docker",
            "exec",
            COWRIE_CONTAINER,
            COWRIE_PYTHON,
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    events = []

    for line in result.stdout.splitlines():

        if not line.strip():
            continue

        try:
            events.append(
                json.loads(line)
            )
        except json.JSONDecodeError:
            continue

    return events


def parse_timestamp(value):
    """
    Parse Cowrie ISO-8601 timestamp.
    """

    if not value:
        return None

    if isinstance(value, datetime):
        return value

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except (
        TypeError,
        ValueError,
    ):
        return None


def event_timestamp(event):
    """
    Get timestamp from a Cowrie event.
    """

    return event.get("timestamp")


def get_session_id(event):
    """
    Extract Cowrie session identifier.
    """

    return event.get("session")


def reconstruct_sessions(events):
    """
    Reconstruct sessions from Cowrie events.
    """

    sessions = defaultdict(
        lambda: {
            "session_id": None,
            "protocol": None,
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,

            "username": None,

            "start_time": None,
            "end_time": None,

            "commands": [],

            "successful_auth": None,
            "failed_attempts": 0,

            "event_count": 0,
        }
    )

    for event in events:

        session_id = get_session_id(event)

        if not session_id:
            continue

        event_id = event.get(
            "eventid",
            "",
        )

        session = sessions[session_id]

        session["session_id"] = session_id

        session["event_count"] += 1

        timestamp = event_timestamp(
            event
        )

        parsed_time = parse_timestamp(
            timestamp
        )

        # -----------------------------------------------------
        # Session start
        # -----------------------------------------------------

        if event_id == "cowrie.session.connect":

            if parsed_time:

                session["start_time"] = (
                    parsed_time
                )

            session["src_ip"] = event.get(
                "src_ip"
            )

            session["src_port"] = event.get(
                "src_port"
            )

            session["dst_ip"] = event.get(
                "dst_ip"
            )

            session["dst_port"] = event.get(
                "dst_port"
            )

            session["protocol"] = event.get(
                "protocol"
            )

        # -----------------------------------------------------
        # Session parameters
        # -----------------------------------------------------

        elif event_id == "cowrie.session.params":

            if event.get("username"):

                session["username"] = (
                    event.get("username")
                )

            if event.get("protocol"):

                session["protocol"] = (
                    event.get("protocol")
                )

        # -----------------------------------------------------
        # Successful authentication
        # -----------------------------------------------------

        elif event_id == "cowrie.login.success":

            session["successful_auth"] = True

            if event.get("username"):

                session["username"] = (
                    event.get("username")
                )

        # -----------------------------------------------------
        # Failed authentication
        # -----------------------------------------------------

        elif event_id == "cowrie.login.failed":

            session["successful_auth"] = False

            session["failed_attempts"] += 1

            if event.get("username"):

                session["username"] = (
                    event.get("username")
                )

        # -----------------------------------------------------
        # Commands
        # -----------------------------------------------------

        elif event_id == "cowrie.command.input":

            command = event.get(
                "input",
                event.get(
                    "command",
                    ""
                ),
            )

            if command is None:
                command = ""

            command = str(command)

            session["commands"].append(
                {
                    "command": command,
                    "timestamp": timestamp,
                }
            )

        # -----------------------------------------------------
        # Session closed
        # -----------------------------------------------------

        elif event_id == "cowrie.session.closed":

            if parsed_time:

                session["end_time"] = (
                    parsed_time
                )

    return sessions


def calculate_duration(session):
    """
    Calculate session duration in milliseconds.
    """

    start = session.get(
        "start_time"
    )

    end = session.get(
        "end_time"
    )

    if not start or not end:
        return 0

    duration = (
        end - start
    ).total_seconds()

    return int(
        max(duration, 0) * 1000
    )


def finalize_session(session):
    """
    Convert internal session structure
    into JSON-serializable record.
    """

    start = session.get(
        "start_time"
    )

    end = session.get(
        "end_time"
    )

    commands = session.get(
        "commands",
        [],
    )

    # If authentication never appeared,
    # preserve None rather than inventing
    # an authentication result.
    successful_auth = session.get(
        "successful_auth"
    )

    failed_attempts = session.get(
        "failed_attempts",
        0,
    )

    return {
        "session_id":
            session.get("session_id"),

        "protocol":
            session.get("protocol"),

        "src_ip":
            session.get("src_ip"),

        "src_port":
            session.get("src_port"),

        "dst_ip":
            session.get("dst_ip"),

        "dst_port":
            session.get("dst_port"),

        "username":
            session.get("username"),

        "start_time":
            start.isoformat()
            if start
            else None,

        "end_time":
            end.isoformat()
            if end
            else None,

        "duration_ms":
            calculate_duration(session),

        "commands":
            commands,

        "successful_auth":
            successful_auth,

        "failed_attempts":
            failed_attempts,

        "event_count":
            session.get(
                "event_count",
                0,
            ),

        "command_count":
            len(commands),

        "empty_command_count":
            sum(
                1
                for command in commands
                if not command.get(
                    "command",
                    "",
                ).strip()
            ),
    }


def save_sessions(sessions):
    """
    Save reconstructed sessions as JSONL.
    """

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    records = []

    for session in sessions.values():

        records.append(
            finalize_session(session)
        )

    # Sort chronologically
    records.sort(
        key=lambda record:
        record.get("start_time")
        or ""
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as f:

        for record in records:

            f.write(
                json.dumps(record)
                + "\n"
            )

    return records


def main():

    print("=" * 60)
    print("COWRIE SESSION COLLECTOR")
    print("=" * 60)

    print(
        "Reading Cowrie logs..."
    )

    events = read_cowrie_log()

    print(
        f"Events loaded: {len(events)}"
    )

    sessions = reconstruct_sessions(
        events
    )

    print(
        f"Sessions reconstructed: "
        f"{len(sessions)}"
    )

    records = save_sessions(
        sessions
    )

    print(
        f"Saved {len(records)} sessions."
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    # ---------------------------------------------------------
    # Authentication summary
    # ---------------------------------------------------------

    successful = sum(
        1
        for record in records
        if record.get(
            "successful_auth"
        ) is True
    )

    failed = sum(
        record.get(
            "failed_attempts",
            0,
        )
        for record in records
    )

    unknown = sum(
        1
        for record in records
        if record.get(
            "successful_auth"
        ) is None
    )

    print()
    print("Authentication summary:")
    print(
        f"  Successful sessions : {successful}"
    )
    print(
        f"  Failed attempts     : {failed}"
    )
    print(
        f"  Unknown             : {unknown}"
    )


if __name__ == "__main__":
    main()