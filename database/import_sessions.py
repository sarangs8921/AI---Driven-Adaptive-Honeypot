from __future__ import annotations

import json
from pathlib import Path

from database.postgres_db import get_connection


SESSION_FILE = Path(
    "data/processed/sessions/sessions.jsonl"
)


def import_sessions() -> None:

    if not SESSION_FILE.exists():
        print("Session file not found:")
        print(SESSION_FILE)
        return

    conn = get_connection()

    session_count = 0
    command_count = 0

    with SESSION_FILE.open("r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            session = json.loads(line)

            session_id = session["session_id"]

            authentication = session.get(
                "authentication",
                {},
            )

            with conn.cursor() as cur:

                # -----------------------------
                # Session
                # -----------------------------

                cur.execute(
                    """
                    INSERT INTO sessions (
                        session_id,
                        protocol,
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                        username,
                        start_time,
                        end_time,
                        duration_ms,
                        successful_auth,
                        failed_attempts,
                        event_count,
                        empty_command_count
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (session_id)
                    DO UPDATE SET
                        end_time = EXCLUDED.end_time,
                        duration_ms = EXCLUDED.duration_ms,
                        event_count = EXCLUDED.event_count
                    """,
                    (
                        session_id,
                        session.get("protocol"),
                        session.get("source_ip"),
                        session.get("source_port"),
                        session.get("destination_ip"),
                        session.get("destination_port"),
                        session.get("username"),
                        session.get("start_time"),
                        session.get("end_time"),
                        session.get("duration_ms"),
                        authentication.get(
                            "successful",
                            False,
                        ),
                        authentication.get(
                            "failed_attempts",
                            0,
                        ),
                        session.get(
                            "event_count",
                            0,
                        ),
                        session.get(
                            "empty_command_count",
                            0,
                        ),
                    ),
                )

                # -----------------------------
                # Commands
                # -----------------------------

                cur.execute(
                    """
                    DELETE FROM commands
                    WHERE session_id = %s
                    """,
                    (session_id,),
                )

                for command in session.get(
                    "commands",
                    [],
                ):

                    cur.execute(
                        """
                        INSERT INTO commands (
                            session_id,
                            command,
                            timestamp
                        )
                        VALUES (%s, %s, %s)
                        """,
                        (
                            session_id,
                            command.get("command"),
                            command.get("timestamp"),
                        ),
                    )

                    command_count += 1

            session_count += 1

    conn.commit()
    conn.close()

    print("=" * 60)
    print("POSTGRESQL SESSION IMPORT")
    print("=" * 60)
    print(f"Sessions imported : {session_count}")
    print(f"Commands imported : {command_count}")


if __name__ == "__main__":
    import_sessions()
