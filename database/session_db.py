from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


DB_PATH = Path("data/processed/honeypot.db")
SESSION_FILE = Path("data/processed/sessions/sessions.jsonl")


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    return conn


def create_tables() -> None:

    conn = get_connection()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            protocol TEXT,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            username TEXT,
            start_time TEXT,
            end_time TEXT,
            duration_ms INTEGER,
            successful_auth INTEGER,
            failed_attempts INTEGER,
            event_count INTEGER,
            empty_command_count INTEGER
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            command TEXT,
            timestamp TEXT,
            FOREIGN KEY(session_id)
                REFERENCES sessions(session_id)
        )
        """
    )

    conn.commit()
    conn.close()


def insert_session(session: dict[str, Any]) -> None:

    conn = get_connection()

    conn.execute(
        """
        INSERT OR REPLACE INTO sessions (
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
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session.get("session_id"),
            session.get("protocol"),
            session.get("source_ip"),
            session.get("source_port"),
            session.get("destination_ip"),
            session.get("destination_port"),
            session.get("username"),
            session.get("start_time"),
            session.get("end_time"),
            session.get("duration_ms"),
            int(
                session.get("authentication", {}).get(
                    "successful",
                    False,
                )
            ),
            session.get("authentication", {}).get(
                "failed_attempts",
                0,
            ),
            session.get("event_count", 0),
            session.get("empty_command_count", 0),
        ),
    )

    conn.execute(
        "DELETE FROM commands WHERE session_id = ?",
        (session["session_id"],),
    )

    for command in session.get("commands", []):

        conn.execute(
            """
            INSERT INTO commands (
                session_id,
                command,
                timestamp
            )
            VALUES (?, ?, ?)
            """,
            (
                session["session_id"],
                command.get("command"),
                command.get("timestamp"),
            ),
        )

    conn.commit()
    conn.close()


def import_sessions() -> int:

    create_tables()

    if not SESSION_FILE.exists():
        print("Session file not found:")
        print(SESSION_FILE)
        return 0

    count = 0

    with SESSION_FILE.open("r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            session = json.loads(line)

            insert_session(session)

            count += 1

    return count


def main() -> None:

    print("=" * 60)
    print("HONEYPOT SESSION DATABASE")
    print("=" * 60)

    count = import_sessions()

    print()
    print(f"Sessions imported: {count}")
    print(f"Database: {DB_PATH}")


if __name__ == "__main__":
    main()
