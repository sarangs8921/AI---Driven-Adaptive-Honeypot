from __future__ import annotations

import os
from typing import Any

import psycopg
from psycopg.rows import dict_row


class Database:
    """
    PostgreSQL database helper for the adaptive honeypot.
    """

    def __init__(self) -> None:
        self.host = os.getenv(
            "POSTGRES_HOST",
            "localhost",
        )

        self.port = int(
            os.getenv(
                "POSTGRES_PORT",
                "5432",
            )
        )

        self.database = os.getenv(
            "POSTGRES_DB",
            "honeypot",
        )

        self.user = os.getenv(
            "POSTGRES_USER",
            "honeypot",
        )

        self.password = os.getenv(
            "POSTGRES_PASSWORD",
            "honeypot_dev_password",
        )

    # =========================================================
    # CONNECTION
    # =========================================================

    def connect(self):
        return psycopg.connect(
            host=self.host,
            port=self.port,
            dbname=self.database,
            user=self.user,
            password=self.password,
            row_factory=dict_row,
        )

    # =========================================================
    # SESSION
    # =========================================================

    def create_session(
        self,
        session_id: str,
        protocol: str | None = None,
        source_ip: str | None = None,
        source_port: int | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        username: str | None = None,
        start_time: Any = None,
        successful_auth: bool | None = None,
        failed_attempts: int | None = None,
    ) -> None:
        """
        Create a session row.

        Existing sessions are not overwritten.

        This is useful because the adapter may call
        create_session more than once.
        """

        with self.connect() as conn:
            with conn.cursor() as cur:

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
                        successful_auth,
                        failed_attempts
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (session_id)
                    DO UPDATE SET
                        protocol = COALESCE(
                            sessions.protocol,
                            EXCLUDED.protocol
                        ),

                        source_ip = COALESCE(
                            sessions.source_ip,
                            EXCLUDED.source_ip
                        ),

                        source_port = COALESCE(
                            sessions.source_port,
                            EXCLUDED.source_port
                        ),

                        destination_ip = COALESCE(
                            sessions.destination_ip,
                            EXCLUDED.destination_ip
                        ),

                        destination_port = COALESCE(
                            sessions.destination_port,
                            EXCLUDED.destination_port
                        ),

                        username = COALESCE(
                            sessions.username,
                            EXCLUDED.username
                        ),

                        start_time = COALESCE(
                            sessions.start_time,
                            EXCLUDED.start_time
                        ),

                        successful_auth = COALESCE(
                            sessions.successful_auth,
                            EXCLUDED.successful_auth
                        ),

                        failed_attempts = COALESCE(
                            sessions.failed_attempts,
                            EXCLUDED.failed_attempts
                        )
                    """,
                    (
                        session_id,
                        protocol,
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                        username,
                        start_time,
                        successful_auth,
                        failed_attempts,
                    ),
                )

    # =========================================================
    # UPDATE SESSION METADATA
    # =========================================================

    def update_session_metadata(
        self,
        session_id: str,
        protocol: str | None = None,
        source_ip: str | None = None,
        source_port: int | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        username: str | None = None,
        start_time: Any = None,
        end_time: Any = None,
        successful_auth: bool | None = None,
        failed_attempts: int | None = None,
        duration_ms: int | None = None,
        event_count: int | None = None,
        empty_command_count: int | None = None,
    ) -> None:
        """
        Update only the metadata values that are supplied.

        NULL values are ignored so that a later partial update
        does not destroy already-known information.
        """

        with self.connect() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    UPDATE sessions
                    SET
                        protocol = COALESCE(
                            %s,
                            protocol
                        ),

                        source_ip = COALESCE(
                            %s,
                            source_ip
                        ),

                        source_port = COALESCE(
                            %s,
                            source_port
                        ),

                        destination_ip = COALESCE(
                            %s,
                            destination_ip
                        ),

                        destination_port = COALESCE(
                            %s,
                            destination_port
                        ),

                        username = COALESCE(
                            %s,
                            username
                        ),

                        start_time = COALESCE(
                            %s,
                            start_time
                        ),

                        end_time = COALESCE(
                            %s,
                            end_time
                        ),

                        successful_auth = COALESCE(
                            %s,
                            successful_auth
                        ),

                        failed_attempts = COALESCE(
                            %s,
                            failed_attempts
                        ),

                        duration_ms = COALESCE(
                            %s,
                            duration_ms
                        ),

                        event_count = COALESCE(
                            %s,
                            event_count
                        ),

                        empty_command_count = COALESCE(
                            %s,
                            empty_command_count
                        )
                    WHERE session_id = %s
                    """,
                    (
                        protocol,
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                        username,
                        start_time,
                        end_time,
                        successful_auth,
                        failed_attempts,
                        duration_ms,
                        event_count,
                        empty_command_count,
                        session_id,
                    ),
                )

    # =========================================================
    # AUTHENTICATION
    # =========================================================

    def update_authentication(
        self,
        session_id: str,
        successful_auth: bool | None = None,
        failed_attempts: int | None = None,
    ) -> None:
        """
        Update authentication information.
        """

        with self.connect() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    UPDATE sessions
                    SET
                        successful_auth = COALESCE(
                            %s,
                            successful_auth
                        ),

                        failed_attempts = COALESCE(
                            %s,
                            failed_attempts
                        )
                    WHERE session_id = %s
                    """,
                    (
                        successful_auth,
                        failed_attempts,
                        session_id,
                    ),
                )

    # =========================================================
    # COMMAND
    # =========================================================

    def add_command(
        self,
        session_id: str,
        command: str,
        timestamp: Any = None,
    ) -> int:

        with self.connect() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO commands (
                        session_id,
                        command,
                        timestamp
                    )
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (
                        session_id,
                        command,
                        timestamp,
                    ),
                )

                row = cur.fetchone()

                if row is None:
                    raise RuntimeError(
                        "Failed to create command record."
                    )

                return int(row["id"])

    # =========================================================
    # BEHAVIOR
    # =========================================================

    def add_behavior(
        self,
        session_id: str,
        behavior: str,
        command_id: int | None = None,
        technique_id: str | None = None,
    ) -> int:

        with self.connect() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO behaviors (
                        session_id,
                        command_id,
                        behavior,
                        technique_id
                    )
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        session_id,
                        command_id,
                        behavior,
                        technique_id,
                    ),
                )

                row = cur.fetchone()

                if row is None:
                    raise RuntimeError(
                        "Failed to create behavior record."
                    )

                return int(row["id"])

    # =========================================================
    # RISK
    # =========================================================

    def add_risk_assessment(
        self,
        session_id: str,
        risk_score: float,
        risk_state: str,
    ) -> int:

        with self.connect() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO risk_assessments (
                        session_id,
                        risk_score,
                        risk_state
                    )
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (
                        session_id,
                        risk_score,
                        risk_state,
                    ),
                )

                row = cur.fetchone()

                if row is None:
                    raise RuntimeError(
                        "Failed to create risk assessment."
                    )

                return int(row["id"])

    # =========================================================
    # ADAPTIVE ACTION
    # =========================================================

    def add_adaptive_action(
        self,
        session_id: str,
        action: str,
        risk_score: float | None = None,
        risk_state: str | None = None,
        command_id: int | None = None,
        target: str | None = None,
    ) -> int:

        with self.connect() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO adaptive_actions (
                        session_id,
                        command_id,
                        risk_score,
                        risk_state,
                        action,
                        target
                    )
                    VALUES (
                        %s, %s, %s,
                        %s, %s, %s
                    )
                    RETURNING id
                    """,
                    (
                        session_id,
                        command_id,
                        risk_score,
                        risk_state,
                        action,
                        target,
                    ),
                )

                row = cur.fetchone()

                if row is None:
                    raise RuntimeError(
                        "Failed to create adaptive action."
                    )

                return int(row["id"])

    # =========================================================
    # DECOY
    # =========================================================

    def add_decoy(
        self,
        session_id: str,
        virtual_path: str,
        decoy_type: str | None = None,
    ) -> int:

        with self.connect() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO decoys (
                        session_id,
                        virtual_path,
                        decoy_type
                    )
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (
                        session_id,
                        virtual_path,
                        decoy_type,
                    ),
                )

                row = cur.fetchone()

                if row is None:
                    raise RuntimeError(
                        "Failed to create decoy record."
                    )

                return int(row["id"])