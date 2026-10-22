from __future__ import annotations

import psycopg


DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 5432,
    "dbname": "honeypot",
    "user": "honeypot",
    "password": "honeypot_dev_password",
}


def get_connection():
    return psycopg.connect(**DB_CONFIG)


def create_tables():

    conn = get_connection()

    with conn.cursor() as cur:

        # ---------------------------------------------------------
        # Sessions
        # ---------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                protocol TEXT,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                username TEXT,
                start_time TIMESTAMPTZ,
                end_time TIMESTAMPTZ,
                duration_ms BIGINT,
                successful_auth BOOLEAN,
                failed_attempts INTEGER,
                event_count INTEGER,
                empty_command_count INTEGER,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """
        )

        # ---------------------------------------------------------
        # Commands
        # ---------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS commands (
                id BIGSERIAL PRIMARY KEY,
                session_id TEXT NOT NULL
                    REFERENCES sessions(session_id)
                    ON DELETE CASCADE,
                command TEXT NOT NULL,
                timestamp TIMESTAMPTZ
            );
            """
        )

        # ---------------------------------------------------------
        # Detected behaviors
        # ---------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS behaviors (
                id BIGSERIAL PRIMARY KEY,
                session_id TEXT NOT NULL
                    REFERENCES sessions(session_id)
                    ON DELETE CASCADE,
                command_id BIGINT
                    REFERENCES commands(id)
                    ON DELETE CASCADE,
                behavior TEXT NOT NULL,
                technique_id TEXT
            );
            """
        )

        # ---------------------------------------------------------
        # Risk assessments
        # ---------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_assessments (
                id BIGSERIAL PRIMARY KEY,
                session_id TEXT NOT NULL
                    REFERENCES sessions(session_id)
                    ON DELETE CASCADE,
                risk_score NUMERIC(10,2),
                risk_state TEXT,
                behavior_score NUMERIC(10,2),
                progression_score NUMERIC(10,2),
                authentication_score NUMERIC(10,2),
                reasons JSONB,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """
        )

        # ---------------------------------------------------------
        # Adaptive actions
        # ---------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS adaptive_actions (
                id BIGSERIAL PRIMARY KEY,
                session_id TEXT NOT NULL
                    REFERENCES sessions(session_id)
                    ON DELETE CASCADE,
                command_id BIGINT
                    REFERENCES commands(id)
                    ON DELETE CASCADE,
                risk_score NUMERIC(10,2),
                risk_state TEXT,
                action TEXT NOT NULL,
                target TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """
        )

        # ---------------------------------------------------------
        # Decoys
        # ---------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS decoys (
                id BIGSERIAL PRIMARY KEY,
                session_id TEXT NOT NULL
                    REFERENCES sessions(session_id)
                    ON DELETE CASCADE,
                virtual_path TEXT NOT NULL,
                decoy_type TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """
        )

    conn.commit()
    conn.close()

    print("PostgreSQL schema created successfully.")


def main():

    print("=" * 60)
    print("HONEYPOT POSTGRESQL DATABASE")
    print("=" * 60)

    create_tables()


if __name__ == "__main__":
    main()