import os
import psycopg


class AdaptiveDatabase:
    """
    Lightweight PostgreSQL helper used by the live Cowrie adapter.

    Database failures are intentionally isolated from Cowrie so that
    logging problems never terminate a honeypot session.
    """

    def __init__(self, session_id):
        self.session_id = session_id

        self.host = os.getenv("POSTGRES_HOST", "honeypot-postgres")
        self.port = int(os.getenv("POSTGRES_PORT", "5432"))
        self.dbname = os.getenv("POSTGRES_DB", "honeypot")
        self.user = os.getenv("POSTGRES_USER", "honeypot")
        self.password = os.getenv(
            "POSTGRES_PASSWORD",
            "honeypot_dev_password",
        )

        self.conn = None

    def connect(self):
        if self.conn is None or self.conn.closed:
            self.conn = psycopg.connect(
                host=self.host,
                port=self.port,
                dbname=self.dbname,
                user=self.user,
                password=self.password,
            )

    def create_session(self):
        try:
            self.connect()

            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO sessions (session_id)
                    VALUES (%s)
                    ON CONFLICT (session_id) DO NOTHING
                    """,
                    (self.session_id,),
                )

            self.conn.commit()

        except Exception as exc:
            self._rollback()
            print(f"[DATABASE] create_session failed: {exc}")

    def add_command(self, command, timestamp=None):
        try:
            self.connect()

            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO commands
                        (session_id, command, timestamp)
                    VALUES
                        (%s, %s, %s)
                    RETURNING id
                    """,
                    (
                        self.session_id,
                        command,
                        timestamp,
                    ),
                )

                command_id = cur.fetchone()[0]

            self.conn.commit()
            return command_id

        except Exception as exc:
            self._rollback()
            print(f"[DATABASE] add_command failed: {exc}")
            return None

    def add_behavior(
        self,
        behavior,
        command_id=None,
        technique_id=None,
    ):
        try:
            self.connect()

            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO behaviors
                        (
                            session_id,
                            command_id,
                            behavior,
                            technique_id
                        )
                    VALUES
                        (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        self.session_id,
                        command_id,
                        behavior,
                        technique_id,
                    ),
                )

                behavior_id = cur.fetchone()[0]

            self.conn.commit()
            return behavior_id

        except Exception as exc:
            self._rollback()
            print(f"[DATABASE] add_behavior failed: {exc}")
            return None

    def add_risk_assessment(
        self,
        risk_score,
        risk_state,
    ):
        try:
            self.connect()

            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO risk_assessments
                        (
                            session_id,
                            risk_score,
                            risk_state
                        )
                    VALUES
                        (%s, %s, %s)
                    RETURNING id
                    """,
                    (
                        self.session_id,
                        risk_score,
                        risk_state,
                    ),
                )

                assessment_id = cur.fetchone()[0]

            self.conn.commit()
            return assessment_id

        except Exception as exc:
            self._rollback()
            print(
                f"[DATABASE] add_risk_assessment failed: {exc}"
            )
            return None

    def add_adaptive_action(
        self,
        action,
        risk_score=None,
        risk_state=None,
        command_id=None,
        target=None,
    ):
        try:
            self.connect()

            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO adaptive_actions
                        (
                            session_id,
                            command_id,
                            risk_score,
                            risk_state,
                            action,
                            target
                        )
                    VALUES
                        (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        self.session_id,
                        command_id,
                        risk_score,
                        risk_state,
                        action,
                        target,
                    ),
                )

                action_id = cur.fetchone()[0]

            self.conn.commit()
            return action_id

        except Exception as exc:
            self._rollback()
            print(
                f"[DATABASE] add_adaptive_action failed: {exc}"
            )
            return None

    def add_decoy(
        self,
        virtual_path,
        decoy_type=None,
    ):
        try:
            self.connect()

            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO decoys
                        (
                            session_id,
                            virtual_path,
                            decoy_type
                        )
                    VALUES
                        (%s, %s, %s)
                    RETURNING id
                    """,
                    (
                        self.session_id,
                        virtual_path,
                        decoy_type,
                    ),
                )

                decoy_id = cur.fetchone()[0]

            self.conn.commit()
            return decoy_id

        except Exception as exc:
            self._rollback()
            print(f"[DATABASE] add_decoy failed: {exc}")
            return None

    def close(self):
        if self.conn is not None and not self.conn.closed:
            try:
                self.conn.close()
            except Exception:
                pass

    def _rollback(self):
        if self.conn is not None:
            try:
                self.conn.rollback()
            except Exception:
                pass
