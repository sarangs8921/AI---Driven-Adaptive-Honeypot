from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from groq import Groq
from pydantic import BaseModel
from pwdlib import PasswordHash

from database.db import Database
from analyzer.threat_profiler import ThreatProfiler
from generator.ml_feature_extractor import extract_features


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="AI Adaptive Honeypot API",
    description=(
        "FastAPI backend for the AI-Powered Adaptive Honeypot "
        "with PostgreSQL, LightGBM, SHAP and adaptive risk analysis."
    ),
    version="1.0.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# DATABASE
# =========================================================

db = Database()


def get_db() -> Database:
    return db


# =========================================================
# THREAT PROFILER
# =========================================================

_threat_profiler: ThreatProfiler | None = None


def get_threat_profiler() -> ThreatProfiler:
    global _threat_profiler

    if _threat_profiler is None:
        _threat_profiler = ThreatProfiler()

    return _threat_profiler


# =========================================================
# ML FEATURE CONFIGURATION
# =========================================================

# These are the three features excluded from the final
# LightGBM training dataset.

EXCLUDED_ML_FEATURES = {
    "max_command_length",
    "successful_auth",
    "failed_attempts",
}


# =========================================================
# AUTHENTICATION
# =========================================================

password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer()

ADMIN_USERNAME = os.getenv(
    "ADMIN_USERNAME",
    "admin",
)

ADMIN_PASSWORD_HASH = os.getenv(
    "ADMIN_PASSWORD_HASH",
    "",
)

JWT_SECRET = os.getenv(
    "JWT_SECRET",
    "",
)

JWT_ALGORITHM = "HS256"


class LoginRequest(BaseModel):
    username: str
    password: str


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


def create_access_token(username: str) -> str:
    if not JWT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="JWT_SECRET is not configured.",
        )

    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def require_auth(
    credentials: HTTPAuthorizationCredentials = Depends(
        bearer_scheme
    ),
) -> str:
    """
    Validate the JWT token sent by the React frontend.
    """

    if not JWT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="JWT_SECRET is not configured.",
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )

        username = payload.get("sub")

        if username != ADMIN_USERNAME:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication.",
            )

        return username

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token expired.",
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token.",
        )


# =========================================================
# LOGIN
# =========================================================

@app.post("/auth/login")
def login(request: LoginRequest):
    if not ADMIN_PASSWORD_HASH:
        raise HTTPException(
            status_code=500,
            detail="ADMIN_PASSWORD_HASH is not configured.",
        )

    if request.username != ADMIN_USERNAME:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    try:
        valid = password_hash.verify(
            request.password,
            ADMIN_PASSWORD_HASH,
        )
    except Exception:
        valid = False

    if not valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    return {
        "access_token": create_access_token(
            request.username
        ),
        "token_type": "bearer",
    }


@app.get("/auth/me")
def auth_me(
    username: str = Depends(require_auth),
):
    return {
        "username": username,
        "authenticated": True,
    }


# =========================================================
# GROQ SECURITY ASSISTANT
# =========================================================

GROQ_API_KEY = os.getenv(
    "GROQ_API_KEY",
    "",
)

GROQ_MODEL = os.getenv(
    "GROQ_MODEL",
    "openai/gpt-oss-120b",
)


def get_groq_client() -> Groq:
    if not GROQ_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY is not configured.",
        )

    return Groq(
        api_key=GROQ_API_KEY
    )


# =========================================================
# DECOY CONTENT
# =========================================================

DECOY_CONTENT = {
    "file_discovery_decoy": (
        "# SYSTEM BACKUP INDEX\n"
        "# SAFE HONEYPOT DECEPTION DATA\n\n"
        "backup_date=2026-10-01\n"
        "backup_server=internal-backup-01\n"
        "backup_status=completed\n"
        "archive=/var/backups/application.tar.gz\n"
        "database_backup=/var/backups/db_latest.sql\n"
    ),

    "credential_deception": (
        "# REDACTED CREDENTIAL BACKUP\n"
        "# HONEYPOT DECEPTION FILE\n\n"
        "root_password=[REDACTED]\n"
        "database_password=[REDACTED]\n"
        "api_token=[REDACTED]\n"
        "ssh_key=[REDACTED]\n"
    ),

    "system_discovery_decoy": (
        "HOSTNAME=prod-web-01\n"
        "OPERATING_SYSTEM=Ubuntu 22.04 LTS\n"
        "KERNEL=5.15.0-honeypot\n"
        "ARCHITECTURE=x86_64\n"
        "ENVIRONMENT=production\n"
        "ROLE=web-server\n"
    ),
}


# =========================================================
# DECOY ENDPOINT
# =========================================================

@app.get("/decoys/{decoy_id}")
def get_decoy_content(
    decoy_id: int,
    username: str = Depends(require_auth),
):
    connection = None

    try:
        connection = get_db().connect()

        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    session_id,
                    virtual_path,
                    decoy_type,
                    created_at
                FROM decoys
                WHERE id = %s
                """,
                (decoy_id,),
            )

            decoy = cursor.fetchone()

            if decoy is None:
                raise HTTPException(
                    status_code=404,
                    detail="Decoy not found.",
                )

            content = DECOY_CONTENT.get(
                decoy.get("decoy_type"),
                "# Safe honeypot decoy\n"
                "No stored content available.",
            )

            return {
                **decoy,
                "content": content,
            }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load decoy: {exc}",
        )

    finally:
        if connection is not None:
            connection.close()


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():
    return {
        "name": "AI Adaptive Honeypot API",
        "version": "1.0.0",
        "status": "online",
        "services": {
            "fastapi": "online",
            "postgresql": "connected",
            "lightgbm": "available",
            "shap": "available",
            "groq": "available",
        },
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health_check():
    connection = None

    try:
        connection = get_db().connect()

        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()

        return {
            "status": "healthy",
            "database": "connected",
            "database_test": result is not None,
        }

    except Exception as exc:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(exc),
        }

    finally:
        if connection is not None:
            connection.close()


# =========================================================
# DASHBOARD SUMMARY
# =========================================================

@app.get("/dashboard/summary")
def dashboard_summary(
    username: str = Depends(require_auth),
):
    connection = None

    try:
        connection = get_db().connect()

        with connection.cursor() as cursor:

            # -------------------------------------------------
            # TOTAL SESSIONS
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM sessions
                """
            )

            session_row = cursor.fetchone()

            total_sessions = int(
                session_row["total"]
            )

            # -------------------------------------------------
            # LATEST RISK PER SESSION
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT
                    LOWER(risk_state) AS risk_state,
                    COUNT(*) AS count
                FROM (
                    SELECT DISTINCT ON (session_id)
                        session_id,
                        risk_score,
                        risk_state,
                        id
                    FROM risk_assessments
                    ORDER BY session_id, id DESC
                ) latest_risk
                GROUP BY LOWER(risk_state)
                """
            )

            risk_rows = cursor.fetchall()

            risk = {
                "high": 0,
                "critical": 0,
                "medium": 0,
                "low": 0,
            }

            for row in risk_rows:
                state = row["risk_state"]

                if state in risk:
                    risk[state] = int(
                        row["count"]
                    )

            # -------------------------------------------------
            # COMMAND COUNT
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM commands
                """
            )

            command_count = int(
                cursor.fetchone()["count"]
            )

            # -------------------------------------------------
            # BEHAVIOR COUNT
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM behaviors
                """
            )

            behavior_count = int(
                cursor.fetchone()["count"]
            )

            # -------------------------------------------------
            # ADAPTIVE ACTION COUNT
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM adaptive_actions
                """
            )

            adaptive_action_count = int(
                cursor.fetchone()["count"]
            )

            # -------------------------------------------------
            # DECOY COUNT
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM decoys
                """
            )

            decoy_count = int(
                cursor.fetchone()["count"]
            )

            return {
                "sessions": {
                    "total": total_sessions,
                },
                "risk": risk,
                "activity": {
                    "commands": command_count,
                    "behaviors": behavior_count,
                    "adaptive_actions": adaptive_action_count,
                    "decoys": decoy_count,
                },
            }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load dashboard summary: "
                f"{exc}"
            ),
        )

    finally:
        if connection is not None:
            connection.close()


# =========================================================
# GET SESSIONS
# =========================================================

@app.get("/sessions")
def get_sessions(
    limit: int = 50,
    username: str = Depends(require_auth),
):
    limit = max(
        1,
        min(limit, 200),
    )

    connection = None

    try:
        connection = get_db().connect()

        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    s.session_id,
                    s.protocol,
                    s.source_ip,
                    s.source_port,
                    s.destination_ip,
                    s.destination_port,
                    s.username,
                    s.start_time,
                    s.end_time,
                    s.duration_ms,
                    s.successful_auth,
                    s.failed_attempts,
                    s.event_count,
                    s.empty_command_count,
                    s.created_at,

                    COUNT(DISTINCT c.id) AS command_count,
                    COUNT(DISTINCT b.id) AS behavior_count,
                    COUNT(DISTINCT a.id) AS adaptive_action_count,
                    COUNT(DISTINCT d.id) AS decoy_count,

                    COALESCE(
                        (
                            SELECT ra.risk_score
                            FROM risk_assessments ra
                            WHERE ra.session_id = s.session_id
                            ORDER BY ra.id DESC
                            LIMIT 1
                        ),
                        0
                    ) AS risk_score,

                    COALESCE(
                        (
                            SELECT ra.risk_state
                            FROM risk_assessments ra
                            WHERE ra.session_id = s.session_id
                            ORDER BY ra.id DESC
                            LIMIT 1
                        ),
                        'LOW'
                    ) AS risk_state

                FROM sessions s

                LEFT JOIN commands c
                    ON c.session_id = s.session_id

                LEFT JOIN behaviors b
                    ON b.session_id = s.session_id

                LEFT JOIN adaptive_actions a
                    ON a.session_id = s.session_id

                LEFT JOIN decoys d
                    ON d.session_id = s.session_id

                GROUP BY
                    s.session_id,
                    s.protocol,
                    s.source_ip,
                    s.source_port,
                    s.destination_ip,
                    s.destination_port,
                    s.username,
                    s.start_time,
                    s.end_time,
                    s.duration_ms,
                    s.successful_auth,
                    s.failed_attempts,
                    s.event_count,
                    s.empty_command_count,
                    s.created_at

                ORDER BY s.created_at DESC

                LIMIT %s
                """,
                (limit,),
            )

            rows = cursor.fetchall()

            return {
                "count": len(rows),
                "sessions": rows,
            }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load sessions: "
                f"{exc}"
            ),
        )

    finally:
        if connection is not None:
            connection.close()


# =========================================================
# GET SINGLE SESSION
# =========================================================

@app.get("/sessions/{session_id}")
def get_session(
    session_id: str,
    username: str = Depends(require_auth),
):
    connection = None

    try:
        connection = get_db().connect()

        with connection.cursor() as cursor:

            # -------------------------------------------------
            # SESSION
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT *
                FROM sessions
                WHERE session_id = %s
                """,
                (session_id,),
            )

            session = cursor.fetchone()

            if session is None:
                raise HTTPException(
                    status_code=404,
                    detail="Session not found.",
                )

            # -------------------------------------------------
            # COMMANDS
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT
                    id,
                    session_id,
                    command,
                    timestamp
                FROM commands
                WHERE session_id = %s
                ORDER BY
                    timestamp ASC NULLS LAST,
                    id ASC
                """,
                (session_id,),
            )

            commands = cursor.fetchall()

            # -------------------------------------------------
            # BEHAVIORS
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT
                    id,
                    session_id,
                    command_id,
                    behavior,
                    technique_id
                FROM behaviors
                WHERE session_id = %s
                ORDER BY id ASC
                """,
                (session_id,),
            )

            behaviors = cursor.fetchall()

            # -------------------------------------------------
            # RISK ASSESSMENTS
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT
                    id,
                    session_id,
                    risk_score,
                    risk_state
                FROM risk_assessments
                WHERE session_id = %s
                ORDER BY id ASC
                """,
                (session_id,),
            )

            risk_assessments = cursor.fetchall()

            # -------------------------------------------------
            # ADAPTIVE ACTIONS
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT
                    id,
                    session_id,
                    command_id,
                    risk_score,
                    risk_state,
                    action,
                    target,
                    created_at
                FROM adaptive_actions
                WHERE session_id = %s
                ORDER BY id ASC
                """,
                (session_id,),
            )

            adaptive_actions = cursor.fetchall()

            # -------------------------------------------------
            # DECOYS
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT
                    id,
                    session_id,
                    virtual_path,
                    decoy_type,
                    created_at
                FROM decoys
                WHERE session_id = %s
                ORDER BY id ASC
                """,
                (session_id,),
            )

            decoys = cursor.fetchall()

            return {
                "session": session,
                "commands": commands,
                "behaviors": behaviors,
                "risk_assessments": risk_assessments,
                "adaptive_actions": adaptive_actions,
                "decoys": decoys,
            }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load session: "
                f"{exc}"
            ),
        )

    finally:
        if connection is not None:
            connection.close()


# =========================================================
# BUILD ML SESSION
# =========================================================

def build_ml_session(
    session: dict[str, Any],
    commands: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Convert PostgreSQL session information into the same
    structure expected by the production ML feature extractor.
    """

    ml_session = dict(session)

    ml_session["commands"] = []

    for command in commands:
        ml_session["commands"].append(
            {
                "command": command.get(
                    "command",
                    "",
                ),
                "timestamp": command.get(
                    "timestamp"
                ),
            }
        )

    if ml_session.get("event_count") is None:
        ml_session["event_count"] = len(commands)

    if ml_session.get("duration_ms") is None:
        ml_session["duration_ms"] = 0

    return ml_session


# =========================================================
# THREAT PROFILE
# =========================================================

@app.get(
    "/sessions/{session_id}/threat-profile"
)
def get_threat_profile(
    session_id: str,
    username: str = Depends(require_auth),
):
    """
    Complete live threat profiling pipeline:

        PostgreSQL
             ↓
        Feature extraction
             ↓
          LightGBM
             ↓
           SHAP
             ↓
      Behavior evidence
             ↓
       Risk engine
             ↓
       Threat profile
    """

    connection = None

    try:
        connection = get_db().connect()

        with connection.cursor() as cursor:

            # -------------------------------------------------
            # SESSION
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT *
                FROM sessions
                WHERE session_id = %s
                """,
                (session_id,),
            )

            session = cursor.fetchone()

            if session is None:
                raise HTTPException(
                    status_code=404,
                    detail="Session not found.",
                )

            # -------------------------------------------------
            # COMMANDS
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT
                    id,
                    session_id,
                    command,
                    timestamp
                FROM commands
                WHERE session_id = %s
                ORDER BY
                    timestamp ASC NULLS LAST,
                    id ASC
                """,
                (session_id,),
            )

            commands = cursor.fetchall()

            # -------------------------------------------------
            # BEHAVIOR COUNTS
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT
                    behavior,
                    COUNT(*) AS count
                FROM behaviors
                WHERE session_id = %s
                GROUP BY behavior
                ORDER BY behavior
                """,
                (session_id,),
            )

            behavior_rows = cursor.fetchall()

            behavior_counts = {
                row["behavior"]: int(row["count"])
                for row in behavior_rows
            }

            observed_behaviors = list(
                behavior_counts.keys()
            )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load threat-profile "
                f"input data: {exc}"
            ),
        )

    finally:
        if connection is not None:
            connection.close()

    # ---------------------------------------------------------
    # BUILD ML INPUT
    # ---------------------------------------------------------

    ml_session = build_ml_session(
        session=session,
        commands=commands,
    )

    try:
        all_features = extract_features(
            ml_session
        )

        ml_features = {
            key: value
            for key, value in all_features.items()
            if key not in EXCLUDED_ML_FEATURES
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to extract ML features: "
                f"{exc}"
            ),
        )

    # ---------------------------------------------------------
    # AUTHENTICATION INFORMATION
    # ---------------------------------------------------------

    authentication = {
        "successful_auth": session.get(
            "successful_auth"
        ),
        "failed_attempts": (
            session.get("failed_attempts") or 0
        ),
    }

    # ---------------------------------------------------------
    # LIGHTGBM + SHAP + RISK
    # ---------------------------------------------------------

    try:
        profiler = get_threat_profiler()

        profile = profiler.profile_session(
            session_id=session_id,
            features=ml_features,
            observed_behaviors=observed_behaviors,
            behavior_counts=behavior_counts,
            authentication=authentication,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Threat profiling failed: "
                f"{exc}"
            ),
        )

    return {
        **profile,

        "feature_count": len(
            ml_features
        ),

        "features": ml_features,

        "session": {
            "protocol": session.get(
                "protocol"
            ),
            "source_ip": session.get(
                "source_ip"
            ),
            "source_port": session.get(
                "source_port"
            ),
            "destination_ip": session.get(
                "destination_ip"
            ),
            "destination_port": session.get(
                "destination_port"
            ),
            "username": session.get(
                "username"
            ),
            "successful_auth": session.get(
                "successful_auth"
            ),
            "failed_attempts": session.get(
                "failed_attempts"
            ),
        },
    }


# =========================================================
# LATEST THREAT PROFILE
# =========================================================

@app.get(
    "/dashboard/latest-threat"
)
def get_latest_threat(
    username: str = Depends(require_auth),
):
    """
    Find the newest session and generate
    its complete threat profile.
    """

    connection = None

    try:
        connection = get_db().connect()

        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT session_id
                FROM sessions
                ORDER BY created_at DESC
                LIMIT 1
                """
            )

            row = cursor.fetchone()

            if row is None:
                return {
                    "available": False,
                    "message": "No sessions available.",
                }

            session_id = row["session_id"]

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to find latest session: "
                f"{exc}"
            ),
        )

    finally:
        if connection is not None:
            connection.close()

    profile = get_threat_profile(
        session_id,
        username,
    )

    return {
        "available": True,
        "profile": profile,
    }


# =========================================================
# SECURITY CHATBOT
# =========================================================

@app.post("/chat")
def chat(
    request: ChatRequest,
    username: str = Depends(require_auth),
):
    """
    Security chatbot.

    Database behavior:

    1. If session_id is provided:
       use that session.

    2. If session_id is not provided:
       automatically select the latest session.

    Therefore questions such as:

        "How risky is the latest session?"

    work even when no session is selected
    in the dashboard.
    """

    if not GROQ_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY is not configured.",
        )

    if not request.message.strip():
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty.",
        )

    connection = None

    try:
        connection = get_db().connect()

        with connection.cursor() as cursor:

            # =================================================
            # 1. DETERMINE SESSION
            # =================================================

            if request.session_id:

                session_id = request.session_id

            else:

                cursor.execute(
                    """
                    SELECT session_id
                    FROM sessions
                    ORDER BY created_at DESC
                    LIMIT 1
                    """
                )

                latest = cursor.fetchone()

                if latest is None:
                    session_id = None
                else:
                    session_id = latest["session_id"]

            # =================================================
            # 2. COLLECT DATABASE CONTEXT
            # =================================================

            session_context: dict[str, Any] = {}

            if session_id:

                # -------------------------------------------------
                # SESSION
                # -------------------------------------------------

                cursor.execute(
                    """
                    SELECT
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
                        empty_command_count,
                        created_at
                    FROM sessions
                    WHERE session_id = %s
                    """,
                    (session_id,),
                )

                session_row = cursor.fetchone()

                if session_row:
                    session_context["session"] = dict(
                        session_row
                    )

                # -------------------------------------------------
                # COMMANDS
                # -------------------------------------------------

                cursor.execute(
                    """
                    SELECT
                        id,
                        command,
                        timestamp
                    FROM commands
                    WHERE session_id = %s
                    ORDER BY id ASC
                    """,
                    (session_id,),
                )

                session_context["commands"] = [
                    dict(row)
                    for row in cursor.fetchall()
                ]

                # -------------------------------------------------
                # BEHAVIORS
                # -------------------------------------------------

                cursor.execute(
                    """
                    SELECT
                        id,
                        behavior,
                        technique_id,
                        command_id
                    FROM behaviors
                    WHERE session_id = %s
                    ORDER BY id ASC
                    """,
                    (session_id,),
                )

                session_context["behaviors"] = [
                    dict(row)
                    for row in cursor.fetchall()
                ]

                # -------------------------------------------------
                # LATEST RISK
                # -------------------------------------------------

                cursor.execute(
                    """
                    SELECT
                        risk_score,
                        risk_state
                    FROM risk_assessments
                    WHERE session_id = %s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (session_id,),
                )

                risk_row = cursor.fetchone()

                session_context["risk"] = (
                    dict(risk_row)
                    if risk_row
                    else None
                )

                # -------------------------------------------------
                # ADAPTIVE ACTIONS
                # -------------------------------------------------

                cursor.execute(
                    """
                    SELECT
                        id,
                        action,
                        target,
                        risk_score,
                        risk_state,
                        created_at
                    FROM adaptive_actions
                    WHERE session_id = %s
                    ORDER BY id ASC
                    """,
                    (session_id,),
                )

                session_context["adaptive_actions"] = [
                    dict(row)
                    for row in cursor.fetchall()
                ]

                # -------------------------------------------------
                # DECOYS
                # -------------------------------------------------

                cursor.execute(
                    """
                    SELECT
                        id,
                        virtual_path,
                        decoy_type,
                        created_at
                    FROM decoys
                    WHERE session_id = %s
                    ORDER BY id ASC
                    """,
                    (session_id,),
                )

                session_context["decoys"] = [
                    dict(row)
                    for row in cursor.fetchall()
                ]

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to retrieve database context: "
                f"{exc}"
            ),
        )

    finally:
        if connection is not None:
            connection.close()

    # =========================================================
    # 3. BUILD SECURITY PROMPT
    # =========================================================

    system_prompt = """
You are the Security Assistant for an
AI-Powered Adaptive Honeypot.

You assist a cybersecurity analyst monitoring
SSH honeypot activity.

You have access to structured PostgreSQL telemetry
provided in the SESSION CONTEXT section.

Use that database context when answering questions
about:

- sessions
- attacks
- commands
- behaviors
- risk
- severity
- adaptive responses
- decoys
- threat activity

IMPORTANT RULES:

1. Never invent database information.

2. If information is not available in the supplied
   database context, explicitly say so.

3. Clearly distinguish observed behavior from
   machine-learning predictions.

4. When discussing risk, mention the actual risk
   score and risk state when available.

5. When discussing an attack, mention relevant
   observed commands and behaviors.

6. If the analyst asks about the latest session,
   use the supplied latest session context.

7. If there is no session context, explain that
   no session data is currently available.

8. Keep answers concise but technically useful.

9. This is a defensive cybersecurity monitoring
   system.

10. Do not provide instructions for attacking
    real systems.

11. Do not claim that a command was observed unless
    it appears in the supplied database context.

12. Do not treat the risk state as the ML class.
    They are separate parts of the system.
"""

    context_text = json.dumps(
        session_context,
        default=str,
        indent=2,
    )

    user_prompt = f"""
SESSION CONTEXT FROM POSTGRESQL:

{context_text}

ANALYST QUESTION:

{request.message}
"""

    # =========================================================
    # 4. CALL GROQ
    # =========================================================

    try:

        client = get_groq_client()

        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            temperature=0.2,
            max_tokens=1200,
        )

        answer = completion.choices[0].message.content

        return {
            "answer": answer,
            "session_id": session_id,
            "database_context": bool(
                session_id
            ),
            "model": GROQ_MODEL,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Groq request failed: "
                f"{exc}"
            ),
        )