# generator/run_independent_evaluation.py

import os
import time
import uuid
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from generator.scenarios import build_scenario_commands


# ============================================================
# CONFIGURATION
# ============================================================

COWRIE_HOST = os.getenv(
    "COWRIE_HOST",
    "127.0.0.1",
)

COWRIE_PORT = int(
    os.getenv(
        "COWRIE_PORT",
        "2222",
    )
)

COWRIE_USER = os.getenv(
    "COWRIE_USER",
    "root",
)

COWRIE_PASSWORD = os.getenv(
    "COWRIE_PASSWORD",
    "",
)

# Number of fresh evaluation sessions per class.
SESSIONS_PER_CLASS = int(
    os.getenv(
        "EVAL_SESSIONS_PER_CLASS",
        "20",
    )
)

# Deliberately different from the training seed.
EVAL_SEED = int(
    os.getenv(
        "EVAL_SEED",
        "20261001",
    )
)

OUTPUT_DIR = Path(
    "data/generated/independent_evaluation"
)

MANIFEST_FILE = (
    OUTPUT_DIR
    / "evaluation_manifest.jsonl"
)


# ============================================================
# SCENARIOS
# ============================================================

SCENARIO_NAMES = [
    "benign",
    "reconnaissance",
    "file_discovery",
    "credential_access",
    "execution",
    "privilege_activity",
    "persistence",
    "file_modification",
    "multi_stage",
]


# ============================================================
# COWRIE CONNECTION
# ============================================================

def connect_to_cowrie():
    """
    Connect to the running Cowrie SSH honeypot.
    """

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    client.connect(
        hostname=COWRIE_HOST,
        port=COWRIE_PORT,
        username=COWRIE_USER,
        password=COWRIE_PASSWORD,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
    )

    transport = client.get_transport()

    source_port = None

    if transport is not None:

        try:

            source_port = (
                transport.sock.getsockname()[1]
            )

        except Exception:

            source_port = None

    return client, source_port


# ============================================================
# BUILD SCENARIO
# ============================================================

def generate_scenario_commands(
    scenario_name,
    scenario_rng,
):
    """
    Use the existing scenario generator.

    Returns:

        commands
        expected_behaviors
    """

    result = build_scenario_commands(
        scenario_id=scenario_name,
        rng=scenario_rng,
    )

    if not isinstance(
        result,
        tuple,
    ):

        raise TypeError(
            "build_scenario_commands() must return "
            "(commands, expected_behaviors)"
        )

    if len(result) != 2:

        raise ValueError(
            "build_scenario_commands() must return "
            "exactly two values"
        )

    commands, expected_behaviors = result

    return (
        list(commands),
        list(expected_behaviors),
    )


# ============================================================
# RUN ONE SCENARIO
# ============================================================

def run_scenario(
    scenario_name,
    commands,
    run_id,
    random_seed,
):
    """
    Execute one independent evaluation scenario.

    The DATASET_EVAL marker allows the resulting Cowrie
    session to be identified independently from the
    training dataset.
    """

    print()
    print("=" * 70)
    print(
        f"SCENARIO : {scenario_name}"
    )
    print(
        f"RUN ID   : {run_id}"
    )
    print(
        f"SEED     : {random_seed}"
    )
    print("=" * 70)

    client = None
    source_port = None
    executed_commands = []

    try:

        # ----------------------------------------------------
        # Connect
        # ----------------------------------------------------

        client, source_port = (
            connect_to_cowrie()
        )

        print(
            f"Connected to Cowrie: "
            f"{COWRIE_HOST}:{COWRIE_PORT}"
        )

        # ----------------------------------------------------
        # Open shell
        # ----------------------------------------------------

        channel = client.invoke_shell()

        time.sleep(1)

        # ----------------------------------------------------
        # Clear banner/prompt
        # ----------------------------------------------------

        if channel.recv_ready():

            try:

                channel.recv(8192)

            except Exception:

                pass

        # ----------------------------------------------------
        # Execute commands
        # ----------------------------------------------------

        for command in commands:

            command = str(command).strip()

            if not command:

                continue

            print(
                f"  > {command}"
            )

            channel.send(
                command + "\n"
            )

            executed_commands.append(
                command
            )

            # Allow Cowrie to process the command.
            time.sleep(0.35)

            # Drain available output.
            if channel.recv_ready():

                try:

                    channel.recv(16384)

                except Exception:

                    pass

        # ----------------------------------------------------
        # Allow final Cowrie events to be written
        # ----------------------------------------------------

        time.sleep(1)

        try:

            channel.close()

        except Exception:

            pass

        try:

            client.close()

        except Exception:

            pass

        print(
            "Scenario completed successfully."
        )

        return {
            "completed": True,
            "source_port": source_port,
            "executed_commands": executed_commands,
            "error": None,
        }

    except Exception as exc:

        print(
            f"ERROR: {exc}"
        )

        try:

            if client is not None:

                client.close()

        except Exception:

            pass

        return {
            "completed": False,
            "source_port": source_port,
            "executed_commands": executed_commands,
            "error": str(exc),
        }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("INDEPENDENT COWRIE EVALUATION GENERATOR")
    print("=" * 70)

    print(
        f"Cowrie       : "
        f"{COWRIE_HOST}:{COWRIE_PORT}"
    )

    print(
        f"Classes      : "
        f"{len(SCENARIO_NAMES)}"
    )

    print(
        f"Sessions/class : "
        f"{SESSIONS_PER_CLASS}"
    )

    print(
        f"Total sessions : "
        f"{len(SCENARIO_NAMES) * SESSIONS_PER_CLASS}"
    )

    print(
        f"Evaluation seed: "
        f"{EVAL_SEED}"
    )

    print("=" * 70)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Start with a fresh evaluation manifest.
    # This file is separate from the training manifest.
    # --------------------------------------------------------

    if MANIFEST_FILE.exists():

        backup_name = (
            OUTPUT_DIR
            / (
                "evaluation_manifest_"
                + datetime.now(timezone.utc)
                .strftime("%Y%m%dT%H%M%SZ")
                + ".jsonl"
            )
        )

        MANIFEST_FILE.rename(
            backup_name
        )

        print(
            f"Existing evaluation manifest backed up to:"
        )

        print(
            f"  {backup_name}"
        )

    master_rng = random.Random(
        EVAL_SEED
    )

    total = (
        len(SCENARIO_NAMES)
        * SESSIONS_PER_CLASS
    )

    completed = 0
    failed = 0

    manifest_records = []

    # --------------------------------------------------------
    # Generate and execute sessions
    # --------------------------------------------------------

    for scenario_name in SCENARIO_NAMES:

        print()
        print(
            "#" * 70
        )

        print(
            f"GENERATING CLASS: "
            f"{scenario_name}"
        )

        print(
            "#" * 70
        )

        for repetition in range(
            SESSIONS_PER_CLASS
        ):

            run_id = str(
                uuid.uuid4()
            )

            random_seed = (
                master_rng.randint(
                    1,
                    2_147_483_647,
                )
            )

            scenario_rng = random.Random(
                random_seed
            )

            try:

                commands, expected_behaviors = (
                    generate_scenario_commands(
                        scenario_name,
                        scenario_rng,
                    )
                )

            except Exception as exc:

                print(
                    f"Scenario generation failed: "
                    f"{exc}"
                )

                failed += 1

                manifest_records.append(
                    {
                        "run_id": run_id,
                        "evaluation": True,
                        "scenario_label": scenario_name,
                        "expected_behaviors":
                            [],
                        "random_seed":
                            random_seed,
                        "repetition":
                            repetition,
                        "marker":
                            None,
                        "commands":
                            [],
                        "completed":
                            False,
                        "error":
                            f"generation: {exc}",
                        "generated_at":
                            datetime.now(
                                timezone.utc
                            ).isoformat(),
                    }
                )

                continue

            # ------------------------------------------------
            # Add a unique evaluation marker.
            # ------------------------------------------------

            marker = (
                "echo "
                f"DATASET_EVAL_{run_id}"
            )

            commands = [
                marker,
                *commands,
            ]

            # ------------------------------------------------
            # Execute through real Cowrie.
            # ------------------------------------------------

            result = run_scenario(
                scenario_name=scenario_name,
                commands=commands,
                run_id=run_id,
                random_seed=random_seed,
            )

            if result["completed"]:

                completed += 1

            else:

                failed += 1

            # ------------------------------------------------
            # Save manifest record.
            # ------------------------------------------------

            manifest_records.append(
                {
                    "run_id": run_id,
                    "evaluation": True,
                    "scenario_label":
                        scenario_name,
                    "expected_behaviors":
                        expected_behaviors,
                    "random_seed":
                        random_seed,
                    "repetition":
                        repetition,
                    "marker":
                        marker,
                    "commands":
                        commands,
                    "executed_commands":
                        result[
                            "executed_commands"
                        ],
                    "source_port":
                        result[
                            "source_port"
                        ],
                    "completed":
                        result[
                            "completed"
                        ],
                    "error":
                        result[
                            "error"
                        ],
                    "generated_at":
                        datetime.now(
                            timezone.utc
                        ).isoformat(),
                }
            )

            print()
            print(
                f"Progress: "
                f"{completed + failed}/{total}"
            )

            # Small gap between sessions.
            time.sleep(0.5)

    # --------------------------------------------------------
    # Write manifest
    # --------------------------------------------------------

    with MANIFEST_FILE.open(
        "w",
        encoding="utf-8",
    ) as handle:

        for record in manifest_records:

            handle.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("INDEPENDENT EVALUATION GENERATION COMPLETE")
    print("=" * 70)

    print(
        f"Expected sessions : {total}"
    )

    print(
        f"Completed          : {completed}"
    )

    print(
        f"Failed             : {failed}"
    )

    print(
        f"Manifest           : {MANIFEST_FILE}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()