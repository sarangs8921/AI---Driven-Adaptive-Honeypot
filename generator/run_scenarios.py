# generator/run_scenarios.py

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

DATASET_REPETITIONS = int(
    os.getenv(
        "DATASET_REPETITIONS",
        "",
    )
)

DATASET_SEED = int(
    os.getenv(
        "DATASET_SEED",
        "42",
    )
)

MANIFEST_DIR = Path(
    "data/generated"
)

MANIFEST_FILE = (
    MANIFEST_DIR
    / "scenario_manifest.jsonl"
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
    Generate commands using the existing scenario generator.

    Current build_scenario_commands() API:

        build_scenario_commands(
            scenario_id,
            rng
        )

    The dedicated RNG is passed directly to the scenario
    generator so different sessions can have controlled
    variation.
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
            "exactly two values: "
            "(commands, expected_behaviors)"
        )

    commands, expected_behaviors = result

    return (
        list(commands),
        expected_behaviors,
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
    Execute one generated scenario against Cowrie.

    A unique DATASET_RUN marker is included in the command
    sequence. The marker is later used by build_dataset.py
    to identify the correct Cowrie session.
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
        # Open interactive shell
        # ----------------------------------------------------

        channel = client.invoke_shell()

        time.sleep(1)

        # ----------------------------------------------------
        # Clear initial banner/prompt
        # ----------------------------------------------------

        if channel.recv_ready():

            try:

                channel.recv(8192)

            except Exception:

                pass

        executed_commands = []

        # ----------------------------------------------------
        # Execute commands
        # ----------------------------------------------------

        for index, command in enumerate(
            commands,
            start=1,
        ):

            print(
                f"[{index}/{len(commands)}] "
                f"{command}"
            )

            channel.send(
                command + "\n"
            )

            executed_commands.append(
                command
            )

            # Allow Cowrie to process command.
            time.sleep(0.5)

            # Drain output.
            while channel.recv_ready():

                try:

                    channel.recv(8192)

                except Exception:

                    break

        # ----------------------------------------------------
        # Allow Cowrie to flush events
        # ----------------------------------------------------

        time.sleep(1)

        try:

            channel.close()

        except Exception:

            pass

        print(
            "Scenario completed successfully."
        )

        return {
            "success": True,
            "source_port": source_port,
            "executed_commands":
                executed_commands,
            "error": None,
        }

    except Exception as exc:

        print()
        print(
            f"ERROR running scenario: {exc}"
        )

        return {
            "success": False,
            "source_port": source_port,
            "executed_commands": [],
            "error": str(exc),
        }

    finally:

        if client is not None:

            try:

                client.close()

            except Exception:

                pass


# ============================================================
# SAVE MANIFEST
# ============================================================

def save_manifest_record(
    record,
):
    """
    Append one record to the scenario manifest.
    """

    MANIFEST_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with MANIFEST_FILE.open(
        "a",
        encoding="utf-8",
    ) as file:

        file.write(
            json.dumps(
                record,
                ensure_ascii=False,
            )
            + "\n"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print(
        "COWRIE DATASET SCENARIO GENERATOR"
    )
    print("=" * 70)

    print(
        f"Cowrie host       : "
        f"{COWRIE_HOST}"
    )

    print(
        f"Cowrie port       : "
        f"{COWRIE_PORT}"
    )

    print(
        f"Dataset repetitions: "
        f"{DATASET_REPETITIONS}"
    )

    print(
        f"Dataset seed      : "
        f"{DATASET_SEED}"
    )

    print(
        f"Manifest          : "
        f"{MANIFEST_FILE}"
    )

    print("=" * 70)

    # --------------------------------------------------------
    # Master RNG
    # --------------------------------------------------------

    master_rng = random.Random(
        DATASET_SEED
    )

    total_runs = (
        DATASET_REPETITIONS
        * len(SCENARIO_NAMES)
    )

    print()
    print(
        f"Total scenarios to generate: "
        f"{total_runs}"
    )

    print()

    completed = 0
    failed = 0

    # ========================================================
    # REPETITIONS
    # ========================================================

    for repetition in range(
        DATASET_REPETITIONS
    ):

        print()
        print("#" * 70)

        print(
            f"REPETITION "
            f"{repetition + 1}/"
            f"{DATASET_REPETITIONS}"
        )

        print("#" * 70)

        # ----------------------------------------------------
        # Scenario loop
        # ----------------------------------------------------

        for scenario_name in SCENARIO_NAMES:

            completed += 1

            # ------------------------------------------------
            # Unique identifier
            # ------------------------------------------------

            run_id = str(
                uuid.uuid4()
            )

            # ------------------------------------------------
            # Unique deterministic seed
            # ------------------------------------------------

            random_seed = (
                master_rng.randint(
                    1,
                    2_147_483_647,
                )
            )

            # ------------------------------------------------
            # Create dedicated RNG
            # ------------------------------------------------

            scenario_rng = random.Random(
                random_seed
            )

            # ------------------------------------------------
            # Generate scenario
            # ------------------------------------------------

            try:

                (
                    commands,
                    expected_behaviors,
                ) = generate_scenario_commands(
                    scenario_name,
                    scenario_rng,
                )

            except Exception as exc:

                print()
                print(
                    "ERROR generating scenario:"
                )

                print(
                    str(exc)
                )

                failed += 1

                record = {
                    "run_id":
                        run_id,

                    "scenario_label":
                        scenario_name,

                    "expected_behaviors":
                        [],

                    "random_seed":
                        random_seed,

                    "repetition":
                        repetition + 1,

                    "marker":
                        None,

                    "commands":
                        [],

                    "source_port":
                        None,

                    "completed":
                        False,

                    "error":
                        str(exc),

                    "generated_at":
                        datetime.now(
                            timezone.utc
                        ).isoformat(),
                }

                save_manifest_record(
                    record
                )

                continue

            # ------------------------------------------------
            # Dataset marker
            # ------------------------------------------------

            marker = (
                f"echo DATASET_RUN_{run_id}"
            )

            commands.insert(
                0,
                marker,
            )

            # ------------------------------------------------
            # Display
            # ------------------------------------------------

            print()
            print("-" * 70)

            print(
                f"Generating "
                f"{completed}/{total_runs}: "
                f"{scenario_name}"
            )

            print(
                f"Run ID: {run_id}"
            )

            print(
                f"Seed  : {random_seed}"
            )

            print(
                f"Marker: {marker}"
            )

            print("-" * 70)

            # ------------------------------------------------
            # Execute
            # ------------------------------------------------

            result = run_scenario(
                scenario_name=
                    scenario_name,

                commands=
                    commands,

                run_id=
                    run_id,

                random_seed=
                    random_seed,
            )

            success = result.get(
                "success",
                False,
            )

            if not success:

                failed += 1

            # ------------------------------------------------
            # Manifest
            # ------------------------------------------------

            record = {
                "run_id":
                    run_id,

                "scenario_label":
                    scenario_name,

                "expected_behaviors":
                    expected_behaviors,

                "random_seed":
                    random_seed,

                "repetition":
                    repetition + 1,

                "marker":
                    marker,

                "commands":
                    commands,

                # Metadata only.
                # Do NOT use source_port for matching.
                "source_port":
                    result.get(
                        "source_port"
                    ),

                "completed":
                    success,

                "generated_at":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),
            }

            if not success:

                record["error"] = (
                    result.get(
                        "error",
                        "Unknown error",
                    )
                )

            save_manifest_record(
                record
            )

            # ------------------------------------------------
            # Small delay
            # ------------------------------------------------

            time.sleep(1)

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print(
        "DATASET GENERATION COMPLETE"
    )
    print("=" * 70)

    print(
        f"Total scenarios : "
        f"{total_runs}"
    )

    print(
        f"Completed       : "
        f"{total_runs - failed}"
    )

    print(
        f"Failed          : "
        f"{failed}"
    )

    print(
        f"Manifest        : "
        f"{MANIFEST_FILE}"
    )

    print("=" * 70)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()