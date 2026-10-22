import json
from pathlib import Path


# ============================================================
# FILE PATHS
# ============================================================

MANIFEST_FILE = Path(
    "data/generated/scenario_manifest.jsonl"
)

SESSIONS_FILE = Path(
    "data/processed/sessions/sessions.jsonl"
)

ANALYZED_FILE = Path(
    "data/processed/sessions/analyzed_sessions.jsonl"
)

OUTPUT_FILE = Path(
    "data/generated/missing_behavior_audit.jsonl"
)


# ============================================================
# JSONL LOADER
# ============================================================

def load_jsonl(path):
    """
    Load a JSONL file into a list of dictionaries.
    """

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    records = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1
        ):

            line = line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )

            except json.JSONDecodeError as exc:

                raise ValueError(
                    f"Invalid JSON in {path} "
                    f"at line {line_number}: {exc}"
                )

    return records


# ============================================================
# COMMAND EXTRACTION
# ============================================================

def get_commands(session):
    """
    Extract command strings from a collected Cowrie session.
    """

    commands = []

    for item in session.get(
        "commands",
        []
    ):

        if isinstance(item, str):

            commands.append(item)

        elif isinstance(item, dict):

            command = item.get(
                "command"
            )

            if command:

                commands.append(
                    command
                )

    return commands


# ============================================================
# FIND COWRIE SESSION USING UNIQUE MARKER
# ============================================================

def find_session_by_marker(
    marker,
    sessions
):
    """
    Find the Cowrie session containing the
    unique DATASET_RUN marker.
    """

    if not marker:
        return None

    for session in sessions:

        commands = get_commands(
            session
        )

        for command in commands:

            if marker in command:

                return session

    return None


# ============================================================
# OBSERVED BEHAVIOR EXTRACTION
# ============================================================

def get_observed_behaviors(
    analyzed_record
):
    """
    Extract behavior labels produced by
    behavior_analyzer.py.
    """

    behaviors = analyzed_record.get(
        "behaviors",
        []
    )

    if isinstance(
        behaviors,
        list
    ):

        return set(behaviors)

    if isinstance(
        behaviors,
        str
    ):

        return {behaviors}

    return set()


# ============================================================
# EXPECTED BEHAVIOR EXTRACTION
# ============================================================

def get_expected_behaviors(
    manifest_record
):
    """
    Extract expected behavior labels from
    scenario_manifest.jsonl.
    """

    behaviors = manifest_record.get(
        "expected_behaviors",
        []
    )

    if isinstance(
        behaviors,
        list
    ):

        return set(behaviors)

    if isinstance(
        behaviors,
        str
    ):

        return {behaviors}

    return set()


# ============================================================
# MAIN AUDIT
# ============================================================

def main():

    print("=" * 70)
    print("EXPECTED vs OBSERVED BEHAVIOR AUDIT")
    print("=" * 70)

    # --------------------------------------------------------
    # Load files
    # --------------------------------------------------------

    manifest = load_jsonl(
        MANIFEST_FILE
    )

    sessions = load_jsonl(
        SESSIONS_FILE
    )

    analyzed = load_jsonl(
        ANALYZED_FILE
    )

    print(
        f"Manifest records : {len(manifest)}"
    )

    print(
        f"Session records  : {len(sessions)}"
    )

    print(
        f"Analyzed records : {len(analyzed)}"
    )

    # --------------------------------------------------------
    # Build analyzed-session index
    # --------------------------------------------------------

    analyzed_index = {}

    for record in analyzed:

        session_id = record.get(
            "session_id"
        )

        if session_id:

            analyzed_index[
                session_id
            ] = record

    # --------------------------------------------------------
    # Counters
    # --------------------------------------------------------

    exact_matches = 0

    additional_behavior_only = 0

    expected_behavior_missing = 0

    cowrie_mapping_missing = 0

    analyzed_session_missing = 0

    # --------------------------------------------------------
    # Detailed result containers
    # --------------------------------------------------------

    missing_results = []

    additional_results = []

    exact_results = []

    # ========================================================
    # PROCESS EVERY MANIFEST RECORD
    # ========================================================

    for manifest_record in manifest:

        run_id = manifest_record.get(
            "run_id"
        )

        scenario = manifest_record.get(
            "scenario_label",
            "unknown"
        )

        marker = manifest_record.get(
            "marker"
        )

        expected = get_expected_behaviors(
            manifest_record
        )

        # ----------------------------------------------------
        # Find Cowrie session
        # ----------------------------------------------------

        session = find_session_by_marker(
            marker,
            sessions
        )

        if session is None:

            cowrie_mapping_missing += 1

            missing_results.append({

                "run_id": run_id,

                "session_id": None,

                "scenario": scenario,

                "type":
                    "cowrie_session_not_found",

                "expected":
                    sorted(expected),

                "observed": [],

                "missing":
                    sorted(expected),

                "extra": [],

                "commands": [],

            })

            continue

        # ----------------------------------------------------
        # Get Cowrie session ID
        # ----------------------------------------------------

        session_id = session.get(
            "session_id"
        )

        if not session_id:

            cowrie_mapping_missing += 1

            continue

        # ----------------------------------------------------
        # Find analyzed session
        # ----------------------------------------------------

        analyzed_record = analyzed_index.get(
            session_id
        )

        if analyzed_record is None:

            analyzed_session_missing += 1

            continue

        # ----------------------------------------------------
        # Get observed behaviors
        # ----------------------------------------------------

        observed = get_observed_behaviors(
            analyzed_record
        )

        # ----------------------------------------------------
        # BENIGN SPECIAL CASE
        #
        # Generator:
        #     ["benign"]
        #
        # Analyzer:
        #     []
        #
        # An empty behavior list means that
        # no malicious behavior was detected.
        # Therefore benign + [] is valid.
        # ----------------------------------------------------

        if (
            expected == {"benign"}
            and not observed
        ):

            exact_matches += 1

            exact_results.append({

                "run_id": run_id,

                "session_id": session_id,

                "scenario": scenario,

                "expected": [
                    "benign"
                ],

                "observed": [],

            })

            continue

        # ----------------------------------------------------
        # Calculate differences
        # ----------------------------------------------------

        missing = sorted(
            expected - observed
        )

        extra = sorted(
            observed - expected
        )

        commands = get_commands(
            session
        )

        # ====================================================
        # EXACT MATCH
        # ====================================================

        if not missing and not extra:

            exact_matches += 1

            exact_results.append({

                "run_id": run_id,

                "session_id": session_id,

                "scenario": scenario,

                "expected":
                    sorted(expected),

                "observed":
                    sorted(observed),

            })

        # ====================================================
        # EXPECTED BEHAVIOR MISSING
        # ====================================================

        elif missing:

            expected_behavior_missing += 1

            missing_results.append({

                "run_id": run_id,

                "session_id": session_id,

                "scenario": scenario,

                "type":
                    "expected_behavior_missing",

                "expected":
                    sorted(expected),

                "observed":
                    sorted(observed),

                "missing":
                    missing,

                "extra":
                    extra,

                "commands":
                    commands,

            })

        # ====================================================
        # ONLY ADDITIONAL BEHAVIORS
        # ====================================================

        else:

            additional_behavior_only += 1

            additional_results.append({

                "run_id": run_id,

                "session_id": session_id,

                "scenario": scenario,

                "type":
                    "additional_observed_behavior",

                "expected":
                    sorted(expected),

                "observed":
                    sorted(observed),

                "extra":
                    extra,

                "commands":
                    commands,

            })

    # ========================================================
    # SAVE DETAILED MISSING-BEHAVIOR AUDIT
    # ========================================================

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as f:

        for result in missing_results:

            f.write(
                json.dumps(
                    result,
                    ensure_ascii=False
                )
                + "\n"
            )

    # ========================================================
    # VALIDATION SUMMARY
    # ========================================================

    print()
    print("-" * 70)
    print("VALIDATION SUMMARY")
    print("-" * 70)

    print(
        f"Exact matches              : "
        f"{exact_matches}"
    )

    print(
        f"Additional behavior only   : "
        f"{additional_behavior_only}"
    )

    print(
        f"Expected behavior missing  : "
        f"{expected_behavior_missing}"
    )

    print(
        f"Cowrie mapping missing     : "
        f"{cowrie_mapping_missing}"
    )

    print(
        f"Analyzed session missing   : "
        f"{analyzed_session_missing}"
    )

    print()
    print(
        f"Detailed output: "
        f"{OUTPUT_FILE}"
    )

    # ========================================================
    # MISSING BEHAVIOR COUNTS
    # ========================================================

    if missing_results:

        missing_counts = {}

        for result in missing_results:

            for behavior in result.get(
                "missing",
                []
            ):

                missing_counts[
                    behavior
                ] = (
                    missing_counts.get(
                        behavior,
                        0
                    ) + 1
                )

        print()
        print("-" * 70)
        print("MISSING BEHAVIOR COUNTS")
        print("-" * 70)

        for behavior, count in sorted(
            missing_counts.items(),
            key=lambda item: (
                -item[1],
                item[0]
            )
        ):

            print(
                f"{behavior:<25} : "
                f"{count}"
            )

    # ========================================================
    # ADDITIONAL BEHAVIOR COUNTS
    # ========================================================

    if additional_results:

        additional_counts = {}

        for result in additional_results:

            for behavior in result.get(
                "extra",
                []
            ):

                additional_counts[
                    behavior
                ] = (
                    additional_counts.get(
                        behavior,
                        0
                    ) + 1
                )

        print()
        print("-" * 70)
        print("ADDITIONAL BEHAVIOR COUNTS")
        print("-" * 70)

        for behavior, count in sorted(
            additional_counts.items(),
            key=lambda item: (
                -item[1],
                item[0]
            )
        ):

            print(
                f"{behavior:<25} : "
                f"{count}"
            )

    # ========================================================
    # FIRST 20 REAL MISMATCHES
    # ========================================================

    if missing_results:

        print()
        print("-" * 70)
        print("FIRST 20 EXPECTED-BEHAVIOR MISMATCHES")
        print("-" * 70)

        shown = 0

        for result in missing_results:

            # Do not show benign special cases.
            if (
                result.get("expected")
                == ["benign"]
                and not result.get(
                    "observed"
                )
            ):
                continue

            print()

            print(
                f"Run ID  : "
                f"{result.get('run_id')}"
            )

            print(
                f"Session : "
                f"{result.get('session_id')}"
            )

            print(
                f"Scenario: "
                f"{result.get('scenario')}"
            )

            print(
                f"Expected: "
                f"{result.get('expected')}"
            )

            print(
                f"Observed: "
                f"{result.get('observed')}"
            )

            print(
                f"Missing : "
                f"{result.get('missing')}"
            )

            print(
                f"Extra   : "
                f"{result.get('extra')}"
            )

            print("Commands:")

            for command in result.get(
                "commands",
                []
            ):

                print(
                    f"  $ {command}"
                )

            shown += 1

            if shown >= 20:
                break

    # ========================================================
    # FINAL INTERPRETATION
    # ========================================================

    print()
    print("=" * 70)
    print("INTERPRETATION")
    print("=" * 70)

    total_validated = (
        exact_matches
        + additional_behavior_only
        + expected_behavior_missing
    )

    print(
        f"Sessions validated : "
        f"{total_validated}"
    )

    if cowrie_mapping_missing == 0:

        print(
            "Cowrie marker mapping: PASS"
        )

    else:

        print(
            "Cowrie marker mapping: "
            "WARNING"
        )

    if analyzed_session_missing == 0:

        print(
            "Analyzer coverage: PASS"
        )

    else:

        print(
            "Analyzer coverage: "
            "WARNING"
        )

    if expected_behavior_missing == 0:

        print(
            "Expected behavior coverage: PASS"
        )

    else:

        print(
            "Expected behavior coverage: "
            "WARNING"
        )

    print()
    print(
        "Benign sessions with no detected "
        "behavior are treated as valid."
    )

    print(
        "Additional observed behaviors are "
        "not automatically errors because "
        "one command can legitimately "
        "trigger multiple behavior categories."
    )

    print("=" * 70)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()