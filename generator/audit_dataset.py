import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


MANIFEST_PATH = Path("data/generated/scenario_manifest.jsonl")
SESSIONS_PATH = Path("data/processed/sessions/sessions.jsonl")


def load_jsonl(path):
    records = []

    if not path.exists():
        print(f"ERROR: File not found: {path}")
        return records

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    return records


def get_commands(record):
    """
    Try to extract commands from different possible record formats.
    """

    commands = record.get("commands", [])

    if isinstance(commands, list):
        result = []

        for command in commands:
            if isinstance(command, str):
                result.append(command.strip())

            elif isinstance(command, dict):
                value = (
                    command.get("command")
                    or command.get("input")
                    or command.get("cmd")
                )

                if value:
                    result.append(str(value).strip())

        return [c for c in result if c]

    return []


def main():

    print("=" * 70)
    print("DATASET DIVERSITY AUDIT")
    print("=" * 70)

    manifest = load_jsonl(MANIFEST_PATH)
    sessions = load_jsonl(SESSIONS_PATH)

    print(f"\nManifest records : {len(manifest)}")
    print(f"Cowrie sessions  : {len(sessions)}")

    if not manifest:
        print("\nERROR: Manifest is empty.")
        return

    # ---------------------------------------------------------
    # 1. Scenario distribution
    # ---------------------------------------------------------

    scenario_counter = Counter()

    for record in manifest:
        scenario = (
            record.get("scenario_id")
            or record.get("scenario")
            or record.get("attack_type")
            or "unknown"
        )

        scenario_counter[scenario] += 1

    print("\n" + "-" * 70)
    print("1. SCENARIO DISTRIBUTION")
    print("-" * 70)

    for scenario, count in sorted(scenario_counter.items()):
        print(f"{scenario:30} {count}")

    # ---------------------------------------------------------
    # 2. Extract command sequences
    # ---------------------------------------------------------

    sequences = []
    all_commands = []

    for record in manifest:

        commands = get_commands(record)

        if not commands:
            # Some manifests may store generated commands differently
            generated = record.get("generated_commands")

            if isinstance(generated, list):
                commands = [str(x).strip() for x in generated if str(x).strip()]

        sequences.append(tuple(commands))
        all_commands.extend(commands)

    unique_sequences = set(sequences)

    print("\n" + "-" * 70)
    print("2. COMMAND SEQUENCE DIVERSITY")
    print("-" * 70)

    print(f"Total sessions              : {len(sequences)}")
    print(f"Unique command sequences    : {len(unique_sequences)}")

    if sequences:
        diversity_ratio = len(unique_sequences) / len(sequences)
        print(f"Sequence diversity ratio    : {diversity_ratio:.3f}")

    # ---------------------------------------------------------
    # 3. Unique commands
    # ---------------------------------------------------------

    command_counter = Counter(all_commands)

    print("\n" + "-" * 70)
    print("3. COMMAND DIVERSITY")
    print("-" * 70)

    print(f"Total command executions    : {len(all_commands)}")
    print(f"Unique commands             : {len(command_counter)}")

    print("\nMost common commands:")

    for command, count in command_counter.most_common(20):
        print(f"{count:4}  {command}")

    # ---------------------------------------------------------
    # 4. Commands per session
    # ---------------------------------------------------------

    lengths = [len(seq) for seq in sequences]

    print("\n" + "-" * 70)
    print("4. SESSION LENGTH")
    print("-" * 70)

    if lengths:
        print(f"Minimum commands/session    : {min(lengths)}")
        print(f"Maximum commands/session    : {max(lengths)}")
        print(f"Average commands/session    : {statistics.mean(lengths):.2f}")
        print(f"Median commands/session     : {statistics.median(lengths):.2f}")

        distribution = Counter(lengths)

        print("\nSession length distribution:")

        for length, count in sorted(distribution.items()):
            print(f"{length:3} commands : {count}")

    # ---------------------------------------------------------
    # 5. Exact duplicate sequences
    # ---------------------------------------------------------

    duplicate_groups = defaultdict(list)

    for index, sequence in enumerate(sequences):
        duplicate_groups[sequence].append(index)

    duplicates = {
        sequence: indexes
        for sequence, indexes in duplicate_groups.items()
        if len(indexes) > 1
    }

    print("\n" + "-" * 70)
    print("5. DUPLICATE SEQUENCES")
    print("-" * 70)

    print(f"Duplicate sequence groups   : {len(duplicates)}")

    duplicated_sessions = sum(len(v) for v in duplicates.values())

    print(f"Sessions in duplicate groups: {duplicated_sessions}")

    if duplicates:

        print("\nTop duplicate groups:")

        duplicate_list = sorted(
            duplicates.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )

        for sequence, indexes in duplicate_list[:10]:

            print(f"\nRepeated {len(indexes)} times:")

            for command in sequence:
                print(f"    {command}")

    # ---------------------------------------------------------
    # 6. Commands per scenario
    # ---------------------------------------------------------

    scenario_commands = defaultdict(set)

    for record in manifest:

        scenario = (
            record.get("scenario_id")
            or record.get("scenario")
            or record.get("attack_type")
            or "unknown"
        )

        commands = get_commands(record)

        if not commands:
            generated = record.get("generated_commands")

            if isinstance(generated, list):
                commands = [str(x).strip() for x in generated if str(x).strip()]

        scenario_commands[scenario].update(commands)

    print("\n" + "-" * 70)
    print("6. UNIQUE COMMANDS PER SCENARIO")
    print("-" * 70)

    for scenario in sorted(scenario_commands):

        commands = scenario_commands[scenario]

        print(
            f"{scenario:30} "
            f"{len(commands):3} unique commands"
        )

        for command in sorted(commands):
            print(f"    {command}")

    # ---------------------------------------------------------
    # 7. Scenario sequence diversity
    # ---------------------------------------------------------

    scenario_sequences = defaultdict(set)

    for record, sequence in zip(manifest, sequences):

        scenario = (
            record.get("scenario_id")
            or record.get("scenario")
            or record.get("attack_type")
            or "unknown"
        )

        scenario_sequences[scenario].add(sequence)

    print("\n" + "-" * 70)
    print("7. UNIQUE SEQUENCES PER SCENARIO")
    print("-" * 70)

    for scenario in sorted(scenario_sequences):

        count = len(scenario_sequences[scenario])

        print(
            f"{scenario:30} "
            f"{count:3} unique sequences"
        )

    # ---------------------------------------------------------
    # 8. Overall assessment
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("INITIAL DATASET ASSESSMENT")
    print("=" * 70)

    sequence_ratio = (
        len(unique_sequences) / len(sequences)
        if sequences else 0
    )

    unique_command_count = len(command_counter)

    if sequence_ratio >= 0.80 and unique_command_count >= 30:
        assessment = "GOOD DIVERSITY"

    elif sequence_ratio >= 0.50 and unique_command_count >= 20:
        assessment = "MODERATE DIVERSITY - IMPROVE BEFORE SCALING"

    else:
        assessment = "LOW DIVERSITY - REDESIGN GENERATOR BEFORE SCALING"

    print(f"\nAssessment: {assessment}")

    print("\nImportant:")
    print(
        "This assessment is only a preliminary diversity check. "
        "It does NOT prove that the dataset is realistic or ML-ready."
    )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()