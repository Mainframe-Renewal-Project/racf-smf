from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import cast

from .analytics import discover_smf_datasets, iter_discovered_security_events, iter_security_events
from .parser import RecordFormat, iter_smf_records


def _parse_subtypes(raw: str) -> set[int]:
    values: set[int] = set()
    for part in raw.split(","):
        stripped = part.strip()
        if not stripped:
            continue
        values.add(int(stripped))
    if not values:
        raise ValueError("At least one subtype value is required")
    return values


def _is_dataset_source(value: str) -> bool:
    return value.startswith("mvs://") or (value.startswith("//'") and value.endswith("'"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="racf-smf",
        description="Fetch RACF and z/OS UNIX security SMF records from a binary SMF file.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Path to SMF binary data or plain z/OS dataset name when --dataset-input is set. Omit to auto-discover datasets via ZOAU.",
    )
    parser.add_argument(
        "--dataset-input",
        action="store_true",
        help="Treat input as a z/OS dataset name (for example SYS1.MAN01)",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Auto-discover SMF datasets using ZOAU and process all of them",
    )
    parser.add_argument(
        "--dataset-pattern",
        action="append",
        dest="dataset_patterns",
        metavar="PATTERN",
        help="Dataset name pattern for discovery (repeatable, default: SYS1.*.MAN* and SYS1.MAN*)",
    )
    parser.add_argument(
        "--list-datasets",
        action="store_true",
        help="Print discovered SMF datasets and exit (useful for diagnosing pattern issues)",
    )
    parser.add_argument(
        "--format",
        choices=("auto", "rdw", "smf", "man"),
        default="auto",
        help="Input framing format: MAN (BDW/VBS), RDW (VB), raw SMF, or auto-detect",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Include all SMF records instead of only security records",
    )
    parser.add_argument(
        "--zos-unix-subtypes",
        default="2,3,4",
        help="Comma-separated type 83 subtypes considered z/OS UNIX security records",
    )
    parser.add_argument(
        "--strict-man",
        action="store_true",
        help="Fail fast on malformed BDW/RDW segments when using MAN format",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=0,
        help="Stop after N emitted records (0 means no limit)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Optional output file for JSON lines (one record per line)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    use_discovery = args.discover or args.input is None

    if not use_discovery:
        if not args.dataset_input and not _is_dataset_source(args.input):
            input_path = Path(args.input)
            if not input_path.exists():
                raise SystemExit(f"Input file not found: {args.input}")

    if args.max_records < 0:
        raise SystemExit("--max-records must be >= 0")

    subtypes = _parse_subtypes(args.zos_unix_subtypes)
    record_format = cast(RecordFormat, args.format)
    emitted = 0
    scanned = 0
    type_counter: Counter[int] = Counter()
    tag_counter: Counter[str] = Counter()
    scanned_types: Counter[int] = Counter()

    if use_discovery:
        discovered = discover_smf_datasets(args.dataset_patterns or None, verbose=True)
        if not discovered:
            raise SystemExit(
                "No SMF datasets found. Try --list-datasets with --dataset-pattern to diagnose."
            )
        if args.list_datasets:
            print(f"\nFound {len(discovered)} dataset(s):")
            for ds in discovered:
                print(f"  {ds}")
            return 0
        print(f"Discovered {len(discovered)} dataset(s): {', '.join(discovered)}", flush=True)
    elif getattr(args, "list_datasets", False):
        raise SystemExit("--list-datasets requires discovery mode (omit input or use --discover).")

    def _scan_sources() -> list[str]:
        """Return the list of inputs that will be processed."""
        if use_discovery:
            return discovered  # type: ignore[return-value]
        return [args.input]

    def _events():
        if use_discovery:
            yield from iter_discovered_security_events(
                dataset_patterns=args.dataset_patterns or None,
                record_format=record_format,
                strict_man=args.strict_man,
                include_all=True,  # filter below so we can count scanned records
                zos_unix_subtypes=subtypes,
            )
        else:
            yield from iter_security_events(
                args.input,
                record_format=record_format,
                strict_man=args.strict_man,
                dataset_input=args.dataset_input,
                include_all=True,  # filter below so we can count scanned records
                zos_unix_subtypes=subtypes,
            )

    out_handle = args.json_out.open("w", encoding="utf-8") if args.json_out else None
    try:
        for event in _events():
            scanned += 1
            scanned_types[int(event["record_type"])] += 1

            # Apply security filter unless --all was requested.
            is_security = bool(event["tags"])
            if not args.all and not is_security:
                continue

            emitted += 1
            type_counter[int(event["record_type"])] += 1
            for tag in event["tags"]:
                tag_counter[tag] += 1

            line = json.dumps(event, separators=(",", ":"))
            if out_handle:
                out_handle.write(line + "\n")
            else:
                print(line)

            if args.max_records and emitted >= args.max_records:
                break
    finally:
        if out_handle:
            out_handle.close()

    print(f"Records scanned: {scanned}, emitted: {emitted}")
    if scanned and not emitted:
        top_types = ", ".join(
            f"type {t}:{n}" for t, n in scanned_types.most_common(5)
        )
        print(f"  No security records (type 80/83) found in scanned data.")
        print(f"  Top record types seen: {top_types}")
        print(f"  Tip: run with --all to emit all {scanned} records and inspect types.")
    if not scanned:
        print("  No records could be read. Check --format (try --format man or --format rdw).")
    if type_counter:
        summary = ", ".join(f"{record_type}:{count}" for record_type, count in sorted(type_counter.items()))
        print(f"By record type: {summary}")
    if tag_counter:
        summary = ", ".join(f"{tag}:{count}" for tag, count in sorted(tag_counter.items()))
        print(f"By tag: {summary}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
