from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import cast

from .analytics import iter_security_events
from .parser import RecordFormat


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="racf-smf",
        description="Fetch RACF and z/OS UNIX security SMF records from a binary SMF file.",
    )
    parser.add_argument("input", type=Path, help="Path to SMF binary data")
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

    if not args.input.exists():
        raise SystemExit(f"Input file not found: {args.input}")

    if args.max_records < 0:
        raise SystemExit("--max-records must be >= 0")

    subtypes = _parse_subtypes(args.zos_unix_subtypes)
    record_format = cast(RecordFormat, args.format)
    emitted = 0
    type_counter: Counter[int] = Counter()
    tag_counter: Counter[str] = Counter()

    out_handle = args.json_out.open("w", encoding="utf-8") if args.json_out else None
    try:
        for event in iter_security_events(
            args.input,
            record_format=record_format,
            strict_man=args.strict_man,
            include_all=args.all,
            zos_unix_subtypes=subtypes,
        ):
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

    print(f"Records emitted: {emitted}")
    if type_counter:
        summary = ", ".join(f"{record_type}:{count}" for record_type, count in sorted(type_counter.items()))
        print(f"By record type: {summary}")
    if tag_counter:
        summary = ", ".join(f"{tag}:{count}" for tag, count in sorted(tag_counter.items()))
        print(f"By tag: {summary}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
