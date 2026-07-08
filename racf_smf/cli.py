from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import cast

from .analytics import (
    _sear_import_status,
    discover_smf_datasets,
    iter_discovered_security_events,
    iter_security_events,
)
from .parser import RecordFormat


# ---------------------------------------------------------------------------
# Colour helpers — disabled when stdout is not a TTY or NO_COLOR is set.
# ---------------------------------------------------------------------------

def _use_color() -> bool:
    return sys.stderr.isatty() and os.environ.get("NO_COLOR", "") == ""


class _C:
    """ANSI colour codes, swapped to empty strings when colour is off."""

    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    CYAN   = "\033[36m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    RED    = "\033[31m"
    BLUE   = "\033[34m"


def _colored(text: str, *codes: str) -> str:
    if not _use_color():
        return text
    return "".join(codes) + text + _C.RESET


def _info(msg: str) -> None:
    print(_colored(msg, _C.CYAN), file=sys.stderr, flush=True)


def _ok(msg: str) -> None:
    print(_colored(msg, _C.GREEN), file=sys.stderr, flush=True)


def _warn(msg: str) -> None:
    print(_colored(msg, _C.YELLOW), file=sys.stderr, flush=True)


def _err(msg: str) -> None:
    print(_colored(msg, _C.RED), file=sys.stderr, flush=True)


def _bold(text: str) -> str:
    return _colored(text, _C.BOLD)


def _dim(text: str) -> str:
    return _colored(text, _C.DIM)


def _pad_plain(text: str, width: int) -> str:
    """Pad text to a fixed width based on plain string length."""
    return text + " " * max(0, width - len(text))


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
        help="Treat input as a z/OS dataset name (for example SMFDATA.MAN01)",
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
        help="Dataset name pattern for discovery (repeatable). Overrides auto-discovery from D SMF,O.",
    )
    parser.add_argument(
        "--list-datasets",
        action="store_true",
        help="Print discovered SMF datasets and exit (useful for diagnosing pattern issues)",
    )
    parser.add_argument(
        "--include-logstreams",
        action="store_true",
        help="Include D LOGGER-discovered logstream names in scan input instead of discovery summary only",
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
    parser.add_argument(
        "--dedup-events",
        action="store_true",
        help="Suppress duplicate emitted events by source, offset, and total length",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Do not emit JSON events; print discovery and record-count summaries only",
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
    if args.summary_only and args.json_out:
        raise SystemExit("--summary-only cannot be combined with --json-out")

    subtypes = _parse_subtypes(args.zos_unix_subtypes)
    record_format = cast(RecordFormat, args.format)
    emitted = 0
    scanned = 0
    type_counter: Counter[int] = Counter()
    tag_counter: Counter[str] = Counter()
    scanned_types: Counter[int] = Counter()

    if use_discovery:
        sources: dict[str, list[str]] = {}
        discovered = discover_smf_datasets(
            args.dataset_patterns or None,
            verbose=False,
            include_logstreams=args.include_logstreams,
            sources_out=sources,
        )

        # Print source summary to stderr.
        sear_ok, sear_err = _sear_import_status()
        print(_bold("Discovery sources:"), file=sys.stderr)

        preferred_order = [
            "D SMF,O + PARMLIB",
            "D SMF,D",
            "D PARMLIB (full concat)",
            "D IPLINFO",
            "D LOGGER",
            "zsystem.search_parmlib",
            "zsystem.list_parmlib",
            "pySEAR",
            "Sibling expansion",
        ]

        ordered_labels: list[str] = [label for label in preferred_order if label in sources]
        ordered_labels.extend(label for label in sources if label not in ordered_labels)

        rows: list[tuple[str, str, str, str]] = []
        for label in ordered_labels:
            names = sources.get(label, [])
            status_note = ""
            if label == "pySEAR":
                if sear_ok:
                    status_note = "installed"
                elif sear_err:
                    status_note = f"installed - import error: {sear_err[:80]}"
                else:
                    status_note = "not installed"

            if names:
                marker = _colored("✔", _C.GREEN)
                detail = _colored(f"{len(names)} dataset(s)", _C.GREEN)
            else:
                marker = _colored("✘", _C.DIM)
                detail = _dim("none")

            if status_note:
                if label == "pySEAR" and sear_err:
                    note = _colored(status_note, _C.YELLOW)
                else:
                    note = _dim(status_note)
            else:
                note = ""

            plain_result = f"{len(names)} dataset(s)" if names else "none"
            if status_note:
                plain_result += f" ({status_note})"

            rendered_result = detail if not note else f"{detail} ({note})"
            rows.append((marker, label, plain_result, rendered_result))

        status_header = "Status"
        source_header = "Source"
        result_header = "Result"
        status_width = max(len(status_header), 1)
        source_width = max(len(source_header), *(len(label) for _, label, _, _ in rows))
        result_width = max(len(result_header), *(len(plain_result) for _, _, plain_result, _ in rows))

        top = f"  ┌{'─' * (status_width + 2)}┬{'─' * (source_width + 2)}┬{'─' * (result_width + 2)}┐"
        mid = f"  ├{'─' * (status_width + 2)}┼{'─' * (source_width + 2)}┼{'─' * (result_width + 2)}┤"
        bot = f"  └{'─' * (status_width + 2)}┴{'─' * (source_width + 2)}┴{'─' * (result_width + 2)}┘"
        print(top, file=sys.stderr)
        print(
            f"  │ {_pad_plain(status_header, status_width)} │ {_pad_plain(source_header, source_width)} │ {_pad_plain(result_header, result_width)} │",
            file=sys.stderr,
        )
        print(mid, file=sys.stderr)
        for marker, label, plain_result, rendered_result in rows:
            print(
                f"  │ {_pad_plain(marker, status_width)} │ {_pad_plain(label, source_width)} │ {rendered_result}{' ' * max(0, result_width - len(plain_result))} │",
                file=sys.stderr,
            )
        print(bot, file=sys.stderr)

        if not discovered:
            _err("No SMF datasets found. Try --list-datasets with --dataset-pattern to diagnose.")
            raise SystemExit(1)
        if args.list_datasets:
            print(_bold(f"\nFound {len(discovered)} dataset(s):"), file=sys.stderr)
            for ds in discovered:
                print(f"  {_bold(ds)}", file=sys.stderr)
            return 0
        _ok(f"Discovered {_bold(str(len(discovered)))} dataset(s): {', '.join(discovered)}")
    elif getattr(args, "list_datasets", False):
        _err("--list-datasets requires discovery mode (omit input or use --discover).")
        raise SystemExit(1)

    def _scan_sources() -> list[str]:
        """Return the list of inputs that will be processed."""
        if use_discovery:
            return discovered  # type: ignore[return-value]
        return [args.input]

    def _events():
        if use_discovery:
            yield from iter_discovered_security_events(
                dataset_patterns=args.dataset_patterns or None,
                include_logstreams=args.include_logstreams,
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
    emitted_keys: set[tuple[str | None, int, int]] = set()
    try:
        for event in _events():
            scanned += 1
            scanned_types[int(event["record_type"])] += 1

            # Apply security filter unless --all was requested.
            is_security = bool(event["tags"])
            if not args.all and not is_security:
                continue

            if args.dedup_events:
                event_key = (
                    event.get("source"),
                    int(event["offset"]),
                    int(event["total_length"]),
                )
                if event_key in emitted_keys:
                    continue
                emitted_keys.add(event_key)

            emitted += 1
            type_counter[int(event["record_type"])] += 1
            for tag in event["tags"]:
                tag_counter[tag] += 1

            if not args.summary_only:
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

    print(f"Records scanned: {_bold(str(scanned))}, emitted: {_bold(str(emitted))}", file=sys.stderr)
    if scanned and not emitted:
        top_types = ", ".join(
            f"type {t}:{n}" for t, n in scanned_types.most_common(5)
        )
        _warn("  No security records (type 80/83) found in scanned data.")
        _warn(f"  Top record types seen: {top_types}")
        _warn(f"  Tip: run with --all to emit all {scanned} records and inspect types.")
    if not scanned:
        _err("  No records could be read. Check --format (try --format man or --format rdw).")
    if type_counter:
        summary = ", ".join(
            f"{_colored(str(rt), _C.CYAN)}:{_bold(str(n))}"
            for rt, n in sorted(type_counter.items())
        )
        print(f"By record type: {summary}", file=sys.stderr)
    if tag_counter:
        summary = ", ".join(
            f"{_colored(tag, _C.GREEN)}:{_bold(str(n))}"
            for tag, n in sorted(tag_counter.items())
        )
        print(f"By tag: {summary}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
