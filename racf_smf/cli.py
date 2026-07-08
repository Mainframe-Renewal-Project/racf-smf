from __future__ import annotations

import argparse
import json
import os
import re
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


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _visible_len(text: str) -> int:
    """Length of text as rendered in a terminal, ignoring ANSI color escapes."""
    return len(_ANSI_RE.sub("", text))


def _pad_plain(text: str, width: int) -> str:
    """Pad text to a fixed width based on visible string length."""
    return text + " " * max(0, width - _visible_len(text))


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
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Read, discover, and summarize RACF and z/OS UNIX security SMF records.\n\n"
            "The input can be a local binary file, a z/OS MAN dataset, or an auto-discovered\n"
            "set of SMF datasets found through operator commands, PARMLIB inspection, ZOAU,\n"
            "and optional pySEAR lookups."
        ),
        epilog=(
            "Examples:\n"
            "  racf-smf /tmp/smf.bin --format rdw\n"
            "      Read a local VB/RDW-wrapped SMF extract.\n\n"
            "  racf-smf USER.SMF.MAN1 --dataset-input --format man\n"
            "      Read a MAN dataset by name.\n\n"
            "  racf-smf --discover --summary-only\n"
            "      Auto-discover datasets, scan them, and print only summaries.\n\n"
            "  racf-smf --discover --dedup-events --json-out events.jsonl\n"
            "      Auto-discover datasets and write deduplicated JSON lines to a file."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        help=(
            "Input source to read. Use a local file path for exported SMF data, or a plain z/OS "
            "dataset name when --dataset-input is set. Omit this argument to enable automatic "
            "discovery via ZOAU/operator-command sources."
        ),
    )
    parser.add_argument(
        "--dataset-input",
        action="store_true",
        help=(
            "Treat the positional input as a z/OS dataset name instead of a local file path. "
            "Use this for names such as USER.SMF.MAN1 or SITE.SMF.DATA.MANX."
        ),
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help=(
            "Auto-discover SMF datasets and scan all discovered inputs. Discovery uses operator "
            "commands, PARMLIB inspection, zsystem helpers, optional pySEAR queries, and catalog "
            "fallback patterns."
        ),
    )
    parser.add_argument(
        "--dataset-pattern",
        action="append",
        dest="dataset_patterns",
        metavar="PATTERN",
        help=(
            "Dataset name pattern to use during discovery, for example USER.*.MAN* or SITE.SMF.DATA.*. "
            "This option is repeatable. Supplying one or more patterns bypasses live-source discovery "
            "and uses the provided catalog search patterns instead."
        ),
    )
    parser.add_argument(
        "--list-datasets",
        action="store_true",
        help=(
            "Print the discovered inputs and exit without parsing records. Useful for diagnosing "
            "discovery behavior or verifying that custom dataset patterns match the expected names."
        ),
    )
    parser.add_argument(
        "--include-logstreams",
        action="store_true",
        help=(
            "Include D LOGGER-discovered logstream names in the scan input instead of only showing them "
            "in the discovery summary. Leave this off unless your site exposes SMF logstreams in a way "
            "that the current reader can consume successfully."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("auto", "rdw", "smf", "man"),
        default="auto",
        help=(
            "Record framing format. 'auto' tries to detect the layout. 'rdw' expects classic VB/RDW-"
            "wrapped records. 'smf' expects raw SMF records with no RDW/BDW framing. 'man' expects a "
            "MAN dataset style stream with BDW/VBS segmentation."
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Emit every parsed SMF record instead of only security-related records. This is useful when "
            "checking whether parsing works but the security filter finds nothing."
        ),
    )
    parser.add_argument(
        "--zos-unix-subtypes",
        default="2,3,4",
        help=(
            "Comma-separated SMF type 83 subtypes to treat as z/OS UNIX security records. The default "
            "is 2,3,4, which covers the common UNIX security event subtypes."
        ),
    )
    parser.add_argument(
        "--strict-man",
        action="store_true",
        help=(
            "Fail immediately when malformed BDW/RDW segments are encountered while parsing MAN-format "
            "data. Without this flag, the parser is more tolerant of damaged or irregular input."
        ),
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=0,
        help=(
            "Stop after emitting N records. The limit applies to emitted output after filtering and "
            "optional deduplication. Use 0 for no limit."
        ),
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help=(
            "Write JSON Lines output to a file instead of stdout. Each emitted event is written as one "
            "compact JSON object per line."
        ),
    )
    parser.add_argument(
        "--dedup-events",
        action="store_true",
        help=(
            "Suppress duplicate emitted events using the tuple (source, offset, total_length). This is "
            "useful when multiple discovery paths or overlapping inputs expose the same SMF record."
        ),
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help=(
            "Do not emit per-record JSON. Only print discovery output and end-of-run counts such as "
            "records scanned, records emitted, and tag/type summaries."
        ),
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
                f"  │ {_pad_plain(marker, status_width)} │ {_pad_plain(label, source_width)} │ {_pad_plain(rendered_result, result_width)} │",
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
        _warn("  No security records or RACF context records (type 80/81/83 or type 1154 subtype 83) found in scanned data.")
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
