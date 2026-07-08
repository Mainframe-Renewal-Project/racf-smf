from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path
import re as _re
from typing import Any

from .parser import RecordFormat, SmfRecord, iter_security_records


DEFAULT_SMF_DATASET_PATTERNS: tuple[str, ...] = (
    "SYS1.*.MAN*",
    "SYS1.MAN*",
)

# Matches the DSNAME(...) block in D SMF,O output including continuation lines.
_DSNAME_BLOCK_RE = _re.compile(r"DSNAME\s*\(([^)]+)\)", _re.DOTALL | _re.IGNORECASE)


def _query_active_smf_datasets(verbose: bool = False) -> list[str]:
    """
    Issue 'D SMF,O' via ZOAU opercmd and parse active DSNAME entries.

    This is naming-convention-agnostic: whatever datasets SMF is actually
    writing to will be returned regardless of HLQ or site standards.
    Returns an empty list if opercmd is unavailable or output cannot be parsed.
    """
    try:
        from zoautil_py import opercmd  # type: ignore[import-not-found]
    except ImportError:
        return []

    try:
        result = opercmd.execute("D SMF,O")
        output = getattr(result, "stdout", None) or str(result)
    except Exception as exc:  # noqa: BLE001
        if verbose:
            print(f"  opercmd 'D SMF,O' failed: {exc}", flush=True)
        return []

    match = _DSNAME_BLOCK_RE.search(output)
    if not match:
        if verbose:
            print("  Could not parse DSNAME block from 'D SMF,O' output.", flush=True)
        return []

    raw = match.group(1)
    names = [n.strip() for n in raw.replace("\n", ",").split(",") if n.strip()]
    return names


def _list_dataset_names(datasets_module, pattern: str, *, include_migrated: bool) -> list[str]:
    try:
        return datasets_module.list_dataset_names(pattern, migrated=include_migrated) or []
    except TypeError:
        # Older ZOAU levels may not support the migrated keyword.
        return datasets_module.list_dataset_names(pattern) or []


def discover_smf_datasets(
    patterns: Iterable[str] | None = None,
    *,
    include_migrated: bool = False,
    verbose: bool = False,
) -> list[str]:
    """
    Discover active SMF datasets.

    Strategy (in order):
    1. If no custom patterns are given, query 'D SMF,O' via ZOAU opercmd to
       read the active DSNAME list directly from the running system.  This is
       naming-convention-agnostic and works for any site.
    2. Fall back to ZOAU catalog search using the supplied (or default) patterns
       when opercmd is unavailable or returns no results.
    """

    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on z/OS runtime
        raise RuntimeError(
            "ZOAU is required for automatic dataset discovery. Install zoautil_py first."
        ) from exc

    discovered: list[str] = []
    seen: set[str] = set()

    # --- Primary: read active datasets directly from D SMF,O ---
    if patterns is None:
        if verbose:
            print("Querying active SMF datasets via 'D SMF,O'...", flush=True)
        live = _query_active_smf_datasets(verbose=verbose)
        if live:
            if verbose:
                print(f"  Found {len(live)} dataset(s) from D SMF,O", flush=True)
            for name in live:
                if name not in seen:
                    seen.add(name)
                    discovered.append(name)
            return discovered
        if verbose:
            print("  D SMF,O returned no datasets, falling back to catalog search.", flush=True)

    # --- Fallback: catalog search by pattern ---
    selected_patterns = tuple(patterns) if patterns is not None else DEFAULT_SMF_DATASET_PATTERNS

    if verbose:
        print(f"Searching catalog patterns: {', '.join(selected_patterns)}", flush=True)

    for pattern in selected_patterns:
        names = _list_dataset_names(datasets, pattern, include_migrated=include_migrated)
        if verbose:
            print(f"  {pattern}: {len(names)} result(s)", flush=True)
        for name in names:
            if name not in seen:
                seen.add(name)
                discovered.append(name)

    return discovered


def record_to_event(record: SmfRecord, *, source: str | None = None) -> dict[str, Any]:
    """Convert an SMF record into a normalized event row for analytics tooling."""

    if "RACF" in record.tags:
        event_family = "RACF"
    elif "ZOS_UNIX_SECURITY" in record.tags:
        event_family = "ZOS_UNIX_SECURITY"
    else:
        event_family = "OTHER"

    return {
        "source": source,
        "offset": record.offset,
        "total_length": record.total_length,
        "record_length": record.record_length,
        "record_type": record.record_type,
        "subtype": record.subtype,
        "system_id": record.system_id,
        "event_family": event_family,
        "tags": tuple(record.tags),
    }


def iter_security_events(
    path: str | Path,
    *,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    dataset_input: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield normalized event dictionaries suitable for pySEAR/analytics pipelines."""

    source = str(path)
    for record in iter_security_records(
        path,
        record_format=record_format,
        strict_man=strict_man,
        dataset_input=dataset_input,
        include_all=include_all,
        zos_unix_subtypes=zos_unix_subtypes,
    ):
        yield record_to_event(record, source=source)


def read_security_events(
    path: str | Path,
    *,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    dataset_input: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Return normalized security events as a materialized list of dict rows."""

    return list(
        iter_security_events(
            path,
            record_format=record_format,
            strict_man=strict_man,
            dataset_input=dataset_input,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        )
    )


def events_to_dataframe(events: Iterable[dict[str, Any]]):
    """
    Convert event rows to a pandas DataFrame.

    Raises ImportError with a helpful message if pandas is unavailable.
    """

    try:
        import pandas as pd  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on optional dependency
        raise ImportError("pandas is required for DataFrame export. Install with: pip install pandas") from exc

    return pd.DataFrame(events)


def read_security_dataframe(
    path: str | Path,
    *,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    dataset_input: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
):
    """Read security events and return them as a pandas DataFrame."""

    return events_to_dataframe(
        iter_security_events(
            path,
            record_format=record_format,
            strict_man=strict_man,
            dataset_input=dataset_input,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        )
    )


def iter_discovered_security_events(
    *,
    dataset_patterns: Iterable[str] | None = None,
    include_migrated: bool = False,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
) -> Iterator[dict[str, Any]]:
    """Auto-discover SMF datasets and yield normalized security events from all of them."""

    for dataset_name in discover_smf_datasets(dataset_patterns, include_migrated=include_migrated):
        yield from iter_security_events(
            dataset_name,
            record_format=record_format,
            strict_man=strict_man,
            dataset_input=True,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        )


def read_discovered_security_events(
    *,
    dataset_patterns: Iterable[str] | None = None,
    include_migrated: bool = False,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Materialize events from all auto-discovered SMF datasets into a list."""

    return list(
        iter_discovered_security_events(
            dataset_patterns=dataset_patterns,
            include_migrated=include_migrated,
            record_format=record_format,
            strict_man=strict_man,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        )
    )


def read_discovered_security_dataframe(
    *,
    dataset_patterns: Iterable[str] | None = None,
    include_migrated: bool = False,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
):
    """Auto-discover SMF datasets and return events as a pandas DataFrame."""

    return events_to_dataframe(
        iter_discovered_security_events(
            dataset_patterns=dataset_patterns,
            include_migrated=include_migrated,
            record_format=record_format,
            strict_man=strict_man,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        )
    )
