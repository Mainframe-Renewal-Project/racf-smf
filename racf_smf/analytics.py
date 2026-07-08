from __future__ import annotations

from collections.abc import Iterable, Iterator
import os
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
# Matches LOGSTREAM(...) entries in SMFPRMxx or D SMF,O output.
_LOGSTREAM_RE = _re.compile(r"LOGSTREAM\s*\(\s*([^)]+)\)", _re.DOTALL | _re.IGNORECASE)


def _derive_sibling_pattern(dataset_name: str) -> str | None:
    """
    Given an active SMF dataset name, return a wildcard pattern covering
    all sibling MAN datasets under the same prefix.
    For example: <HLQ>.<qualifier>.MAN03 -> <HLQ>.<qualifier>.MAN*
    """
    parts = dataset_name.upper().split(".")
    last = parts[-1]
    idx = last.find("MAN")
    if idx >= 0:
        return ".".join(parts[:-1]) + "." + last[:idx] + "MAN*"
    return None


_MEMBER_RE = _re.compile(r"MEMBER\s*=\s*(\w+)", _re.IGNORECASE)
_PARMLIB_RE = _re.compile(r"PARMLIB\s*=\s*(\S+)", _re.IGNORECASE)


def _opercmd_output(command: str, verbose: bool = False) -> str | None:
    """Issue an operator command via ZOAU and return stdout, or None on failure."""
    try:
        from zoautil_py import opercmd  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        result = opercmd.execute(command)
        return getattr(result, "stdout", None) or str(result)
    except Exception as exc:  # noqa: BLE001
        if verbose:
            print(f"  opercmd '{command}' failed: {exc}", flush=True)
        return None


def _sear_import_status() -> tuple[bool, str | None]:
    """
    Return (available, error_message).

    - (True,  None)  : sear imports cleanly.
    - (False, None)  : sear/pysear package is not installed.
    - (False, <msg>) : package is installed but the import failed (e.g. the
                       native libsear.so could not be loaded due to missing
                       Language Environment PTFs or RACF authorizations).
    """
    for module_name in ("sear", "pysear"):
        try:
            import importlib
            importlib.import_module(module_name)
            return True, None
        except ModuleNotFoundError:
            continue          # module genuinely absent — try next name
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)  # installed but broken
    return False, None


def _sear_available() -> bool:
    """Return True if the pySEAR package is importable."""
    ok, _ = _sear_import_status()
    return ok


def _query_sear_smf_dataset_profiles(
    known_prefixes: list[str],
    verbose: bool = False,
) -> list[str]:
    """
    Use pySEAR to search for RACF dataset profiles that look like SMF MAN datasets.

    SEAR's ``dataset_filter`` is a prefix filter (HLQ), so we use the HLQ(s)
    derived from datasets already found by earlier sources.  Results are filtered
    client-side for profiles whose last qualifier starts with 'MAN'.

    Silently returns an empty list when sear is not installed.
    Returns ["__sear_available__"] when installed but no matching profiles found,
    so the caller can distinguish "not installed" from "installed, no results".
    """
    try:
        from sear import sear  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        try:
            from pysear import sear  # type: ignore[import-not-found]
        except ModuleNotFoundError:
            return []
        except Exception:
            return []  # installed but native library unavailable
    except Exception:
        return []  # installed but native library unavailable

    _MAN_SMF_RE = _re.compile(r"(^|\.)(?:MAN|SMF)[A-Z0-9]*(\.|$)", _re.IGNORECASE)

    candidates: list[str] = []
    seen_profiles: set[str] = set()

    for prefix in known_prefixes or [""]:
        try:
            kwargs: dict = {"operation": "search", "admin_type": "dataset"}
            if prefix:
                kwargs["dataset_filter"] = prefix
            result = sear(kwargs)
            profiles: list[str] = getattr(result, "result", None) or []
            if not isinstance(profiles, list):
                continue
        except Exception as exc:  # noqa: BLE001
            if verbose:
                print(f"  SEAR search (prefix='{prefix}') failed: {exc}", flush=True)
            continue

        for p in profiles:
            if isinstance(p, str) and p not in seen_profiles:
                seen_profiles.add(p)
                # Keep only non-generic profiles whose last qualifier looks like MAN*.
                if "%" not in p and "*" not in p and _MAN_SMF_RE.search(p):
                    candidates.append(p)

    if verbose:
        print(f"  SEAR searched {len(known_prefixes or [''])} prefix(es), found {len(candidates)} MAN profile(s)", flush=True)

    return candidates if candidates else []


def _parse_dsnames_from_output(output: str) -> list[str]:
    """Extract all dataset names from a DSNAME(...) block in operator command output."""
    match = _DSNAME_BLOCK_RE.search(output)
    if not match:
        return []
    raw = match.group(1)
    return [n.strip() for n in raw.replace("\n", ",").split(",") if n.strip()]


def _query_smf_d_datasets(verbose: bool = False) -> list[str]:
    """
    Issue 'D SMF,D' and parse all MAN dataset names from the status listing.
    D SMF,D reports ALL configured datasets (ACTIVE, ALTERNATE, FULL, EMPTY),
    not just the current write target, making it more complete than D SMF,O.
    """
    output = _opercmd_output("D SMF,D", verbose=verbose)
    if not output:
        return []
    names = _parse_dsnames_from_output(output)
    if not names:
        # D SMF,D may format each dataset on its own line without a block.
        # Extract any token that looks like a multi-qualifier dataset name.
        names = _re.findall(r"\b([A-Z#@$][A-Z0-9#@$]{0,7}(?:\.[A-Z0-9#@$]{1,8}){1,21})\b", output)
    return names


def _resolve_smf_variables(names: list[str], sysname: str | None) -> list[str]:
    """
    Substitute JCL system variables that appear literally in PARMLIB content.

    SMFPRMxx members use &SYSNAME (and sometimes &SYSPLEX) which are resolved
    by z/OS at IPL, not at read time.  When we read the raw text we must
    substitute them ourselves using the live system name.
    """
    if not sysname:
        return [n for n in names if "&" not in n]
    resolved = []
    for name in names:
        name = name.replace("&SYSNAME.", sysname).replace("&SYSNAME", sysname)
        if "&" not in name:  # drop any remaining unresolvable variables
            resolved.append(name)
    return resolved


def _query_parmlib_datasets(smfprm_member: str, verbose: bool = False) -> list[str]:
    """
    Read a SMFPRMxx PARMLIB member and parse the DSNAME block.
    The PARMLIB member contains ALL configured MAN datasets regardless of
    their current SMF status.

    JCL system variables such as &SYSNAME are resolved using the live
    system name before the dataset names are returned.
    """
    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError:
        return []

    # Determine current system name for &SYSNAME substitution.
    sysname: str | None = None
    try:
        node = _re.sub(r"[^A-Z0-9#@$]", "", os.uname().nodename.upper())  # type: ignore[attr-defined]
        sysname = node or None
    except AttributeError:
        pass
    if not sysname:
        sysname = (os.environ.get("SYSNAME") or os.environ.get("_BPXK_SYSNAME") or "").upper() or None

    for parmlib_dsn in (f"SYS1.PARMLIB({smfprm_member})",):
        try:
            content = datasets.read(parmlib_dsn)
            raw_names = _parse_dsnames_from_output(content)
            names = _resolve_smf_variables(raw_names, sysname)
            if names:
                if verbose:
                    print(f"  Read {len(names)} dataset(s) from PARMLIB member {smfprm_member}", flush=True)
                return names
        except Exception:  # noqa: BLE001
            continue
    return []


def _query_logstream_names(output: str) -> list[str]:
    """Extract logstream names from a LOGSTREAM(...) block in operator output."""
    match = _LOGSTREAM_RE.search(output)
    if not match:
        return []
    raw = match.group(1)
    return [n.strip() for n in raw.replace("\n", ",").split(",") if n.strip()]


def _read_logstream_records(logstream_name: str) -> list[bytes]:
    """
    Attempt to read SMF records from a z/OS logstream via ZOAU.

    ZOAU does not yet expose a dedicated logstream API, so we attempt to
    read the logstream as a dataset.  If the site has bridged its SMF
    logstream to a coupling facility or DASD log, ZOAU's dataset.read_as_bytes
    may succeed.  Returns an empty list when the logstream cannot be read.

    Note: reading directly from in-memory SMF buffers in common storage (as
    zSecure does from an APF-authorized started task) is not possible from a
    USS Python process.
    """
    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError:
        return []
    try:
        records = datasets.read_as_bytes(logstream_name, records=0)
        return records if isinstance(records, list) else []
    except Exception:  # noqa: BLE001
        return []


def _query_active_smf_datasets(verbose: bool = False) -> list[str]:
    """
    Issue 'D SMF,O' via ZOAU opercmd and parse active DSNAME entries.
    Also extracts the active SMFPRMxx member name so the PARMLIB member
    can be read to obtain the full set of configured datasets.
    Returns an empty list if opercmd is unavailable or output cannot be parsed.
    """
    output = _opercmd_output("D SMF,O", verbose=verbose)
    if not output:
        return []

    names = _parse_dsnames_from_output(output)

    # Extract the active PARMLIB member name (MEMBER=xx) from D SMF,O output
    # and read it to get the complete DSNAME list.
    member_match = _MEMBER_RE.search(output)
    if member_match:
        member = f"SMFPRM{member_match.group(1).upper()}"
        if verbose:
            print(f"  Active PARMLIB member: {member}", flush=True)
        parmlib_names = _query_parmlib_datasets(member, verbose=verbose)
        seen = set(names)
        for name in parmlib_names:
            if name not in seen:
                seen.add(name)
                names.append(name)

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
    sources_out: dict[str, list[str]] | None = None,
) -> list[str]:
    """
    Discover active SMF datasets.

    Strategy (in order):
    1. D SMF,O  — active write-target dataset(s) + PARMLIB member for all configured names.
    2. D SMF,D  — all dataset statuses (ACTIVE, ALTERNATE, FULL, EMPTY).
    3. pySEAR   — RACF dataset profiles whose names contain 'MAN'.
    4. Sibling expansion — catalog wildcard derived from any name found above.
    5. Catalog patterns  — explicit or default patterns when all else fails.

    If ``sources_out`` is provided it is populated with a mapping of
    source label → list of dataset names that source contributed.
    """

    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on z/OS runtime
        raise RuntimeError(
            "ZOAU is required for automatic dataset discovery. Install zoautil_py first."
        ) from exc

    if sources_out is not None:
        sources_out.clear()

    discovered: list[str] = []
    seen: set[str] = set()

    def _add(names: list[str], label: str) -> list[str]:
        """Add new names to discovered, record contribution in sources_out."""
        added: list[str] = []
        for n in names:
            if n not in seen:
                seen.add(n)
                discovered.append(n)
                added.append(n)
        if sources_out is not None:
            sources_out[label] = added
        return added

    # --- Source 1: D SMF,O + active PARMLIB member ---
    if patterns is None:
        live = _query_active_smf_datasets(verbose=verbose)
        _add(live, "D SMF,O + PARMLIB")

        # --- Source 2: D SMF,D ---
        smfd = _query_smf_d_datasets(verbose=verbose)
        _add(smfd, "D SMF,D")

        # --- Source 3: pySEAR RACF profile search ---
        # Derive HLQ prefixes from datasets already found so SEAR's prefix
        # filter targets the right part of the catalog.
        hlq_prefixes = list({n.split(".")[0] for n in seen if "." in n})
        sear_names = _query_sear_smf_dataset_profiles(hlq_prefixes, verbose=verbose)
        _add(sear_names, "pySEAR")

        # --- Source 4: sibling expansion via catalog search ---
        sibling_patterns: list[str] = []
        for name in list(seen):
            pat = _derive_sibling_pattern(name)
            if pat and pat not in sibling_patterns:
                sibling_patterns.append(pat)

        siblings: list[str] = []
        for pat in sibling_patterns:
            for name in _list_dataset_names(datasets, pat, include_migrated=include_migrated):
                if name not in seen:
                    siblings.append(name)
        _add(siblings, "Sibling expansion")

        if discovered:
            return discovered

        if sources_out is not None:
            sources_out["D SMF,O + PARMLIB"] = sources_out.get("D SMF,O + PARMLIB", [])

    # --- Source 5: catalog pattern search (fallback or explicit patterns) ---
    selected_patterns = tuple(patterns) if patterns is not None else DEFAULT_SMF_DATASET_PATTERNS
    catalog_hits: list[str] = []
    for pattern in selected_patterns:
        catalog_hits.extend(
            _list_dataset_names(datasets, pattern, include_migrated=include_migrated)
        )
    _add(catalog_hits, f"Catalog patterns ({', '.join(selected_patterns)})")

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
