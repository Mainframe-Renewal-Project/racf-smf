from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Iterator
import os
from pathlib import Path
from typing import Any

from .parser import RecordFormat, SmfRecord, iter_security_records


_SEAR_SENTINEL = "__sear_available__"


DEFAULT_SMF_DATASET_PATTERNS: tuple[str, ...] = (
    "SYS1.*.MAN*",
    "SYS1.MAN*",
    "*.SMF*.*",
    "*.SMF*.*.**",
)

_CATALOG_RECURSIVE_WILDCARD_DEPTH = 8

_DSN_FIRST_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ#@$")
_DSN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$")
_DSN_TOKEN_CHARS = _DSN_CHARS | frozenset(".")


def _is_valid_dsn(name: str) -> bool:
    """Return True only for syntactically valid MVS dataset names (≤ 44 chars)."""
    if not name or len(name) > 44:
        return False
    qualifiers = name.upper().split(".")
    return all(
        qualifier
        and len(qualifier) <= 8
        and qualifier[0] in _DSN_FIRST_CHARS
        and all(char in _DSN_CHARS for char in qualifier)
        for qualifier in qualifiers
    )


def _has_man_or_smf_qualifier(name: str) -> bool:
    return any(part.upper().startswith(("MAN", "SMF")) for part in name.split("."))


def _clean_sysname(value: str) -> str | None:
    cleaned = "".join(char for char in value.upper() if char in _DSN_CHARS)
    return cleaned or None


def _extract_dsn_tokens(text: str | None) -> list[str]:
    if not text:
        return []
    tokens: list[str] = []
    current: list[str] = []
    for char in text.upper():
        if char in _DSN_TOKEN_CHARS:
            current.append(char)
            continue
        if current:
            token = "".join(current).strip(".")
            if "." in token and _is_valid_dsn(token):
                tokens.append(token)
            current = []
    if current:
        token = "".join(current).strip(".")
        if "." in token and _is_valid_dsn(token):
            tokens.append(token)
    return tokens


def _find_assignment_value(text: str | None, key: str) -> str | None:
    if not text:
        return None
    upper = text.upper()
    needle = key.upper()
    cursor = 0
    while True:
        idx = upper.find(needle, cursor)
        if idx < 0:
            return None
        after = idx + len(needle)
        if idx > 0 and upper[idx - 1] in _DSN_CHARS:
            cursor = after
            continue
        while after < len(upper) and upper[after].isspace():
            after += 1
        if after >= len(upper) or upper[after] != "=":
            cursor = after
            continue
        after += 1
        while after < len(upper) and upper[after].isspace():
            after += 1
        start = after
        while after < len(upper) and upper[after] in _DSN_CHARS:
            after += 1
        return upper[start:after] or None


def _iter_parenthesized_values(text: str | None, keyword: str) -> Iterator[str]:
    if not text:
        return
    upper = text.upper()
    needle = keyword.upper()
    cursor = 0
    while True:
        idx = upper.find(needle, cursor)
        if idx < 0:
            return
        after = idx + len(needle)
        while after < len(upper) and upper[after].isspace():
            after += 1
        if after >= len(upper) or upper[after] != "(":
            cursor = after
            continue
        start = after + 1
        end = text.find(")", start)
        if end < 0:
            return
        yield text[start:end]
        cursor = end + 1


def _find_ieasys_list(output: str) -> str | None:
    upper = output.upper()
    cursor = 0
    while True:
        idx = upper.find("IEASYS", cursor)
        if idx < 0:
            return None
        list_idx = upper.find("LIST", idx + len("IEASYS"))
        if list_idx < 0:
            return None
        between = upper[idx + len("IEASYS") : list_idx]
        if between.strip():
            cursor = idx + len("IEASYS")
            continue
        after = list_idx + len("LIST")
        while after < len(upper) and upper[after].isspace():
            after += 1
        if after >= len(upper) or upper[after] != "=":
            cursor = after
            continue
        after += 1
        while after < len(upper) and upper[after].isspace():
            after += 1
        if after >= len(upper) or upper[after] != "(":
            cursor = after
            continue
        end = output.find(")", after + 1)
        return output[after + 1 : end] if end >= 0 else None


def _find_smfprm_members(text: str) -> list[str]:
    members: set[str] = set()
    for token in text.replace("(", " ").replace(")", " ").replace(",", " ").split():
        normalized = token.strip().upper()
        if 6 <= len(normalized) <= 8 and normalized.startswith("SMFPRM") and all(char in _DSN_CHARS for char in normalized):
            members.add(normalized)
    return list(members)


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


def _derive_sibling_broad_pattern(dataset_name: str) -> str | None:
    """
    Full-qualifier wildcard for the parent prefix, used as a fallback when ZOAU
    does not support within-qualifier wildcards.
    e.g. HLQ.SMF.MAN03 -> HLQ.SMF.*  (caller filters with _MAN_SMF_RE)
    """
    parts = dataset_name.upper().split(".")
    last = parts[-1]
    if ("MAN" in last or "SMF" in last) and len(parts) > 1:
        return ".".join(parts[:-1]) + ".*"
    return None


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


def _import_sear_function() -> tuple[Callable[[dict[str, Any]], Any] | None, str | None, bool]:
    """Return (sear_callable, error_message, module_found)."""
    for module_name in ("sear", "pysear"):
        try:
            module = __import__(module_name, fromlist=["sear"])
        except ModuleNotFoundError:
            continue
        except Exception as exc:  # noqa: BLE001
            return None, str(exc), True

        sear_func = getattr(module, "sear", None)
        if callable(sear_func):
            return sear_func, None, True
        return None, f"{module_name}.sear is not callable", True

    return None, None, False


def _sear_import_status() -> tuple[bool, str | None]:
    """
    Return (available, error_message).

    - (True,  None)  : sear imports cleanly.
    - (False, None)  : sear/pysear package is not installed.
    - (False, <msg>) : package is installed but the import failed (e.g. the
                       native libsear.so could not be loaded due to missing
                       Language Environment PTFs or RACF authorizations).
    """
    sear_func, error, found = _import_sear_function()
    if sear_func is not None:
        return True, None
    return False, error if found else None


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
    Returns [_SEAR_SENTINEL] when installed but no matching profiles found,
    so the caller can distinguish "not installed" from "installed, no results".
    """
    sear, import_error, found = _import_sear_function()
    if sear is None:
        if verbose and import_error:
            print(f"  pySEAR import failed: {import_error}", flush=True)
        return []

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
                if "%" not in p and "*" not in p and _has_man_or_smf_qualifier(p):
                    candidates.append(p)

    if verbose:
        print(f"  SEAR searched {len(known_prefixes or [''])} prefix(es), found {len(candidates)} MAN profile(s)", flush=True)

    return candidates if candidates else ([_SEAR_SENTINEL] if found else [])


def _parse_dsnames_from_output(output: str | None) -> list[str]:
    """Extract all dataset names from DSNAME(...) blocks in operator command output.

    Uses finditer to capture every DSNAME block (some SMFPRMxx members list one
    dataset per block).  Non-printable characters introduced by EBCDIC conversion
    are stripped so encoding artifacts do not silently discard valid dataset names.
    """
    if not output:
        return []
    all_names: list[str] = []
    for raw in _iter_parenthesized_values(output, "DSNAME"):
        for token in raw.replace("\n", ",").split(","):
            clean = "".join(c for c in token.strip() if c.isprintable()).strip()
            if clean and _is_valid_dsn(clean):
                all_names.append(clean)
    return all_names


def _coerce_text_output(value: Any) -> str | None:
    """Normalize command-style return values into text for downstream parsing."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    if isinstance(value, (list, tuple, set)):
        parts = [str(item) for item in value if item is not None]
        return "\n".join(parts) if parts else None
    for attr in ("stdout", "output", "text", "result"):
        data = getattr(value, attr, None)
        if data:
            coerced = _coerce_text_output(data)
            if coerced:
                return coerced
    return str(value) if value else None


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
        names = _extract_dsn_tokens(output)
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
        node = _clean_sysname(os.uname().nodename)  # type: ignore[attr-defined]
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


def _query_zsystem_parmlib_search(verbose: bool = False) -> list[str]:
    """
    Use zsystem.search_parmlib as the first live source to find SMF-related
    dataset names in the active parmlib concatenation.

    This searches for DSNAME and LOGSTREAM tokens across parmlib members,
    then resolves any literal &SYSNAME variables using the live system name.
    """
    try:
        from zoautil_py import zsystem  # type: ignore[import-not-found]
    except ImportError:
        return []

    sysname: str | None = None
    try:
        node = _clean_sysname(os.uname().nodename)  # type: ignore[attr-defined]
        sysname = node or None
    except AttributeError:
        pass
    if not sysname:
        sysname = (os.environ.get("SYSNAME") or os.environ.get("_BPXK_SYSNAME") or "").upper() or None

    candidates: list[str] = []
    for needle in ("DSNAME", "LOGSTREAM"):
        try:
            output = zsystem.search_parmlib(needle, ignore_case=True, display_lines=True)
        except Exception as exc:  # noqa: BLE001
            if verbose:
                print(f"  zsystem.search_parmlib('{needle}') failed: {exc}", flush=True)
            continue

        text_output = _coerce_text_output(output)
        raw_names = _parse_dsnames_from_output(text_output)
        if not raw_names:
            raw_names = _extract_dsn_tokens(text_output)

        resolved = _resolve_smf_variables(raw_names, sysname)
        for name in resolved:
            if _has_man_or_smf_qualifier(name) and name not in candidates:
                candidates.append(name)

    if verbose:
        print(f"  zsystem.search_parmlib found {len(candidates)} candidate dataset(s)", flush=True)

    return candidates


# ─── D PARMLIB — full PARMLIB concatenation ───────────────────────────────────


def _query_parmlib_concat(verbose: bool = False) -> list[str]:
    """Issue 'D PARMLIB' and return the ordered list of active PARMLIB dataset names.

    IEE250I prints one line per dataset in the concatenation:
      <volume>  <dataset.name>
    """
    output = _opercmd_output("D PARMLIB", verbose=verbose)
    if not output:
        return []
    dsns: list[str] = []
    seen_set: set[str] = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            candidate = parts[-1].upper().rstrip(".")
            if (
                _is_valid_dsn(candidate)
                and "." in candidate
                and candidate not in seen_set
            ):
                seen_set.add(candidate)
                dsns.append(candidate)
    if verbose:
        print(f"  D PARMLIB found {len(dsns)} PARMLIB dataset(s)", flush=True)
    return dsns


def _read_smfprm_from_parmlibs(
    parmlib_dsns: list[str],
    member: str,
    sysname: str | None,
) -> list[str]:
    """Read one SMFPRMxx member from every PARMLIB dataset; return merged DSNAME/LOGSTREAM names."""
    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError:
        return []
    results: list[str] = []
    seen: set[str] = set()
    for dsn in parmlib_dsns:
        try:
            content = datasets.read(f"{dsn}({member})")
            if not content:
                continue
            for n in _resolve_smf_variables(_parse_dsnames_from_output(content), sysname):
                if n not in seen:
                    seen.add(n)
                    results.append(n)
            for logstream_block in _iter_parenthesized_values(content, "LOGSTREAM"):
                for ls in logstream_block.replace("\n", ",").split(","):
                    ls = ls.strip()
                    if ls and ls not in seen:
                        seen.add(ls)
                        results.append(ls)
        except Exception:  # noqa: BLE001
            continue
    return results


def _query_full_parmlib_smfprm(sysname: str | None, verbose: bool = False) -> list[str]:
    """
    Extend SMFPRMxx reading to every dataset in the active PARMLIB concatenation.

    Source 1 only reads SYS1.PARMLIB.  Many sites prepend a site-specific
    PARMLIB dataset that contains the live SMFPRMxx member.  This source
    re-issues D PARMLIB and tries the active member (from D SMF,O) plus
    SMFPRM00 across every concatenated dataset.
    """
    parmlib_dsns = _query_parmlib_concat(verbose=verbose)
    if not parmlib_dsns:
        return []

    active_member: str | None = None
    smfo = _opercmd_output("D SMF,O")
    if smfo:
        member_suffix = _find_assignment_value(smfo, "MEMBER")
        if member_suffix:
            active_member = f"SMFPRM{member_suffix.upper()}"

    members_to_try: list[str] = []
    if active_member:
        members_to_try.append(active_member)
    if "SMFPRM00" not in members_to_try:
        members_to_try.append("SMFPRM00")

    results: list[str] = []
    seen: set[str] = set()
    for member in members_to_try:
        for n in _read_smfprm_from_parmlibs(parmlib_dsns, member, sysname):
            if n not in seen:
                seen.add(n)
                results.append(n)

    if verbose and results:
        print(f"  Full PARMLIB concat search found {len(results)} additional dataset(s)", flush=True)
    return results


# ─── D IPLINFO ────────────────────────────────────────────────────────────────


def _query_iplinfo_smfprm(sysname: str | None, verbose: bool = False) -> list[str]:
    """
    Issue 'D IPLINFO', locate the SMFPRM suffix via IEASYS, and read the
    corresponding SMFPRMxx member from every PARMLIB dataset.

    Some z/OS levels print SMFPRM=xx directly in D IPLINFO output.
    Otherwise each IEASYSxx member listed in IEASYS LIST is read and
    searched for SMFPRM= to derive the correct suffix.
    """
    output = _opercmd_output("D IPLINFO", verbose=verbose)
    if not output:
        return []

    parmlib_dsns = _query_parmlib_concat()

    smfprm_suffix = _find_assignment_value(output, "SMFPRM")
    if smfprm_suffix:
        member = f"SMFPRM{smfprm_suffix.upper():0>2}"
        if verbose:
            print(f"  D IPLINFO -> SMFPRM suffix {smfprm_suffix.upper()}", flush=True)
        return _read_smfprm_from_parmlibs(parmlib_dsns, member, sysname)

    ieasys_list = _find_ieasys_list(output)
    if not ieasys_list:
        return []

    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError:
        return []

    for suffix in ieasys_list.split(","):
        suffix = suffix.strip().upper()
        if not suffix:
            continue
        ieasys_member = f"IEASYS{suffix:0>2}"
        for dsn in parmlib_dsns:
            try:
                content = datasets.read(f"{dsn}({ieasys_member})")
                smfprm_suffix = _find_assignment_value(content, "SMFPRM")
                if smfprm_suffix:
                    member = f"SMFPRM{smfprm_suffix.upper():0>2}"
                    if verbose:
                        print(f"  {ieasys_member} -> SMFPRM suffix {smfprm_suffix.upper()}", flush=True)
                    return _read_smfprm_from_parmlibs(parmlib_dsns, member, sysname)
            except Exception:  # noqa: BLE001
                continue
    return []


# ─── zsystem.list_parmlib ─────────────────────────────────────────────────────


def _query_zsystem_all_smfprm_members(sysname: str | None, verbose: bool = False) -> list[str]:
    """
    Call zsystem.list_parmlib() to enumerate every member in the PARMLIB
    concatenation, filter for SMFPRM* members, and parse DSNAME entries from each.
    Uses zsystem.find_parmlib() to locate the containing dataset for each member.
    """
    try:
        from zoautil_py import zsystem, datasets  # type: ignore[import-not-found]
    except ImportError:
        return []

    try:
        raw = zsystem.list_parmlib()
    except Exception as exc:  # noqa: BLE001
        if verbose:
            print(f"  zsystem.list_parmlib() failed: {exc}", flush=True)
        return []

    text = _coerce_text_output(raw) or ""
    smfprm_members = _find_smfprm_members(text)
    if verbose:
        print(f"  zsystem.list_parmlib found {len(smfprm_members)} SMFPRM* member(s)", flush=True)

    results: list[str] = []
    seen: set[str] = set()
    for member in smfprm_members:
        containing_dsn = "SYS1.PARMLIB"
        try:
            found_text = _coerce_text_output(zsystem.find_parmlib(member)) or ""
            dsn_candidate = found_text.strip().split("(")[0].strip()
            if _is_valid_dsn(dsn_candidate) and "." in dsn_candidate:
                containing_dsn = dsn_candidate
        except Exception:  # noqa: BLE001
            pass
        try:
            content = datasets.read(f"{containing_dsn}({member})")
            if not content:
                continue
            for n in _resolve_smf_variables(_parse_dsnames_from_output(content), sysname):
                if n not in seen:
                    seen.add(n)
                    results.append(n)
        except Exception:  # noqa: BLE001
            continue

    return results


# ─── D LOGGER ─────────────────────────────────────────────────────────────────

def _query_smf_logstreams(verbose: bool = False) -> list[str]:
    """
    Issue 'D LOGGER,L' and return logstream names that contain 'SMF'.
    Logstreams are added to the discovered list alongside datasets; ZOAU
    can transparently read DASD-bridged logstreams via datasets.read_as_bytes.
    """
    output = _opercmd_output("D LOGGER,L", verbose=verbose)
    if not output:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for name in _extract_dsn_tokens(output):
        if _has_man_or_smf_qualifier(name) and name not in seen:
            seen.add(name)
            found.append(name)
    if verbose:
        print(f"  D LOGGER,L found {len(found)} SMF logstream candidate(s)", flush=True)
    return found


def _query_logstream_names(output: str) -> list[str]:
    """Extract logstream names from a LOGSTREAM(...) block in operator output."""
    names: list[str] = []
    for raw in _iter_parenthesized_values(output, "LOGSTREAM"):
        names.extend(n.strip() for n in raw.replace("\n", ",").split(",") if n.strip())
    return names


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
    member_suffix = _find_assignment_value(output, "MEMBER")
    if member_suffix:
        member = f"SMFPRM{member_suffix.upper()}"
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
        try:
            # Older ZOAU levels may not support the migrated keyword.
            return datasets_module.list_dataset_names(pattern) or []
        except Exception:  # noqa: BLE001
            return []
    except Exception:  # noqa: BLE001
        return []


def _catalog_pattern_variants(pattern: str) -> tuple[str, ...]:
    """Return portable catalog probes for patterns that use recursive ** suffixes."""
    normalized = pattern.strip().upper()
    if not normalized:
        return ()

    variants: list[str] = []
    seen: set[str] = set()

    def _add(candidate: str) -> None:
        if candidate and candidate not in seen:
            seen.add(candidate)
            variants.append(candidate)

    if normalized.endswith(".**"):
        base = normalized[:-3]
        _add(base)
        for depth in range(1, _CATALOG_RECURSIVE_WILDCARD_DEPTH + 1):
            _add(base + (".*" * depth))
        _add(normalized)
    elif "**" in normalized:
        _add(normalized.replace("**", "*"))
        _add(normalized)
    else:
        _add(normalized)

    return tuple(variants)


def _import_zoau_datasets():
    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError:
        return None
    return datasets


def discover_smf_datasets(
    patterns: Iterable[str] | None = None,
    *,
    include_migrated: bool = False,
    include_logstreams: bool = False,
    verbose: bool = False,
    sources_out: dict[str, list[str]] | None = None,
) -> list[str]:
    """
    Discover active SMF datasets.

    Strategy (in order):
    1.  zsystem.search_parmlib - scan active parmlib concatenation for DSNAME/LOGSTREAM tokens.
    2.  zsystem.list_parmlib — enumerate all SMFPRM* members across the concatenation.
    3.  pySEAR   - RACF dataset profiles whose names contain MAN or SMF.
    4.  D SMF,O  - active write-target dataset(s) + PARMLIB member for all configured names.
    5.  D SMF,D  - all dataset statuses (ACTIVE, ALTERNATE, FULL, EMPTY).
    6.  D PARMLIB — read active SMFPRMxx from every PARMLIB dataset in the concatenation.
    7.  D IPLINFO - locate SMFPRM suffix via IEASYSxx when D SMF,O does not report it.
    8.  D LOGGER  — discover SMF logstreams for sites using logstream-based SMF recording.
    9.  Sibling expansion — catalog wildcard derived from any name found above.
    10. Catalog patterns  — explicit or default patterns when all else fails.

    If ``sources_out`` is provided it is populated with a mapping of
    source label -> list of dataset names that source contributed.
    """

    datasets = _import_zoau_datasets()

    if sources_out is not None:
        sources_out.clear()

    discovered: list[str] = []
    seen: set[str] = set()

    def _add(names: list[str], label: str, *, include_in_discovered: bool = True) -> list[str]:
        """Add new names to discovered, record contribution in sources_out."""
        added: list[str] = []
        for n in names:
            if n not in seen and include_in_discovered:
                seen.add(n)
                discovered.append(n)
                added.append(n)
            elif include_in_discovered and n in seen:
                continue
            elif not include_in_discovered:
                added.append(n)
        if sources_out is not None:
            sources_out[label] = added
        return added

    # Pre-compute system name for &SYSNAME substitution; shared across all sources.
    _sysname: str | None = None
    try:
        _node = _clean_sysname(os.uname().nodename)  # type: ignore[attr-defined]
        _sysname = _node or None
    except AttributeError:
        pass
    if not _sysname:
        _sysname = (os.environ.get("SYSNAME") or os.environ.get("_BPXK_SYSNAME") or "").upper() or None

    if patterns is None:
        # --- Source 1: zsystem search of parmlib text ---
        zsys_names = _query_zsystem_parmlib_search(verbose=verbose)
        _add(zsys_names, "zsystem.search_parmlib")

        # --- Source 2: zsystem.list_parmlib SMFPRM* members ---
        zlist_names = _query_zsystem_all_smfprm_members(_sysname, verbose=verbose)
        _add(zlist_names, "zsystem.list_parmlib")

        # --- Source 3: pySEAR RACF profile search ---
        # Derive HLQ prefixes from datasets already found so SEAR's prefix
        # filter targets the right part of the catalog.
        hlq_prefixes = list({n.split(".")[0] for n in seen if "." in n})
        sear_names = _query_sear_smf_dataset_profiles(hlq_prefixes, verbose=verbose)
        sear_hits = [name for name in sear_names if name != _SEAR_SENTINEL]
        _add(sear_hits, "pySEAR")
        if sources_out is not None and _SEAR_SENTINEL in sear_names:
            sources_out["pySEAR"] = []

        # --- Source 4: D SMF,O + active PARMLIB member ---
        live = _query_active_smf_datasets(verbose=verbose)
        _add(live, "D SMF,O + PARMLIB")

        # --- Source 5: D SMF,D ---
        smfd = _query_smf_d_datasets(verbose=verbose)
        _add(smfd, "D SMF,D")

        # --- Source 6: full PARMLIB concatenation SMFPRMxx search ---
        parmlib_names = _query_full_parmlib_smfprm(_sysname, verbose=verbose)
        _add(parmlib_names, "D PARMLIB (full concat)")

        # --- Source 7: D IPLINFO -> SMFPRM suffix via IEASYSxx ---
        iplinfo_names = _query_iplinfo_smfprm(_sysname, verbose=verbose)
        _add(iplinfo_names, "D IPLINFO")

        # --- Source 8: D LOGGER SMF logstreams ---
        logstream_names = _query_smf_logstreams(verbose=verbose)
        _add(logstream_names, "D LOGGER", include_in_discovered=include_logstreams)

        # --- Source 9: sibling expansion via catalog search ---
        sibling_patterns: list[str] = []
        for name in list(seen):
            # Try both a specific MAN*/SMF* suffix pattern and the broader parent.*
            # wildcard so expansion works regardless of ZOAU's wildcard support level.
            for pat in (_derive_sibling_pattern(name), _derive_sibling_broad_pattern(name)):
                if pat and pat not in sibling_patterns:
                    sibling_patterns.append(pat)

        siblings: list[str] = []
        if datasets is not None:
            for pat in sibling_patterns:
                for name in _list_dataset_names(datasets, pat, include_migrated=include_migrated):
                    if name not in seen and _has_man_or_smf_qualifier(name):
                        siblings.append(name)
        _add(siblings, "Sibling expansion")

        if discovered:
            return discovered

        if sources_out is not None:
            sources_out["D SMF,O + PARMLIB"] = sources_out.get("D SMF,O + PARMLIB", [])

    # --- Source 10: catalog pattern search (fallback or explicit patterns) ---
    if datasets is None:
        if discovered:
            return discovered
        raise RuntimeError(
            "ZOAU datasets support is required for catalog pattern discovery. Install zoautil_py "
            "or use pySEAR/zsystem discovery on z/OS."
        )

    selected_patterns = tuple(patterns) if patterns is not None else DEFAULT_SMF_DATASET_PATTERNS
    catalog_hits: list[str] = []
    for pattern in selected_patterns:
        for catalog_pattern in _catalog_pattern_variants(pattern):
            catalog_hits.extend(
                _list_dataset_names(datasets, catalog_pattern, include_migrated=include_migrated)
            )
    _add(catalog_hits, f"Catalog patterns ({', '.join(selected_patterns)})")

    return discovered


def record_to_event(record: SmfRecord, *, source: str | None = None) -> dict[str, Any]:
    """Convert an SMF record into a normalized event row for analytics tooling."""

    if "RACF" in record.tags:
        event_family = "RACF"
    elif "RACF_INIT" in record.tags:
        event_family = "RACF_INIT"
    elif "ZOS_UNIX_SECURITY" in record.tags:
        event_family = "ZOS_UNIX_SECURITY"
    elif "RACF_COMPLIANCE" in record.tags:
        event_family = "RACF_COMPLIANCE"
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
        "timestamp": record.timestamp,
        "event_code": record.event_code,
        "event_qualifier": record.event_qualifier,
        "user_id": record.user_id,
        "group_name": record.group_name,
        "terminal_id": record.terminal_id,
        "job_name": record.job_name,
        "smf_user_id": record.smf_user_id,
        "product_name": record.product_name,
        "product_version": record.product_version,
        "address_space_user_id": record.address_space_user_id,
        "address_space_group_name": record.address_space_group_name,
        "resource_name": record.resource_name,
        "class_name": record.class_name,
        "profile_name": record.profile_name,
        "authenticated_user_name": record.authenticated_user_name,
        "authenticated_user_registry": record.authenticated_user_registry,
        "authenticated_user_host": record.authenticated_user_host,
        "authenticated_user_oid": record.authenticated_user_oid,
        "distributed_identity_user_name": record.distributed_identity_user_name,
        "distributed_identity_registry": record.distributed_identity_registry,
        "action_hint": record.action_hint,
        "initialization_context": record.initialization_context,
        "compliance_context": record.compliance_context,
        "compliance_summary": record.compliance_summary,
        "compliance_findings": tuple(record.compliance_findings),
        "unloaded_fields": record.unloaded_fields,
        "user_id_candidates": tuple(record.user_id_candidates),
        "resource_candidates": tuple(record.resource_candidates),
        "text_tokens": tuple(record.text_tokens),
        "event_family": event_family,
        "tags": tuple(record.tags),
    }


def event_user_ids(event: dict[str, Any]) -> tuple[str, ...]:
    """Return all decoded user identifiers associated with an event."""

    users = {
        event.get("user_id"),
        event.get("smf_user_id"),
        event.get("address_space_user_id"),
        event.get("authenticated_user_name"),
        event.get("distributed_identity_user_name"),
        *event.get("user_id_candidates", ()),
    }
    return tuple(sorted({str(user).upper() for user in users if user}))


def event_action_label(event: dict[str, Any]) -> str:
    """Return a readable action label for a normalized security event."""

    return str(
        event.get("action_hint")
        or f"type={event.get('record_type')} event={event.get('event_code')}"
    )


def event_resource_label(event: dict[str, Any]) -> str:
    """Return the best available resource/profile label for a security event."""

    return str(
        event.get("resource_name")
        or event.get("profile_name")
        or ", ".join(event.get("resource_candidates", ()))
        or "-"
    )


def event_matches_user(event: dict[str, Any], user_id: str) -> bool:
    """Return True when any decoded identity on the event matches user_id."""

    return user_id.upper() in event_user_ids(event)


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
    include_logstreams: bool = False,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
) -> Iterator[dict[str, Any]]:
    """Auto-discover SMF datasets and yield normalized security events from all of them."""

    for dataset_name in discover_smf_datasets(
        dataset_patterns,
        include_migrated=include_migrated,
        include_logstreams=include_logstreams,
    ):
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
    include_logstreams: bool = False,
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
            include_logstreams=include_logstreams,
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
    include_logstreams: bool = False,
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
            include_logstreams=include_logstreams,
            record_format=record_format,
            strict_man=strict_man,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        )
    )


def iter_user_security_events(
    user_id: str,
    path: str | Path | None = None,
    *,
    dataset_patterns: Iterable[str] | None = None,
    include_migrated: bool = False,
    include_logstreams: bool = False,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    dataset_input: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
) -> Iterator[dict[str, Any]]:
    """
    Yield normalized security events associated with a specific user.

    If path is omitted, SMF datasets are auto-discovered. If path is supplied,
    events are read from that file or dataset according to dataset_input.
    """

    if path is None:
        events = iter_discovered_security_events(
            dataset_patterns=dataset_patterns,
            include_migrated=include_migrated,
            include_logstreams=include_logstreams,
            record_format=record_format,
            strict_man=strict_man,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        )
    else:
        events = iter_security_events(
            path,
            record_format=record_format,
            strict_man=strict_man,
            dataset_input=dataset_input,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        )

    for event in events:
        if event_matches_user(event, user_id):
            yield event


def read_user_security_events(
    user_id: str,
    path: str | Path | None = None,
    *,
    dataset_patterns: Iterable[str] | None = None,
    include_migrated: bool = False,
    include_logstreams: bool = False,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    dataset_input: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Return all security events associated with a specific user."""

    return list(
        iter_user_security_events(
            user_id,
            path,
            dataset_patterns=dataset_patterns,
            include_migrated=include_migrated,
            include_logstreams=include_logstreams,
            record_format=record_format,
            strict_man=strict_man,
            dataset_input=dataset_input,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        )
    )


def _counter_rows(counter: Counter[str], *, limit: int | None = None) -> list[dict[str, Any]]:
    rows = counter.most_common(limit)
    return [{"value": value, "count": count} for value, count in rows]


def _value_or_dash(value: Any) -> Any:
    if value is None or value == "":
        return "-"
    return value


def _event_detail(event: dict[str, Any], *, include_raw: bool) -> dict[str, Any]:
    detail = {
        "timestamp": event.get("timestamp"),
        "event_family": event.get("event_family"),
        "system_id": event.get("system_id"),
        "source": event.get("source"),
        "offset": event.get("offset"),
        "record_type": event.get("record_type"),
        "subtype": event.get("subtype"),
        "identity": {
            "matched_identities": event_user_ids(event),
            "user_id": event.get("user_id"),
            "smf_user_id": event.get("smf_user_id"),
            "group_name": event.get("group_name"),
            "address_space_user_id": event.get("address_space_user_id"),
            "address_space_group_name": event.get("address_space_group_name"),
            "authenticated_user_name": event.get("authenticated_user_name"),
            "distributed_identity_user_name": event.get("distributed_identity_user_name"),
        },
        "action": {
            "action_hint": event_action_label(event),
            "event_code": event.get("event_code"),
            "event_qualifier": event.get("event_qualifier"),
            "job_name": event.get("job_name"),
            "terminal_id": event.get("terminal_id"),
        },
        "target": {
            "class_name": event.get("class_name"),
            "resource_name": event.get("resource_name"),
            "profile_name": event.get("profile_name"),
            "best_target": event_resource_label(event),
            "resource_candidates": tuple(event.get("resource_candidates", ())),
        },
        "product_context": {
            "product_name": event.get("product_name"),
            "product_version": event.get("product_version"),
            "authenticated_user_registry": event.get("authenticated_user_registry"),
            "authenticated_user_host": event.get("authenticated_user_host"),
            "authenticated_user_oid": event.get("authenticated_user_oid"),
            "distributed_identity_registry": event.get("distributed_identity_registry"),
        },
    }
    if include_raw:
        detail["raw_event"] = event
    return detail


def build_user_security_report(
    user_id: str,
    events: Iterable[dict[str, Any]],
    *,
    max_detail_events: int = 50,
    raw_samples: int = 0,
) -> dict[str, Any]:
    """Build a drilldown report from events that are already filtered to a user."""

    matched_events = list(events)
    sorted_events = sorted(
        matched_events,
        key=lambda event: event.get("timestamp") or "",
        reverse=True,
    )
    detail_events = sorted_events[:max_detail_events]

    return {
        "target_user": user_id.upper(),
        "matched_count": len(matched_events),
        "summaries": {
            "by_action": _counter_rows(Counter(event_action_label(event) for event in matched_events)),
            "by_class": _counter_rows(Counter(event.get("class_name") or "-" for event in matched_events)),
            "by_resource": _counter_rows(Counter(event_resource_label(event) for event in matched_events), limit=20),
            "by_job": _counter_rows(Counter(event.get("job_name") or "-" for event in matched_events)),
            "by_terminal": _counter_rows(Counter(event.get("terminal_id") or "-" for event in matched_events)),
            "by_source": _counter_rows(Counter(event.get("source") or "-" for event in matched_events)),
        },
        "events": [
            _event_detail(event, include_raw=index < raw_samples)
            for index, event in enumerate(detail_events)
        ],
        "max_detail_events": max_detail_events,
        "raw_samples": raw_samples,
    }


def read_user_security_report(
    user_id: str,
    path: str | Path | None = None,
    *,
    dataset_patterns: Iterable[str] | None = None,
    include_migrated: bool = False,
    include_logstreams: bool = False,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    dataset_input: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
    max_detail_events: int = 50,
    raw_samples: int = 0,
) -> dict[str, Any]:
    """Read events for a user and return a ready-to-render drilldown report."""

    return build_user_security_report(
        user_id,
        iter_user_security_events(
            user_id,
            path,
            dataset_patterns=dataset_patterns,
            include_migrated=include_migrated,
            include_logstreams=include_logstreams,
            record_format=record_format,
            strict_man=strict_man,
            dataset_input=dataset_input,
            include_all=include_all,
            zos_unix_subtypes=zos_unix_subtypes,
        ),
        max_detail_events=max_detail_events,
        raw_samples=raw_samples,
    )


def _format_summary(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [title]
    for row in rows:
        lines.append(f"  {row['count']:6}  {row['value']}")
    lines.append("")
    return lines


def _format_field(label: str, value: Any) -> str:
    return f"  {label:<28} {_value_or_dash(value)}"


def format_user_security_report(report: dict[str, Any]) -> str:
    """Format a user security drilldown report as readable text."""

    from pprint import pformat

    lines = [
        f"Security event drilldown for user: {report['target_user']}",
        f"Matched events: {report['matched_count']}",
        "",
    ]
    summaries = report["summaries"]
    lines.extend(_format_summary("Summary by action", summaries["by_action"]))
    lines.extend(_format_summary("Summary by RACF class", summaries["by_class"]))
    lines.extend(_format_summary("Top resources/profiles", summaries["by_resource"]))
    lines.extend(_format_summary("Summary by job", summaries["by_job"]))
    lines.extend(_format_summary("Summary by terminal", summaries["by_terminal"]))
    lines.extend(_format_summary("Summary by source", summaries["by_source"]))

    lines.append(f"Detailed events, newest first, showing up to {report['max_detail_events']}")
    for event_number, event in enumerate(report["events"], start=1):
        identity = event["identity"]
        action = event["action"]
        target = event["target"]
        product_context = event["product_context"]

        lines.extend([
            "",
            f"Event {event_number}",
            _format_field("timestamp", event.get("timestamp")),
            _format_field("event family", event.get("event_family")),
            _format_field("system id", event.get("system_id")),
            _format_field("source", event.get("source")),
            _format_field("offset", event.get("offset")),
            _format_field("record type", event.get("record_type")),
            _format_field("subtype", event.get("subtype")),
            "  Identity",
            _format_field("matched identities", ", ".join(identity["matched_identities"])),
            _format_field("user id", identity.get("user_id")),
            _format_field("SMF user id", identity.get("smf_user_id")),
            _format_field("group name", identity.get("group_name")),
            _format_field("address-space user", identity.get("address_space_user_id")),
            _format_field("address-space group", identity.get("address_space_group_name")),
            _format_field("authenticated user", identity.get("authenticated_user_name")),
            _format_field("distributed identity", identity.get("distributed_identity_user_name")),
            "  Action",
            _format_field("action hint", action.get("action_hint")),
            _format_field("event code", action.get("event_code")),
            _format_field("event qualifier", action.get("event_qualifier")),
            _format_field("job name", action.get("job_name")),
            _format_field("terminal id", action.get("terminal_id")),
            "  Target",
            _format_field("class name", target.get("class_name")),
            _format_field("resource name", target.get("resource_name")),
            _format_field("profile name", target.get("profile_name")),
            _format_field("best target", target.get("best_target")),
            _format_field("resource candidates", ", ".join(target["resource_candidates"])),
            "  Product/context",
            _format_field("product name", product_context.get("product_name")),
            _format_field("product version", product_context.get("product_version")),
            _format_field("auth registry", product_context.get("authenticated_user_registry")),
            _format_field("auth host", product_context.get("authenticated_user_host")),
            _format_field("auth oid", product_context.get("authenticated_user_oid")),
            _format_field("distributed registry", product_context.get("distributed_identity_registry")),
        ])
        if "raw_event" in event:
            lines.append("  Raw decoded event")
            lines.append("    " + pformat(event["raw_event"], width=100).replace("\n", "\n    "))

    return "\n".join(lines)
