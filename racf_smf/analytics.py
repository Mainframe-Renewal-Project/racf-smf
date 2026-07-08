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
# Dataset names that contain MAN or SMF in at least one qualifier.
_MAN_SMF_RE = _re.compile(r"(?:^|\.)(?:MAN|SMF)[A-Z0-9]*(?:\.|$)", _re.IGNORECASE)
# Validates a syntactically legal MVS dataset name (each qualifier starts with a letter
# or national character; digits-only tokens like block addresses are rejected).
_VALID_DSN_RE = _re.compile(
    r"^[A-Z#@$][A-Z0-9#@$]{0,7}(\.[A-Z#@$][A-Z0-9#@$]{0,7})*$",
    _re.IGNORECASE,
)


def _is_valid_dsn(name: str) -> bool:
    """Return True only for syntactically valid MVS dataset names (≤ 44 chars)."""
    return bool(name) and len(name) <= 44 and bool(_VALID_DSN_RE.match(name))


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
    e.g. SYS1.YCPU.MAN03 -> SYS1.YCPU.*  (caller filters with _MAN_SMF_RE)
    """
    parts = dataset_name.upper().split(".")
    last = parts[-1]
    if ("MAN" in last or "SMF" in last) and len(parts) > 1:
        return ".".join(parts[:-1]) + ".*"
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


def _parse_dsnames_from_output(output: str | None) -> list[str]:
    """Extract all dataset names from DSNAME(...) blocks in operator command output.

    Uses finditer to capture every DSNAME block (some SMFPRMxx members list one
    dataset per block).  Non-printable characters introduced by EBCDIC conversion
    are stripped so encoding artifacts do not silently discard valid dataset names.
    """
    if not output:
        return []
    all_names: list[str] = []
    for match in _DSNAME_BLOCK_RE.finditer(output):
        raw = match.group(1)
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


def _query_zsystem_parmlib_search(verbose: bool = False) -> list[str]:
    """
    Use zsystem.search_parmlib as a broad fallback to find SMF-related
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
        node = _re.sub(r"[^A-Z0-9#@$]", "", os.uname().nodename.upper())  # type: ignore[attr-defined]
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
            raw_names = _re.findall(r"\b([A-Z#@$][A-Z0-9#@$]{0,7}(?:\.[A-Z0-9#@$]{1,8}){1,21})\b", text_output or "")

        resolved = _resolve_smf_variables(raw_names, sysname)
        for name in resolved:
            if _MAN_SMF_RE.search(name) and name not in candidates:
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
                _re.match(r"^[A-Z#@$][A-Z0-9#@$]{0,7}(\.[A-Z0-9#@$]{1,8})+$", candidate)
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
            ls_m = _LOGSTREAM_RE.search(content)
            if ls_m:
                for ls in ls_m.group(1).replace("\n", ",").split(","):
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
        m = _MEMBER_RE.search(smfo)
        if m:
            active_member = f"SMFPRM{m.group(1).upper()}"

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

    direct = _re.search(r"\bSMFPRM\s*=\s*([0-9A-Z]{1,2})\b", output, _re.IGNORECASE)
    if direct:
        member = f"SMFPRM{direct.group(1).upper():0>2}"
        if verbose:
            print(f"  D IPLINFO → SMFPRM suffix {direct.group(1).upper()}", flush=True)
        return _read_smfprm_from_parmlibs(parmlib_dsns, member, sysname)

    ieasys_m = _re.search(r"IEASYS\s+LIST\s*=\s*\(([^)]+)\)", output, _re.IGNORECASE)
    if not ieasys_m:
        return []

    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError:
        return []

    for suffix in ieasys_m.group(1).split(","):
        suffix = suffix.strip().upper()
        if not suffix:
            continue
        ieasys_member = f"IEASYS{suffix:0>2}"
        for dsn in parmlib_dsns:
            try:
                content = datasets.read(f"{dsn}({ieasys_member})")
                smfm = _re.search(r"\bSMFPRM\s*=\s*([0-9A-Z]{1,2})\b", content or "", _re.IGNORECASE)
                if smfm:
                    member = f"SMFPRM{smfm.group(1).upper():0>2}"
                    if verbose:
                        print(f"  {ieasys_member} → SMFPRM suffix {smfm.group(1).upper()}", flush=True)
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
    smfprm_members = list({m.upper() for m in _re.findall(r"\bSMFPRM[A-Z0-9]{0,2}\b", text, _re.IGNORECASE)})
    if verbose:
        print(f"  zsystem.list_parmlib found {len(smfprm_members)} SMFPRM* member(s)", flush=True)

    results: list[str] = []
    seen: set[str] = set()
    for member in smfprm_members:
        containing_dsn = "SYS1.PARMLIB"
        try:
            found_text = _coerce_text_output(zsystem.find_parmlib(member)) or ""
            dsn_candidate = found_text.strip().split("(")[0].strip()
            if _re.match(r"^[A-Z#@$][A-Z0-9#@$]{0,7}(\.[A-Z0-9#@$]{1,8})+$", dsn_candidate):
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

_LOGGER_TOKEN_RE = _re.compile(r"\b([A-Z#@$][A-Z0-9#@$]{0,7}(?:\.[A-Z0-9#@$]{1,8}){1,21})\b")
_SMF_IN_TOKEN_RE = _re.compile(r"(?:^|\.)SMF(?:\.|$|[0-9A-Z])", _re.IGNORECASE)


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
    for name in _LOGGER_TOKEN_RE.findall(output):
        if _SMF_IN_TOKEN_RE.search(name) and name not in seen:
            seen.add(name)
            found.append(name)
    if verbose:
        print(f"  D LOGGER,L found {len(found)} SMF logstream candidate(s)", flush=True)
    return found


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
    1.  D SMF,O  — active write-target dataset(s) + PARMLIB member for all configured names.
    2.  D SMF,D  — all dataset statuses (ACTIVE, ALTERNATE, FULL, EMPTY).
    3.  pySEAR   — RACF dataset profiles whose names contain MAN or SMF.
    4.  zsystem.search_parmlib — scan active parmlib concatenation for DSNAME/LOGSTREAM tokens.
    5.  D PARMLIB — read active SMFPRMxx from every PARMLIB dataset in the concatenation.
    6.  D IPLINFO — locate SMFPRM suffix via IEASYSxx when D SMF,O does not report it.
    7.  zsystem.list_parmlib — enumerate all SMFPRM* members across the concatenation.
    8.  D LOGGER  — discover SMF logstreams for sites using logstream-based SMF recording.
    9.  Sibling expansion — catalog wildcard derived from any name found above.
    10. Catalog patterns  — explicit or default patterns when all else fails.

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

    # Pre-compute system name for &SYSNAME substitution; shared across all sources.
    _sysname: str | None = None
    try:
        _node = _re.sub(r"[^A-Z0-9#@$]", "", os.uname().nodename.upper())  # type: ignore[attr-defined]
        _sysname = _node or None
    except AttributeError:
        pass
    if not _sysname:
        _sysname = (os.environ.get("SYSNAME") or os.environ.get("_BPXK_SYSNAME") or "").upper() or None

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

        # --- Source 4: zsystem search of parmlib text ---
        zsys_names = _query_zsystem_parmlib_search(verbose=verbose)
        _add(zsys_names, "zsystem.search_parmlib")

        # --- Source 5: full PARMLIB concatenation SMFPRMxx search ---
        parmlib_names = _query_full_parmlib_smfprm(_sysname, verbose=verbose)
        _add(parmlib_names, "D PARMLIB (full concat)")

        # --- Source 6: D IPLINFO → SMFPRM suffix via IEASYSxx ---
        iplinfo_names = _query_iplinfo_smfprm(_sysname, verbose=verbose)
        _add(iplinfo_names, "D IPLINFO")

        # --- Source 7: zsystem.list_parmlib SMFPRM* members ---
        zlist_names = _query_zsystem_all_smfprm_members(_sysname, verbose=verbose)
        _add(zlist_names, "zsystem.list_parmlib")

        # --- Source 8: D LOGGER SMF logstreams ---
        logstream_names = _query_smf_logstreams(verbose=verbose)
        _add(logstream_names, "D LOGGER")

        # --- Source 9: sibling expansion via catalog search ---
        sibling_patterns: list[str] = []
        for name in list(seen):
            # Try both a specific MAN*/SMF* suffix pattern and the broader parent.*
            # wildcard so expansion works regardless of ZOAU's wildcard support level.
            for pat in (_derive_sibling_pattern(name), _derive_sibling_broad_pattern(name)):
                if pat and pat not in sibling_patterns:
                    sibling_patterns.append(pat)

        siblings: list[str] = []
        for pat in sibling_patterns:
            for name in _list_dataset_names(datasets, pat, include_migrated=include_migrated):
                if name not in seen and _MAN_SMF_RE.search(name):
                    siblings.append(name)
        _add(siblings, "Sibling expansion")

        if discovered:
            return discovered

        if sources_out is not None:
            sources_out["D SMF,O + PARMLIB"] = sources_out.get("D SMF,O + PARMLIB", [])

    # --- Source 10: catalog pattern search (fallback or explicit patterns) ---
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
