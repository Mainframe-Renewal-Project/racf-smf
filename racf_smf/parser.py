from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import date, datetime, time, timedelta
import os
from pathlib import Path
import re
import struct
import tempfile
from typing import Any, Iterator, Literal, TypedDict


RecordFormat = Literal["auto", "rdw", "smf", "man"]


class _DecodedFieldPatch(TypedDict, total=False):
    record_type: int
    subtype: int | None
    system_id: str | None
    timestamp: str | None
    event_code: int | None
    event_qualifier: int | None
    user_id: str | None
    group_name: str | None
    terminal_id: str | None
    job_name: str | None
    smf_user_id: str | None
    product_name: str | None
    product_version: str | None
    address_space_user_id: str | None
    address_space_group_name: str | None
    resource_name: str | None
    class_name: str | None
    profile_name: str | None
    authenticated_user_name: str | None
    authenticated_user_registry: str | None
    authenticated_user_host: str | None
    authenticated_user_oid: str | None
    distributed_identity_user_name: str | None
    distributed_identity_registry: str | None
    action_hint: str | None
    initialization_context: dict[str, Any] | None
    compliance_context: dict[str, Any] | None
    compliance_summary: dict[str, Any] | None
    compliance_findings: tuple[dict[str, Any], ...]
    user_id_candidates: tuple[str, ...]
    resource_candidates: tuple[str, ...]
    text_tokens: tuple[str, ...]


class _DecodedFields(TypedDict):
    record_type: int
    subtype: int | None
    system_id: str | None
    timestamp: str | None
    event_code: int | None
    event_qualifier: int | None
    user_id: str | None
    group_name: str | None
    terminal_id: str | None
    job_name: str | None
    smf_user_id: str | None
    product_name: str | None
    product_version: str | None
    address_space_user_id: str | None
    address_space_group_name: str | None
    resource_name: str | None
    class_name: str | None
    profile_name: str | None
    authenticated_user_name: str | None
    authenticated_user_registry: str | None
    authenticated_user_host: str | None
    authenticated_user_oid: str | None
    distributed_identity_user_name: str | None
    distributed_identity_registry: str | None
    action_hint: str | None
    initialization_context: dict[str, Any] | None
    compliance_context: dict[str, Any] | None
    compliance_summary: dict[str, Any] | None
    compliance_findings: tuple[dict[str, Any], ...]
    user_id_candidates: tuple[str, ...]
    resource_candidates: tuple[str, ...]
    text_tokens: tuple[str, ...]


@dataclass(slots=True)
class SmfRecord:
    """Minimal representation of an SMF record."""

    offset: int
    total_length: int
    record_length: int
    record_type: int
    subtype: int | None
    system_id: str | None
    timestamp: str | None
    event_code: int | None
    event_qualifier: int | None
    user_id: str | None
    group_name: str | None
    terminal_id: str | None
    job_name: str | None
    smf_user_id: str | None
    product_name: str | None
    product_version: str | None
    address_space_user_id: str | None
    address_space_group_name: str | None
    resource_name: str | None
    class_name: str | None
    profile_name: str | None
    authenticated_user_name: str | None
    authenticated_user_registry: str | None
    authenticated_user_host: str | None
    authenticated_user_oid: str | None
    distributed_identity_user_name: str | None
    distributed_identity_registry: str | None
    action_hint: str | None
    initialization_context: dict[str, Any] | None
    compliance_context: dict[str, Any] | None
    compliance_summary: dict[str, Any] | None
    compliance_findings: tuple[dict[str, Any], ...]
    user_id_candidates: tuple[str, ...]
    resource_candidates: tuple[str, ...]
    text_tokens: tuple[str, ...]
    tags: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _dataset_name_from_source(source: str | Path) -> str | None:
    value = str(source)
    if value.startswith("mvs://"):
        name = value[len("mvs://") :].strip()
        return name or None

    if value.startswith("//'") and value.endswith("'") and len(value) > 4:
        return value[3:-1]

    return None


def _read_records_from_dataset(dataset_name: str) -> list[bytes]:
    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on z/OS runtime
        raise RuntimeError(
            "ZOAU is required for dataset input. Install zoautil_py or use a local binary file instead."
        ) from exc

    records = datasets.read_as_bytes(dataset_name, records=0)
    if not isinstance(records, list):
        raise RuntimeError(f"Unexpected ZOAU response while reading dataset {dataset_name}")
    return records


def _read_dataset_stream_via_copy(dataset_name: str) -> bytes:
    """Copy a dataset to a temporary USS file and return raw bytes."""

    try:
        from zoautil_py import datasets  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on z/OS runtime
        raise RuntimeError(
            "ZOAU is required for dataset input. Install zoautil_py or use a local binary file instead."
        ) from exc

    fd, temp_name = tempfile.mkstemp(prefix="racf_smf_", suffix=".bin")
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        datasets.copy(dataset_name, str(temp_path), force=True)
        return temp_path.read_bytes()
    finally:
        temp_path.unlink(missing_ok=True)


def _normalize_dataset_record(record: bytes) -> bytes:
    # Some APIs return VB records with the RDW still attached; strip it when present.
    if len(record) >= 4:
        rdw_length = struct.unpack(">H", record[0:2])[0]
        if rdw_length == len(record) and record[2] == 0 and record[3] == 0:
            return record[4:]
    return record


def _iter_records_dataset(records: list[bytes]) -> Iterator[tuple[int, int, bytes]]:
    offset = 0
    for record in records:
        payload = _normalize_dataset_record(record)
        total_length = len(record)
        yield offset, total_length, payload
        offset += total_length


def _decode_system_id(raw: bytes) -> str | None:
    raw = raw.rstrip(b"\x00 ")
    if not raw:
        return None

    # System identifiers are often EBCDIC on z/OS exports.
    for encoding in ("cp1047", "cp037", "latin-1"):
        try:
            return raw.decode(encoding).strip() or None
        except UnicodeDecodeError:
            continue

    return None


def _decode_ebcdic_field(raw: bytes) -> str | None:
    text = _decode_ebcdic_text(raw).strip("\x00 ")
    return text or None


_TEXT_TOKEN_RE = re.compile(r"[A-Z0-9#@$][A-Z0-9#@$._/-]{2,43}")
_ACTION_KEYWORDS = (
    "ADD",
    "ALTER",
    "CONNECT",
    "DEFINE",
    "DELETE",
    "PERMIT",
    "PHRASE",
    "PASSWORD",
    "READ",
    "REMOVE",
    "REVOKE",
    "UPDATE",
)
_TEXT_STOPWORDS = {
    "RACF",
    "SMF",
    "USER",
    "GROUP",
    "DATASET",
    "RESOURCE",
    "ACCESS",
    "SYSTEM",
    "CLASS",
    "READ",
    "UPDATE",
    "ALTER",
    "DELETE",
    "DEFINE",
    "PERMIT",
    "REMOVE",
    "REVOKE",
}

_EVENT_CODE_NAMES = {
    1: "VERIFY",
    8: "ADDSD",
    9: "ADDGROUP",
    10: "ADDUSER",
    11: "ALTDSD",
    12: "ALTGROUP",
    13: "ALTUSER",
    14: "CONNECT",
    15: "DELDSD",
    16: "DELGROUP",
    17: "DELUSER",
    18: "PASSWORD",
    19: "PERMIT",
    20: "RALTER",
    21: "RDEFINE",
    22: "RDELETE",
    23: "REMOVE",
    24: "SETROPTS",
    25: "RVARY",
    28: "DIRECTORY_SEARCH",
    29: "CHECK_DIRECTORY_ACCESS",
    30: "CHECK_FILE_ACCESS",
    31: "CHAUDIT",
    32: "CHDIR",
    33: "CHMOD",
    34: "CHOWN",
    41: "LINK",
    42: "MKDIR",
    44: "MOUNT",
    45: "OPEN_NEW_FILE",
    47: "RENAME",
    48: "RMDIR",
    53: "SYMLINK",
    54: "UNLINK",
    55: "UNMOUNT",
    57: "CK_PRIV",
    75: "SET_FILE_ACL",
    76: "REMOVE_FILE_ACL",
}


def _decode_ebcdic_text(raw: bytes) -> str:
    for encoding in ("cp1047", "cp037"):
        try:
            return raw.decode(encoding, errors="ignore")
        except LookupError:
            continue
    return raw.decode("latin-1", errors="ignore")


_FIXED_IDENTIFIER_RE = re.compile(r"[A-Z0-9#@$._/-]{1,8}")


def _decode_fixed_identifier(raw: bytes) -> str | None:
    text = (_decode_ebcdic_field(raw) or "").replace("\x00", "").strip().upper()
    if not text or not _FIXED_IDENTIFIER_RE.fullmatch(text):
        return None
    return text


def _packed_decimal_digits(raw: bytes) -> str | None:
    if len(raw) != 4:
        return None
    nibbles: list[int] = []
    for byte in raw:
        nibbles.append((byte >> 4) & 0x0F)
        nibbles.append(byte & 0x0F)
    if nibbles[-1] not in (0x0F, 0x0C, 0x0D):
        return None
    digits = "".join(str(n) for n in nibbles[:-1])
    return digits if digits.isdigit() else None


def _decode_smf_timestamp(payload: bytes, *, time_offset: int = 5, date_offset: int = 9) -> str | None:
    if len(payload) < max(time_offset + 4, date_offset + 4):
        return None

    hundredths = struct.unpack(">I", payload[time_offset : time_offset + 4])[0]
    date_digits = _packed_decimal_digits(payload[date_offset : date_offset + 4])
    if date_digits is None or len(date_digits) != 7:
        return None

    # SMF common header date is packed as 0cyydddF.
    century_code = int(date_digits[1])
    yy = int(date_digits[2:4])
    day_of_year = int(date_digits[4:7])
    year = 1900 + (century_code * 100) + yy
    try:
        day = date(year, 1, 1) + timedelta(days=day_of_year - 1)
    except ValueError:
        return None

    seconds_total, centiseconds = divmod(hundredths, 100)
    hours, rem = divmod(seconds_total, 3600)
    minutes, seconds = divmod(rem, 60)
    if hours >= 24:
        return None
    stamp = datetime.combine(day, time(hour=hours, minute=minutes, second=seconds, microsecond=centiseconds * 10000))
    return stamp.isoformat(timespec="milliseconds")


def _unique_preserve_order(values: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return tuple(ordered)


def _decode_racf_hints(payload: bytes, system_id: str | None) -> tuple[str | None, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    text = _decode_ebcdic_text(payload).upper()
    tokens = _unique_preserve_order(_TEXT_TOKEN_RE.findall(text))

    action_hint = next((token for token in tokens if token in _ACTION_KEYWORDS), None)

    user_candidates = [
        token
        for token in tokens
        if len(token) <= 8
        and "." not in token
        and "/" not in token
        and token != (system_id or "")
        and token not in _TEXT_STOPWORDS
    ]
    resource_candidates = [
        token
        for token in tokens
        if ("." in token or "/" in token or len(token) > 8)
        and token not in _TEXT_STOPWORDS
    ]

    return (
        action_hint,
        _unique_preserve_order(user_candidates[:10]),
        _unique_preserve_order(resource_candidates[:10]),
        tokens[:20],
    )


def _u16(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return struct.unpack(">H", data[offset : offset + 2])[0]


def _u32(data: bytes, offset: int) -> int | None:
    if offset + 4 > len(data):
        return None
    return struct.unpack(">I", data[offset : offset + 4])[0]


_TYPE80_LAYOUTS = (
    {
        "system": 13,
        "time": 5,
        "date": 9,
        "event": 19,
        "qualifier": 20,
        "user": 21,
        "group": 29,
        "terminal": 45,
        "job": 53,
        "smf_user": 69,
    },
    {
        "system": 10,
        "time": 2,
        "date": 6,
        "event": 16,
        "qualifier": 17,
        "user": 18,
        "group": 26,
        "terminal": 42,
        "job": 50,
        "smf_user": 66,
    },
)


def _decode_type80_layout(payload: bytes, layout: dict[str, int]) -> _DecodedFieldPatch:
    event_offset = layout["event"]
    qualifier_offset = layout["qualifier"]
    event_code = payload[event_offset] if len(payload) > event_offset else None
    event_qualifier = payload[qualifier_offset] if len(payload) > qualifier_offset else None
    system_offset = layout["system"]
    user_offset = layout["user"]
    group_offset = layout["group"]
    terminal_offset = layout["terminal"]
    job_offset = layout["job"]
    smf_user_offset = layout["smf_user"]
    system_id = _decode_system_id(payload[system_offset : system_offset + 4]) if len(payload) >= system_offset + 4 else None
    timestamp = _decode_smf_timestamp(payload, time_offset=layout["time"], date_offset=layout["date"])
    user_id = _decode_fixed_identifier(payload[user_offset : user_offset + 8]) if len(payload) >= user_offset + 8 else None
    group_name = _decode_fixed_identifier(payload[group_offset : group_offset + 8]) if len(payload) >= group_offset + 8 else None
    terminal_id = _decode_fixed_identifier(payload[terminal_offset : terminal_offset + 8]) if len(payload) >= terminal_offset + 8 else None
    job_name = _decode_fixed_identifier(payload[job_offset : job_offset + 8]) if len(payload) >= job_offset + 8 else None
    smf_user_id = _decode_fixed_identifier(payload[smf_user_offset : smf_user_offset + 8]) if len(payload) >= smf_user_offset + 8 else None
    action_hint = _EVENT_CODE_NAMES.get(event_code) if event_code is not None else None

    hints_action, user_candidates, resource_candidates, text_tokens = _decode_racf_hints(payload, None)
    if action_hint is None:
        action_hint = hints_action

    if user_id:
        user_candidates = _unique_preserve_order([user_id, *user_candidates])

    return {
        "subtype": None,
        "system_id": system_id,
        "timestamp": timestamp,
        "event_code": event_code,
        "event_qualifier": event_qualifier,
        "user_id": user_id,
        "group_name": group_name,
        "terminal_id": terminal_id,
        "job_name": job_name,
        "smf_user_id": smf_user_id,
        "action_hint": action_hint,
        "user_id_candidates": user_candidates,
        "resource_candidates": resource_candidates,
        "text_tokens": text_tokens,
    }


def _score_type80_layout(fields: _DecodedFieldPatch) -> int:
    score = 0
    event_code = fields.get("event_code")
    if event_code in _EVENT_CODE_NAMES:
        score += 4
    elif isinstance(event_code, int) and 0 < event_code < 128:
        score += 2
    if fields.get("event_qualifier") is not None:
        score += 1
    if fields.get("system_id"):
        score += 2
    if fields.get("timestamp"):
        score += 2
    for name in ("user_id", "group_name", "terminal_id", "job_name", "smf_user_id"):
        if fields.get(name):
            score += 2
    return score


def _decode_type80_fields(payload: bytes) -> _DecodedFieldPatch:
    decoded_layouts = [_decode_type80_layout(payload, layout) for layout in _TYPE80_LAYOUTS]
    return max(decoded_layouts, key=_score_type80_layout)


def _decode_bit_options(value: int | None, labels: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(label for index, label in enumerate(labels) if value & (0x80 >> index))


_TYPE81_LAYOUTS = (
    {
        "system": 14,
        "time": 6,
        "date": 10,
        "racf_database": 18,
        "racf_database_volume": 62,
        "racf_database_unit": 68,
        "uads_dataset": 71,
        "uads_volume": 115,
        "options": 121,
        "options2": 122,
        "options3": 123,
        "audit_options": 124,
        "audit_options2": 125,
        "terminal_options": 126,
        "password_interval": 127,
        "relocate_offset": 128,
        "relocate_count": 130,
        "version_indicator": 132,
        "single_level_dataset_name": 133,
        "options4": 141,
        "options5": 142,
        "retention_period": 143,
        "erase_security_level": 145,
        "audit_security_level": 146,
        "racf_fmid": 147,
        "setropts_options": 151,
        "partner_lu_key_interval": 152,
        "jes_nje_user_id": 154,
        "jes_undefined_user_id": 162,
        "setropts_extensions": 170,
        "primary_language": 171,
        "secondary_language": 172,
        "kerb_level": 177,
        "password_minimum_days": 178,
        "options6": 179,
        "mls_options2": 180,
        "password_algorithm": 181,
        "vmxevent_control_profile": 182,
        "vmxevent_audit_profile": 190,
        "password_phrase_interval": 198,
    },
    {
        "system": 10,
        "time": 2,
        "date": 6,
        "racf_database": 14,
        "racf_database_volume": 58,
        "racf_database_unit": 64,
        "uads_dataset": 67,
        "uads_volume": 111,
        "options": 117,
        "options2": 118,
        "options3": 119,
        "audit_options": 120,
        "audit_options2": 121,
        "terminal_options": 122,
        "password_interval": 123,
        "relocate_offset": 124,
        "relocate_count": 126,
        "version_indicator": 128,
        "single_level_dataset_name": 129,
        "options4": 137,
        "options5": 138,
        "retention_period": 139,
        "erase_security_level": 141,
        "audit_security_level": 142,
        "racf_fmid": 143,
        "setropts_options": 147,
        "partner_lu_key_interval": 148,
        "jes_nje_user_id": 150,
        "jes_undefined_user_id": 158,
        "setropts_extensions": 166,
        "primary_language": 167,
        "secondary_language": 168,
        "kerb_level": 173,
        "password_minimum_days": 174,
        "options6": 175,
        "mls_options2": 176,
        "password_algorithm": 177,
        "vmxevent_control_profile": 178,
        "vmxevent_audit_profile": 186,
        "password_phrase_interval": 194,
    },
)


def _field(data: bytes, offset: int, length: int) -> str | None:
    return _decode_ebcdic_field(data[offset : offset + length]) if offset + length <= len(data) else None


def _byte(data: bytes, offset: int) -> int | None:
    return data[offset] if offset < len(data) else None


def _decode_type81_layout(payload: bytes, layout: dict[str, int]) -> _DecodedFieldPatch:
    options = _byte(payload, layout["options"])
    options2 = _byte(payload, layout["options2"])
    options3 = _byte(payload, layout["options3"])
    audit_options = _byte(payload, layout["audit_options"])
    audit_options2 = _byte(payload, layout["audit_options2"])
    terminal_options = _byte(payload, layout["terminal_options"])
    options4 = _byte(payload, layout["options4"])
    options5 = _byte(payload, layout["options5"])
    setropts_options = _byte(payload, layout["setropts_options"])
    setropts_extensions = _byte(payload, layout["setropts_extensions"])
    options6 = _byte(payload, layout["options6"])
    mls_options2 = _byte(payload, layout["mls_options2"])
    password_algorithm = _byte(payload, layout["password_algorithm"])

    context: dict[str, Any] = {
        "racf_database": _field(payload, layout["racf_database"], 44),
        "racf_database_volume": _field(payload, layout["racf_database_volume"], 6),
        "racf_database_unit": _field(payload, layout["racf_database_unit"], 3),
        "uads_dataset": _field(payload, layout["uads_dataset"], 44),
        "uads_volume": _field(payload, layout["uads_volume"], 6),
        "options": _decode_bit_options(options, (
            "NO_VERIFY_STATISTICS", "NO_DATASET_STATISTICS", "VERIFY_PREPROCESSING_EXIT",
            "AUTH_PREPROCESSING_EXIT", "DEFINE_PREPROCESSING_EXIT", "VERIFY_POSTPROCESSING_EXIT",
            "AUTH_POSTPROCESSING_EXIT", "NEW_PASSWORD_EXIT",
        )),
        "options2": _decode_bit_options(options2, (
            "NO_TAPE_VOLUME_STATISTICS", "NO_DASD_VOLUME_STATISTICS", "NO_TERMINAL_STATISTICS",
            "COMMAND_EXIT_ICHCNX00", "COMMAND_EXIT_ICHCCX00", "ADSP_NOT_ACTIVE",
            "ENCRYPTION_EXIT", "NAMING_CONVENTION_TABLE",
        )),
        "options3": _decode_bit_options(options3, (
            "TAPE_VOLUME_PROTECTION", "NO_DUPLICATE_DATASET_NAMES", "DASD_VOLUME_PROTECTION",
            "HAS_VERSION_INDICATOR", "FASTAUTH_PREPROCESSING_EXIT", "LIST_PRE_POST_EXIT",
            "LIST_SELECTION_EXIT", "DEFINE_POSTPROCESSING_EXIT",
        )),
        "audit_options": _decode_bit_options(audit_options, (
            "USER_PROFILE_CHANGES", "GROUP_PROFILE_CHANGES", "DATASET_PROFILE_CHANGES",
            "TAPE_VOLUME_PROFILE_CHANGES", "DASD_VOLUME_PROFILE_CHANGES", "TERMINAL_PROFILE_CHANGES",
            "COMMAND_VIOLATIONS", "SPECIAL_USER_ACTIVITY",
        )),
        "audit_options2": _decode_bit_options(audit_options2, ("OPERATIONS_USER_ACTIVITY", "SECLEVEL_AUDIT", "RESERVED_2", "RESERVED_3", "RESERVED_4", "RESERVED_5", "RESERVED_6", "RESERVED_7")),
        "terminal_options": _decode_bit_options(terminal_options, (
            "TERMINAL_AUTH_CHECKING", "UNDEFINED_TERMINAL_UACC_NONE", "REALDSN", "JES_XBMALLRACF",
            "JES_EARLYVERIFY", "JES_BATCHALLRACF", "FASTAUTH_POSTPROCESSING_EXIT", "RESERVED_7",
        )),
        "password_interval": _byte(payload, layout["password_interval"]),
        "relocate_offset": _u16(payload, layout["relocate_offset"]),
        "relocate_count": _u16(payload, layout["relocate_count"]),
        "version_indicator": _byte(payload, layout["version_indicator"]),
        "single_level_dataset_name": _field(payload, layout["single_level_dataset_name"], 8),
        "options4": _decode_bit_options(options4, (
            "TAPEDSN", "PROTECTALL", "PROTECTALL_WARNING", "ERASE_ON_SCRATCH",
            "ERASE_ON_SCRATCH_SECLEVEL", "ERASE_ON_SCRATCH_ALL", "ENHANCED_GENERIC_NAMING", "HAS_VRM",
        )),
        "options5": _decode_bit_options(options5, (
            "PROGRAM_CONTROL", "ACEE_COMPRESSION_EXIT", "FASTAUTH_POSTPROCESSING_EXIT_4",
            "FASTAUTH_PREPROCESSING_EXIT_3", "NOADDCREATOR", "IRREVX01_EXIT",
            "RESERVED_6", "RESERVED_7",
        )),
        "retention_period": _u16(payload, layout["retention_period"]),
        "erase_security_level": _byte(payload, layout["erase_security_level"]),
        "audit_security_level": _byte(payload, layout["audit_security_level"]),
        "racf_fmid": _field(payload, layout["racf_fmid"], 4),
        "setropts_options": _decode_bit_options(setropts_options, (
            "SECLABELCONTROL", "CATDSNS", "MLQUIET", "MLSTABLE", "MLS", "MLACTIVE",
            "GENERICOWNER", "SECLABELAUDIT",
        )),
        "partner_lu_key_interval": _u16(payload, layout["partner_lu_key_interval"]),
        "jes_nje_user_id": _field(payload, layout["jes_nje_user_id"], 8),
        "jes_undefined_user_id": _field(payload, layout["jes_undefined_user_id"], 8),
        "setropts_extensions": _decode_bit_options(setropts_extensions, (
            "COMPATMODE", "CATDSNS_FAILURES", "MLS_FAILURES", "MLACTIVE_FAILURES", "APPLAUDIT",
            "INSTALLATION_RVARY_SWITCH_PASSWORD", "INSTALLATION_RVARY_STATUS_PASSWORD", "ENHANCEDGENERICOWNER",
        )),
        "primary_language": _field(payload, layout["primary_language"], 3),
        "secondary_language": _field(payload, layout["secondary_language"], 3),
        "kerb_segment_level": _byte(payload, layout["kerb_level"]),
        "password_minimum_days": _byte(payload, layout["password_minimum_days"]),
        "options6": _decode_bit_options(options6, (
            "MIXED_CASE_PASSWORDS", "PASSWORD_PHRASE_EXIT", "CUSTOM_FIELD_VALIDATION_EXIT",
            "SPECIAL_PASSWORD_CHARACTERS", "RESERVED_4", "RESERVED_5", "RESERVED_6", "RESERVED_7",
        )),
        "mls_options2": _decode_bit_options(mls_options2, ("MLFSOBJ", "MLIPCOBJ", "MLNAMES", "SECLBYSYSTEM", "RESERVED_4", "RESERVED_5", "RESERVED_6", "RESERVED_7")),
        "password_algorithm": None if password_algorithm is None else {0: "LEGACY", 1: "KDFAES"}.get(password_algorithm, f"UNKNOWN({password_algorithm})"),
        "vmxevent_control_profile": _field(payload, layout["vmxevent_control_profile"], 8),
        "vmxevent_audit_profile": _field(payload, layout["vmxevent_audit_profile"], 8),
        "password_phrase_interval": _u16(payload, layout["password_phrase_interval"]),
    }
    return {
        "subtype": None,
        "system_id": _decode_system_id(payload[layout["system"] : layout["system"] + 4]) if layout["system"] + 4 <= len(payload) else None,
        "timestamp": _decode_smf_timestamp(payload, time_offset=layout["time"], date_offset=layout["date"]),
        "product_name": "RACF",
        "action_hint": "RACF_INITIALIZATION",
        "initialization_context": context,
        "resource_candidates": _unique_preserve_order([value for value in (context["racf_database"], context["uads_dataset"]) if isinstance(value, str)]),
        "text_tokens": _unique_preserve_order([value for value in (context["racf_database"], context["uads_dataset"], context["racf_fmid"]) if isinstance(value, str)]),
    }


def _score_type81_layout(fields: _DecodedFieldPatch) -> int:
    context = fields.get("initialization_context") or {}
    score = 0
    if fields.get("system_id"):
        score += 2
    if fields.get("timestamp"):
        score += 2
    for name in ("racf_database", "uads_dataset", "racf_fmid"):
        if context.get(name):
            score += 2
    return score


def _decode_type81_fields(payload: bytes) -> _DecodedFieldPatch:
    decoded_layouts = [_decode_type81_layout(payload, layout) for layout in _TYPE81_LAYOUTS]
    return max(decoded_layouts, key=_score_type81_layout)


def _record_type_from_payload(payload: bytes, fallback: int) -> int:
    if len(payload) > 5 and payload[5] == 81:
        return 81
    return fallback


def _parse_type83_standard_relocates(data: bytes, start: int) -> dict[str, str | None]:
    resource_name: str | None = None
    class_name: str | None = None
    profile_name: str | None = None
    cursor = start
    while cursor + 2 <= len(data):
        data_type = data[cursor]
        data_len = data[cursor + 1]
        cursor += 2
        end = cursor + data_len
        if end > len(data):
            break
        value = data[cursor:end]
        text = _decode_ebcdic_field(value)
        if data_type in (1, 9, 62) and text and resource_name is None:
            resource_name = text
        elif data_type in (17, 26) and text and class_name is None:
            class_name = text
        elif data_type in (33, 38) and text and profile_name is None:
            profile_name = text
        cursor = end
    return {
        "resource_name": resource_name,
        "class_name": class_name,
        "profile_name": profile_name,
    }


def _parse_type83_extended_relocates(data: bytes, start: int) -> dict[str, str | None]:
    fields: dict[str, str | None] = {
        "resource_name": None,
        "class_name": None,
        "profile_name": None,
        "authenticated_user_name": None,
        "authenticated_user_registry": None,
        "authenticated_user_host": None,
        "authenticated_user_oid": None,
        "distributed_identity_user_name": None,
        "distributed_identity_registry": None,
    }
    cursor = start
    while cursor + 4 <= len(data):
        data_type = _u16(data, cursor)
        data_len = _u16(data, cursor + 2)
        if data_type is None or data_len is None:
            break
        cursor += 4
        end = cursor + data_len
        if end > len(data):
            break
        value = data[cursor:end]
        if data_type == 3:
            fields["resource_name"] = fields["resource_name"] or _decode_ebcdic_field(value)
        elif data_type == 4:
            fields["class_name"] = fields["class_name"] or _decode_ebcdic_field(value)
        elif data_type == 5:
            fields["profile_name"] = fields["profile_name"] or _decode_ebcdic_field(value)
        elif data_type == 10:
            fields["authenticated_user_name"] = fields["authenticated_user_name"] or _decode_ebcdic_field(value)
        elif data_type == 11:
            fields["authenticated_user_registry"] = fields["authenticated_user_registry"] or _decode_ebcdic_field(value)
        elif data_type == 12:
            fields["authenticated_user_host"] = fields["authenticated_user_host"] or _decode_ebcdic_field(value)
        elif data_type == 13:
            fields["authenticated_user_oid"] = fields["authenticated_user_oid"] or _decode_ebcdic_field(value)
        elif data_type == 14:
            try:
                fields["distributed_identity_user_name"] = fields["distributed_identity_user_name"] or value.decode("utf-8", errors="ignore").strip("\x00 ") or None
            except UnicodeDecodeError:
                pass
        elif data_type == 15:
            try:
                fields["distributed_identity_registry"] = fields["distributed_identity_registry"] or value.decode("utf-8", errors="ignore").strip("\x00 ") or None
            except UnicodeDecodeError:
                pass
        cursor = end
    return fields


def _decode_type83_fields(payload: bytes) -> _DecodedFieldPatch:
    subtype = _u16(payload, 21)
    product_offset = _u32(payload, 27)
    security_offset = _u32(payload, 35)
    relocate_offset = _u32(payload, 43)

    product_name: str | None = None
    product_version: str | None = None
    if product_offset is not None and product_offset + 8 <= len(payload):
        product_version = _decode_ebcdic_field(payload[product_offset : product_offset + 4])
        product_name = _decode_ebcdic_field(payload[product_offset + 4 : product_offset + 8])

    event_code: int | None = None
    event_qualifier: int | None = None
    user_id: str | None = None
    group_name: str | None = None
    terminal_id: str | None = None
    job_name: str | None = None
    smf_user_id: str | None = None
    address_space_user_id: str | None = None
    address_space_group_name: str | None = None
    if security_offset is not None and security_offset + 72 <= len(payload):
        event_code = payload[security_offset + 6]
        event_qualifier = payload[security_offset + 7]
        user_id = _decode_ebcdic_field(payload[security_offset + 8 : security_offset + 16])
        group_name = _decode_ebcdic_field(payload[security_offset + 16 : security_offset + 24])
        terminal_id = _decode_ebcdic_field(payload[security_offset + 32 : security_offset + 40])
        job_name = _decode_ebcdic_field(payload[security_offset + 40 : security_offset + 48])
        smf_user_id = _decode_ebcdic_field(payload[security_offset + 56 : security_offset + 64])
        if subtype is not None and subtype >= 2 and security_offset + 96 <= len(payload):
            address_space_user_id = _decode_ebcdic_field(payload[security_offset + 80 : security_offset + 88])
            address_space_group_name = _decode_ebcdic_field(payload[security_offset + 88 : security_offset + 96])

    reloc_fields: dict[str, str | None] = {
        "resource_name": None,
        "class_name": None,
        "profile_name": None,
        "authenticated_user_name": None,
        "authenticated_user_registry": None,
        "authenticated_user_host": None,
        "authenticated_user_oid": None,
        "distributed_identity_user_name": None,
        "distributed_identity_registry": None,
    }
    if relocate_offset is not None and relocate_offset < len(payload):
        if subtype == 1:
            reloc_fields.update(_parse_type83_standard_relocates(payload, relocate_offset))
        elif subtype is not None and subtype >= 2:
            reloc_fields.update(_parse_type83_extended_relocates(payload, relocate_offset))

    action_hint = _EVENT_CODE_NAMES.get(event_code) if event_code is not None else None
    user_candidates = _unique_preserve_order([v for v in (user_id, smf_user_id, address_space_user_id) if v])
    resource_candidates = _unique_preserve_order([v for v in (reloc_fields["resource_name"], reloc_fields["profile_name"]) if v])
    text_tokens = tuple(v for v in (
        reloc_fields["resource_name"],
        reloc_fields["class_name"],
        reloc_fields["profile_name"],
        reloc_fields["authenticated_user_name"],
        reloc_fields["distributed_identity_user_name"],
    ) if v)

    return {
        "subtype": subtype,
        "event_code": event_code,
        "event_qualifier": event_qualifier,
        "user_id": user_id,
        "group_name": group_name,
        "terminal_id": terminal_id,
        "job_name": job_name,
        "smf_user_id": smf_user_id,
        "product_name": product_name,
        "product_version": product_version,
        "address_space_user_id": address_space_user_id,
        "address_space_group_name": address_space_group_name,
        "resource_name": reloc_fields["resource_name"],
        "class_name": reloc_fields["class_name"],
        "profile_name": reloc_fields["profile_name"],
        "authenticated_user_name": reloc_fields["authenticated_user_name"],
        "authenticated_user_registry": reloc_fields["authenticated_user_registry"],
        "authenticated_user_host": reloc_fields["authenticated_user_host"],
        "authenticated_user_oid": reloc_fields["authenticated_user_oid"],
        "distributed_identity_user_name": reloc_fields["distributed_identity_user_name"],
        "distributed_identity_registry": reloc_fields["distributed_identity_registry"],
        "action_hint": action_hint,
        "user_id_candidates": user_candidates,
        "resource_candidates": resource_candidates,
        "text_tokens": text_tokens,
    }


def _decode_status(value: int | None, labels: dict[int, str]) -> str | None:
    if value is None:
        return None
    return labels.get(value, f"UNKNOWN({value})")


def _u8(data: bytes, offset: int) -> int | None:
    if offset >= len(data):
        return None
    return data[offset]


def _record_offset_candidates(offset: int) -> tuple[int, ...]:
    return (offset, offset - 4) if offset >= 4 else (offset,)


_TYPE92_SUBTYPE_NAMES = {
    1: "ZOS_UNIX_FILE_SYSTEM_MOUNT",
    2: "ZOS_UNIX_FILE_SYSTEM_QUIESCE",
    4: "ZOS_UNIX_FILE_SYSTEM_UNQUIESCE",
    5: "ZOS_UNIX_FILE_SYSTEM_UNMOUNT",
    6: "ZOS_UNIX_FILE_SYSTEM_REMOUNT",
    7: "ZOS_UNIX_FILE_SYSTEM_MOVE",
    8: "ZOS_UNIX_FILE_SYSTEM_MIGRATION",
    10: "ZOS_UNIX_FILE_OPEN",
    11: "ZOS_UNIX_FILE_CLOSE",
    12: "ZOS_UNIX_MMAP",
    13: "ZOS_UNIX_MUNMAP",
    14: "ZOS_UNIX_FILE_DELETE_OR_RENAME",
    15: "ZOS_UNIX_SECURITY_ATTRIBUTE_CHANGE",
    16: "ZOS_UNIX_SPECIAL_FILE_CLOSE",
    17: "ZOS_UNIX_FILE_ACCESS_COUNT",
    50: "ZOS_UNIX_FILE_SYSTEM_EVENTS",
    51: "ZFS_COUNTS_AND_RESPONSE_TIMES",
    52: "ZFS_USER_FILE_CACHE_STATISTICS",
    53: "ZFS_METADATA_CACHE_STATISTICS",
    54: "ZFS_LOCKING_AND_SLEEP_STATISTICS",
    55: "ZFS_GENERAL_IO_STATISTICS",
    56: "ZFS_TOKEN_MANAGER_INFORMATION",
    57: "ZFS_MEMORY_USAGE",
    58: "ZFS_TRANSMIT_AND_RECEIVE_STATISTICS",
    59: "ZFS_PER_FILE_SYSTEM_USAGE",
}


def _type92_layout_candidates(payload: bytes) -> tuple[dict[str, int], ...]:
    return (
        {"adjust": 0, "record_type": 5, "time": 6, "date": 10, "system": 14, "subsystem": 18, "subtype": 22, "sdl": 26, "triplets": 28},
        {"adjust": -4, "record_type": 1, "time": 2, "date": 6, "system": 10, "subsystem": 14, "subtype": 18, "sdl": 22, "triplets": 24},
    )


def _self_defining_triplet(payload: bytes, start: int) -> tuple[int | None, int | None, int | None]:
    return _u32(payload, start), _u16(payload, start + 4), _u16(payload, start + 6)


def _section_start(payload: bytes, record_offset: int | None, adjust: int) -> int | None:
    if record_offset is None:
        return None
    for candidate in (record_offset + adjust, record_offset):
        if 0 <= candidate < len(payload):
            return candidate
    return None


def _looks_like_type92_layout(payload: bytes, layout: dict[str, int]) -> bool:
    if layout["record_type"] >= len(payload) or payload[layout["record_type"]] != 92:
        return False
    if layout["triplets"] + 24 > len(payload):
        return False
    sdl = _u16(payload, layout["sdl"])
    if sdl is None or sdl < 24 or sdl > 256:
        return False
    for triplet_start in (layout["triplets"], layout["triplets"] + 8, layout["triplets"] + 16):
        section_offset, section_length, section_count = _self_defining_triplet(payload, triplet_start)
        if section_offset is None or section_length is None or section_count is None:
            return False
        if section_count and section_length == 0:
            return False
        section_start = _section_start(payload, section_offset, layout["adjust"])
        if section_count and (section_start is None or section_start + section_length > len(payload)):
            return False
    return True


def _find_type92_layout(payload: bytes) -> dict[str, int] | None:
    for layout in _type92_layout_candidates(payload):
        if _looks_like_type92_layout(payload, layout):
            return layout
    return None


def _decode_type92_fields(payload: bytes) -> _DecodedFieldPatch:
    layout = _find_type92_layout(payload)
    if layout is None:
        return {}

    subsystem_offset, subsystem_length, subsystem_count = _self_defining_triplet(payload, layout["triplets"])
    identity_offset, identity_length, identity_count = _self_defining_triplet(payload, layout["triplets"] + 8)
    data_offset, data_length, data_count = _self_defining_triplet(payload, layout["triplets"] + 16)

    subsystem_start = _section_start(payload, subsystem_offset, layout["adjust"])
    identity_start = _section_start(payload, identity_offset, layout["adjust"])

    subtype = _u16(payload, layout["subtype"])
    product_name: str | None = None
    product_version: str | None = None
    if subsystem_start is not None and subsystem_count and subsystem_length and subsystem_length >= 20:
        product_name = _decode_ebcdic_field(payload[subsystem_start + 4 : subsystem_start + 12])
        product_version = _decode_ebcdic_field(payload[subsystem_start + 12 : subsystem_start + 20])

    job_name: str | None = None
    group_name: str | None = None
    user_id: str | None = None
    if identity_start is not None and identity_count and identity_length and identity_length >= 40:
        job_name = _decode_fixed_identifier(payload[identity_start : identity_start + 8])
        group_name = _decode_fixed_identifier(payload[identity_start + 24 : identity_start + 32])
        user_id = _decode_fixed_identifier(payload[identity_start + 32 : identity_start + 40])

    action_hint = _TYPE92_SUBTYPE_NAMES.get(subtype, f"ZOS_UNIX_TYPE92_SUBTYPE_{subtype}" if subtype is not None else "ZOS_UNIX_TYPE92")
    text_tokens = _unique_preserve_order([value for value in (product_name, product_version, action_hint) if value])

    return {
        "subtype": subtype,
        "system_id": _decode_system_id(payload[layout["system"] : layout["system"] + 4]) if layout["system"] + 4 <= len(payload) else None,
        "timestamp": _decode_smf_timestamp(payload, time_offset=layout["time"], date_offset=layout["date"]),
        "user_id": user_id,
        "group_name": group_name,
        "job_name": job_name,
        "product_name": product_name or "ZOS_UNIX",
        "product_version": product_version,
        "action_hint": action_hint,
        "user_id_candidates": _unique_preserve_order([user_id] if user_id else []),
        "text_tokens": text_tokens,
    }


def _find_extended_1154_header(payload: bytes) -> dict[str, int] | None:
    for adjust in (0, -4):
        rty_offset = 5 + adjust
        subtype_offset = 22 + adjust
        version_offset = 26 + adjust
        ext_type_offset = 52 + adjust
        if min(rty_offset, subtype_offset, version_offset, ext_type_offset) < 0:
            continue
        if ext_type_offset + 2 > len(payload):
            continue
        if payload[rty_offset] != 126:
            continue
        extended_type = _u16(payload, ext_type_offset)
        subtype = _u16(payload, subtype_offset)
        version = payload[version_offset]
        if extended_type == 1154 and subtype == 83 and version in (1, 2):
            return {
                "adjust": adjust,
                "header_end": (56 if version == 1 else 92) + adjust,
                "subtype": subtype,
                "system": 14 + adjust,
                "time": 6 + adjust,
                "date": 10 + adjust,
            }
    return None


def _payload_offset_from_record_offset(record_offset: int, adjust: int, payload_len: int) -> int | None:
    offset = record_offset + adjust
    if 0 <= offset < payload_len:
        return offset
    return None


def _decode_1154_common_context(payload: bytes, common_offset: int | None) -> dict[str, Any] | None:
    if common_offset is None or common_offset + 60 > len(payload):
        return None
    return {
        "version": _u16(payload, common_offset),
        "more_records_follow": _u8(payload, common_offset + 2) == 1,
        "sequence_number": _u8(payload, common_offset + 3),
        "system_name": _decode_fixed_identifier(payload[common_offset + 8 : common_offset + 16]),
        "sysplex_name": _decode_fixed_identifier(payload[common_offset + 16 : common_offset + 24]),
        "user_id": _decode_fixed_identifier(payload[common_offset + 24 : common_offset + 32]),
        "job_name": _decode_fixed_identifier(payload[common_offset + 32 : common_offset + 40]),
        "request_id": _decode_ebcdic_field(payload[common_offset + 40 : common_offset + 56]),
        "correlator": _u32(payload, common_offset + 56),
    }


def _decode_racf_admin_audit(value: int | None) -> tuple[str, ...]:
    if value is None:
        return ()
    names = (
        (0x01, "SAUDIT"),
        (0x02, "CMDVIOL"),
        (0x04, "OPERAUDIT"),
    )
    return tuple(name for bit, name in names if value & bit)


def _decode_1154_summary(section: bytes) -> dict[str, Any]:
    password_rules: list[dict[str, Any]] = []
    if len(section) >= 108:
        for index in range(8):
            offset = 28 + (index * 10)
            min_length = section[offset]
            rule = _decode_ebcdic_field(section[offset + 1 : offset + 9])
            max_length = section[offset + 9]
            if rule:
                password_rules.append({"minimum_length": min_length, "rule": rule, "maximum_length": max_length})

    return {
        "version": _u16(section, 0),
        "eye_catcher": _decode_ebcdic_field(section[4:8]) if len(section) >= 8 else None,
        "racf_fmid": _decode_ebcdic_field(section[8:12]) if len(section) >= 12 else None,
        "racf_status": _decode_status(_u8(section, 19), {0: "ACTIVE", 1: "FAILSOFT"}) if _u8(section, 18) == 1 else None,
        "statistics_bypassed": _decode_status(_u8(section, 21), {0: "NO", 1: "YES"}) if _u8(section, 20) == 1 else None,
        "default_ibmuser_revoked": _decode_status(_u8(section, 23), {0: "NO", 1: "YES"}) if _u8(section, 22) == 1 else None,
        "administrator_audit_options": _decode_racf_admin_audit(_u8(section, 25)) if _u8(section, 24) == 1 else (),
        "password_rules": tuple(password_rules),
        "lowercase_passwords_allowed": _decode_status(_u8(section, 109), {0: "NO", 1: "YES"}) if _u8(section, 108) == 1 else None,
        "special_password_chars_allowed": _decode_status(_u8(section, 111), {0: "NO", 1: "YES"}) if _u8(section, 110) == 1 else None,
        "password_exit_configured": _decode_status(_u8(section, 115), {0: "NO", 1: "YES"}) if _u8(section, 114) == 1 else None,
        "password_interval": _u8(section, 117) if _u8(section, 116) == 1 else None,
        "password_minimum_lifetime": _u8(section, 119) if _u8(section, 118) == 1 else None,
        "password_history_count": _u8(section, 121) if _u8(section, 120) == 1 else None,
        "maximum_failed_password_attempts": _u8(section, 123) if _u8(section, 122) == 1 else None,
        "maximum_password_inactivity_days": _u8(section, 125) if _u8(section, 124) == 1 else None,
        "default_rvary_switch_password_in_use": _decode_status(_u8(section, 127), {0: "NO", 1: "YES"}) if _u8(section, 126) == 1 else None,
        "default_rvary_status_password_in_use": _decode_status(_u8(section, 129), {0: "NO", 1: "YES"}) if _u8(section, 128) == 1 else None,
        "password_encryption": _decode_status(_u8(section, 131), {0: "LEGACY", 1: "KDFAES"}) if _u8(section, 130) == 1 else None,
        "protectall_fail": _decode_status(_u8(section, 133), {0: "NO", 1: "YES"}) if _u8(section, 132) == 1 else None,
        "dataset_generic_profiles_enabled": _decode_status(_u8(section, 135), {0: "NO", 1: "YES"}) if _u8(section, 134) == 1 else None,
        "catdsns": _decode_status(_u8(section, 137), {0: "NOCATDSNS", 1: "CATDSNS"}) if _u8(section, 136) == 1 else None,
        "erase_all_enabled": _decode_status(_u8(section, 139), {0: "NO", 1: "YES"}) if _u8(section, 138) == 1 else None,
        "aceechk_active": _decode_status(_u8(section, 141), {0: "NO", 1: "YES"}) if _u8(section, 140) == 1 else None,
        "aceechk_raclisted": _decode_status(_u8(section, 143), {0: "NO", 1: "YES"}) if _u8(section, 142) == 1 else None,
        "batchallracf": _decode_status(_u8(section, 145), {0: "NOBATCHALLRACF", 1: "BATCHALLRACF"}) if _u8(section, 144) == 1 else None,
    }


def _decode_1154_profile_finding(section_name: str, data: bytes) -> dict[str, Any]:
    return {
        "section": section_name,
        "resource_name": _decode_ebcdic_field(data[0:246]) if len(data) >= 246 else None,
        "class_name": _decode_fixed_identifier(data[246:254]) if len(data) >= 254 else None,
        "profile_status_known": _u8(data, 254) == 1,
        "profile_exists": _decode_status(_u8(data, 255), {0: "NO", 1: "YES"}) if _u8(data, 254) == 1 else None,
        "uacc": _u8(data, 256),
        "audit": _u8(data, 257),
        "audit_success": _u8(data, 258),
        "audit_failure": _u8(data, 259),
        "gaudit": _u8(data, 260),
        "id_star_on_access_list": _decode_status(_u8(data, 264), {0: "NO", 1: "YES"}) if len(data) > 264 else None,
        "id_star_access": _u8(data, 265),
    }


def _decode_1154_dataset_finding(data: bytes) -> dict[str, Any]:
    return {
        "section": "RACFAPFL_DATASET",
        "dataset_name": _decode_ebcdic_field(data[0:44]) if len(data) >= 44 else None,
        "volume": _decode_ebcdic_field(data[44:50]) if len(data) >= 50 else None,
        "profile_status_known": _u8(data, 50) == 1,
        "profile_exists": _decode_status(_u8(data, 51), {0: "NO", 1: "YES"}) if _u8(data, 50) == 1 else None,
        "uacc": _u8(data, 52),
        "warning": _u8(data, 53),
        "id_star_on_access_list": _decode_status(_u8(data, 54), {0: "NO", 1: "YES"}) if len(data) > 54 else None,
        "id_star_access": _u8(data, 55),
        "dataset_type": _decode_ebcdic_field(data[56:57]) if len(data) >= 57 else None,
    }


def _decode_1154_actl_finding(data: bytes) -> dict[str, Any]:
    return {
        "section": "RACFACTL",
        "module_name": _decode_fixed_identifier(data[0:8]) if len(data) >= 8 else None,
        "authorization_code": _u32(data, 8),
        "in_lpa": _decode_status(_u8(data, 12), {0: "NO", 1: "YES"}) if len(data) > 12 else None,
    }


def _section_offset(payload: bytes, subtype_start: int, section_relative_offset: int | None, adjust: int) -> int | None:
    if section_relative_offset is None:
        return None
    relative = subtype_start + section_relative_offset
    if 0 <= relative < len(payload):
        return relative
    absolute = section_relative_offset + adjust
    if 0 <= absolute < len(payload):
        return absolute
    return None


def _decode_type1154_subtype83_fields(payload: bytes) -> _DecodedFieldPatch:
    header = _find_extended_1154_header(payload)
    if header is None:
        return {}

    adjust = header["adjust"]
    triplets_start = header["header_end"]
    common_offset: int | None = None
    subtype_start: int | None = None
    if triplets_start >= 0 and triplets_start + 20 <= len(payload):
        common_record_offset = _u32(payload, triplets_start + 4)
        subtype_record_offset = _u32(payload, triplets_start + 12)
        if common_record_offset is not None:
            common_offset = _payload_offset_from_record_offset(common_record_offset, adjust, len(payload))
        if subtype_record_offset is not None:
            subtype_start = _payload_offset_from_record_offset(subtype_record_offset, adjust, len(payload))

    context = _decode_1154_common_context(payload, common_offset)
    summary: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = []
    resource_candidates: list[str] = []
    text_tokens: list[str] = []

    if subtype_start is not None and subtype_start + 36 <= len(payload):
        section_defs = (
            ("RACFSMRY", _u32(payload, subtype_start + 4), _u16(payload, subtype_start + 8), _u16(payload, subtype_start + 10)),
            ("RACFCRIT", _u32(payload, subtype_start + 12), _u16(payload, subtype_start + 16), _u16(payload, subtype_start + 18)),
            ("RACFAPFL", _u32(payload, subtype_start + 20), _u16(payload, subtype_start + 24), _u16(payload, subtype_start + 26)),
            ("RACFACTL", _u32(payload, subtype_start + 28), _u16(payload, subtype_start + 32), _u16(payload, subtype_start + 34)),
        )
        for section_name, section_offset, section_length, section_count in section_defs:
            start = _section_offset(payload, subtype_start, section_offset, adjust)
            if start is None or section_length is None or section_count is None or section_length <= 0:
                continue
            for index in range(section_count):
                item_start = start + (index * section_length)
                item_end = item_start + section_length
                if item_end > len(payload):
                    break
                section_data = payload[item_start:item_end]
                if section_name == "RACFSMRY" and index == 0:
                    summary = _decode_1154_summary(section_data)
                elif section_name == "RACFCRIT":
                    finding = _decode_1154_profile_finding(section_name, section_data)
                    findings.append(finding)
                    for value in (finding.get("resource_name"), finding.get("class_name")):
                        if value:
                            resource_candidates.append(str(value))
                elif section_name == "RACFAPFL":
                    finding = _decode_1154_dataset_finding(section_data) if section_length <= 80 else _decode_1154_profile_finding(section_name, section_data)
                    findings.append(finding)
                    for value in (finding.get("dataset_name"), finding.get("resource_name"), finding.get("class_name")):
                        if value:
                            resource_candidates.append(str(value))
                elif section_name == "RACFACTL":
                    finding = _decode_1154_actl_finding(section_data)
                    findings.append(finding)
                    if finding.get("module_name"):
                        text_tokens.append(str(finding["module_name"]))

    user_id = context.get("user_id") if context else None
    job_name = context.get("job_name") if context else None
    system_id = _decode_system_id(payload[header["system"] : header["system"] + 4]) if header["system"] + 4 <= len(payload) else None
    timestamp = _decode_smf_timestamp(payload, time_offset=header["time"], date_offset=header["date"])

    return {
        "record_type": 1154,
        "subtype": 83,
        "system_id": system_id,
        "timestamp": timestamp,
        "user_id": user_id,
        "job_name": job_name,
        "product_name": "RACF",
        "action_hint": "RACF_COMPLIANCE_EVIDENCE",
        "compliance_context": context,
        "compliance_summary": summary,
        "compliance_findings": tuple(findings),
        "user_id_candidates": _unique_preserve_order([user_id] if user_id else []),
        "resource_candidates": _unique_preserve_order(resource_candidates[:20]),
        "text_tokens": _unique_preserve_order(text_tokens[:20]),
    }


def _classify(record_type: int, subtype: int | None, zos_unix_subtypes: set[int]) -> list[str]:
    tags: list[str] = []
    if record_type == 80:
        tags.append("RACF")

    if record_type == 81:
        tags.append("RACF_INIT")

    if record_type == 83:
        if subtype is None or subtype in zos_unix_subtypes:
            tags.append("ZOS_UNIX_SECURITY")

    if record_type == 1154 and subtype == 83:
        tags.append("RACF_COMPLIANCE")

    return tags


def _extract_fields(payload: bytes) -> _DecodedFields:
    """
    Extract common fields from an SMF payload.

    Standard SMF common header layout (all formats, payload includes SMFLEN):
      0-1  SMFLEN  record length
      2    SMFSEG  segment descriptor (0 for non-spanned)
      3    SMFFLG  system indicator flags
      4    SMFRTY  record type
      5-8  SMFTIME time
      9-12 SMFDATE date
      13-16 SMFSID system identifier (4 EBCDIC chars)
      17-20 SMFSSID subsystem identifier (4 EBCDIC chars)
      21-22 SMFSUBT subtype (2 bytes, for records that carry one)
    """

    if len(payload) < 5:
        raise ValueError("Record payload too short to determine record type")

    compliance_fields = _decode_type1154_subtype83_fields(payload)
    record_type = int(compliance_fields.get("record_type", _record_type_from_payload(payload, payload[4])))
    decoded: _DecodedFields = {
        "record_type": record_type,
        "subtype": None,
        "system_id": _decode_system_id(payload[13:17]) if len(payload) >= 17 else None,
        "timestamp": _decode_smf_timestamp(payload),
        "event_code": None,
        "event_qualifier": None,
        "user_id": None,
        "group_name": None,
        "terminal_id": None,
        "job_name": None,
        "smf_user_id": None,
        "product_name": None,
        "product_version": None,
        "address_space_user_id": None,
        "address_space_group_name": None,
        "resource_name": None,
        "class_name": None,
        "profile_name": None,
        "authenticated_user_name": None,
        "authenticated_user_registry": None,
        "authenticated_user_host": None,
        "authenticated_user_oid": None,
        "distributed_identity_user_name": None,
        "distributed_identity_registry": None,
        "action_hint": None,
        "initialization_context": None,
        "compliance_context": None,
        "compliance_summary": None,
        "compliance_findings": (),
        "user_id_candidates": (),
        "resource_candidates": (),
        "text_tokens": (),
    }

    if compliance_fields:
        decoded.update(compliance_fields)
    elif record_type == 80:
        decoded.update(_decode_type80_fields(payload))
    elif record_type == 81:
        decoded.update(_decode_type81_fields(payload))
    elif record_type == 83:
        decoded.update(_decode_type83_fields(payload))

    return decoded


def _iter_records_rdw(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    cursor = 0
    data_len = len(data)
    while cursor + 4 <= data_len:
        total_length = struct.unpack(">H", data[cursor : cursor + 2])[0]
        if total_length < 4:
            raise ValueError(f"Invalid RDW length {total_length} at offset {cursor}")
        end = cursor + total_length
        if end > data_len:
            raise ValueError(f"Truncated RDW record at offset {cursor}")

        payload = data[cursor + 4 : end]
        yield cursor, total_length, payload
        cursor = end

    if cursor != data_len:
        raise ValueError(f"Trailing bytes after RDW parsing at offset {cursor}")


def _iter_records_man(data: bytes, *, strict: bool) -> Iterator[tuple[int, int, bytes]]:
    """
    Parse MAN dataset binary content using BDW/VBS framing.

    Each block starts with a 4-byte BDW, followed by one or more RDW segments.
    Spanned records are reassembled using RDW segment control flags.
    """

    cursor = 0
    data_len = len(data)
    pending_payload: bytearray | None = None
    pending_offset: int | None = None
    pending_total_length = 0

    while cursor + 4 <= data_len:
        block_offset = cursor
        block_length = struct.unpack(">H", data[cursor : cursor + 2])[0]
        if block_length < 4:
            if strict:
                raise ValueError(f"Invalid BDW length {block_length} at offset {block_offset}")
            break

        block_end = cursor + block_length
        if block_end > data_len:
            if strict:
                raise ValueError(f"Truncated BDW block at offset {block_offset}")
            break

        inner = cursor + 4
        while inner + 4 <= block_end:
            segment_offset = inner
            segment_length = struct.unpack(">H", data[inner : inner + 2])[0]
            if segment_length < 4:
                if strict:
                    raise ValueError(f"Invalid RDW segment length {segment_length} at offset {segment_offset}")
                pending_payload = None
                pending_offset = None
                pending_total_length = 0
                inner = block_end
                break

            segment_end = inner + segment_length
            if segment_end > block_end:
                if strict:
                    raise ValueError(f"RDW segment exceeds BDW block at offset {segment_offset}")
                pending_payload = None
                pending_offset = None
                pending_total_length = 0
                inner = block_end
                break

            segment_control = data[inner + 2]
            segment_payload = data[inner + 4 : segment_end]

            if segment_control == 0:
                if pending_payload is not None:
                    if strict:
                        raise ValueError(f"Unexpected complete segment while a spanned record is open at {segment_offset}")
                    pending_payload = None
                    pending_offset = None
                    pending_total_length = 0
                yield segment_offset, segment_length, segment_payload
            elif segment_control == 1:
                if pending_payload is not None:
                    if strict:
                        raise ValueError(f"Unexpected first segment while a spanned record is open at {segment_offset}")
                pending_payload = bytearray(segment_payload)
                pending_offset = segment_offset
                pending_total_length = segment_length
            elif segment_control == 2:
                if pending_payload is None:
                    if strict:
                        raise ValueError(f"Unexpected middle segment without a first segment at {segment_offset}")
                    inner = segment_end
                    continue
                pending_payload.extend(segment_payload)
                pending_total_length += segment_length
            elif segment_control == 3:
                if pending_payload is None or pending_offset is None:
                    if strict:
                        raise ValueError(f"Unexpected last segment without a first segment at {segment_offset}")
                    inner = segment_end
                    continue
                pending_payload.extend(segment_payload)
                pending_total_length += segment_length
                yield pending_offset, pending_total_length, bytes(pending_payload)
                pending_payload = None
                pending_offset = None
                pending_total_length = 0
            else:
                if strict:
                    raise ValueError(f"Unsupported RDW segment control {segment_control} at offset {segment_offset}")
                pending_payload = None
                pending_offset = None
                pending_total_length = 0
                inner = segment_end
                continue

            inner = segment_end

        if inner != block_end and strict:
            raise ValueError(f"Trailing bytes inside BDW block at offset {block_offset}")

        cursor = block_end

    if cursor != data_len and strict:
        raise ValueError(f"Trailing bytes after MAN/BDW parsing at offset {cursor}")

    if pending_payload is not None and strict:
        raise ValueError("Unterminated spanned record at end of MAN data")


def _iter_records_smf(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    cursor = 0
    data_len = len(data)
    while cursor + 2 <= data_len:
        record_length = struct.unpack(">H", data[cursor : cursor + 2])[0]
        if record_length < 2:
            raise ValueError(f"Invalid SMF length {record_length} at offset {cursor}")
        end = cursor + record_length
        if end > data_len:
            raise ValueError(f"Truncated SMF record at offset {cursor}")

        payload = data[cursor:end]
        yield cursor, record_length, payload
        cursor = end

    if cursor != data_len:
        raise ValueError(f"Trailing bytes after SMF parsing at offset {cursor}")


def _iterator_from_data(data: bytes, *, record_format: RecordFormat, strict_man: bool) -> Iterator[tuple[int, int, bytes]]:
    active_format = _detect_format(data) if record_format == "auto" else record_format
    if active_format == "rdw":
        return _iter_records_rdw(data)
    if active_format == "man":
        return _iter_records_man(data, strict=strict_man)
    return _iter_records_smf(data)


def _detect_format(data: bytes) -> RecordFormat:
    if len(data) < 8:
        return "smf"

    # MAN datasets are commonly BDW/VBS. If first block contains plausible
    # RDW segments, prefer MAN parsing for automatic mode.
    first_length = struct.unpack(">H", data[0:2])[0]
    if data[2] == 0 and data[3] == 0 and 8 <= first_length <= len(data):
        inner = 4
        end = first_length
        saw_segment = False
        while inner + 4 <= end:
            segment_length = struct.unpack(">H", data[inner : inner + 2])[0]
            if segment_length < 4 or inner + segment_length > end:
                break
            saw_segment = True
            inner += segment_length
        if saw_segment and inner == end:
            return "man"

    # RDW bytes 2-3 are usually binary zeros for classic VB datasets.
    if data[2] == 0 and data[3] == 0:
        return "rdw"

    return "smf"


def iter_smf_records(
    path: str | Path,
    record_format: RecordFormat = "auto",
    *,
    strict_man: bool = False,
    dataset_input: bool = False,
) -> Iterator[SmfRecord]:
    dataset_name = str(path).strip() if dataset_input else _dataset_name_from_source(path)
    if dataset_name is not None:
        try:
            iterator = _iter_records_dataset(_read_records_from_dataset(dataset_name))
        except OSError as exc:
            # EDC5012I: dataset rejects file-positioning; fall back to copy.
            # EDC5092I: I/O abend (e.g. non-SMF dataset opened as binary);
            #            skip the dataset entirely rather than crashing.
            message = str(exc)
            errno_val = getattr(exc, "errno", None)
            if "EDC5092I" in message or errno_val == 92:
                return
            if "EDC5047I" in message or errno_val == 47:
                # Invalid dataset name (e.g. a non-name token passed from discovery).
                return
            if "EDC5049I" in message or errno_val == 49:
                # Dataset/logstream not found (e.g. a logstream name that cannot be
                # opened as a regular dataset).
                return
            if errno_val != 12 and "EDC5012I" not in message:
                raise
            data = _read_dataset_stream_via_copy(dataset_name)
            iterator = _iterator_from_data(data, record_format=record_format, strict_man=strict_man)
    else:
        file_path = Path(path)
        data = file_path.read_bytes()
        iterator = _iterator_from_data(data, record_format=record_format, strict_man=strict_man)

    for offset, total_length, payload in iterator:
        decoded = _extract_fields(payload)
        yield SmfRecord(
            offset=offset,
            total_length=total_length,
            record_length=len(payload),
            record_type=int(decoded["record_type"]),
            subtype=decoded["subtype"],
            system_id=decoded["system_id"],
            timestamp=decoded["timestamp"],
            event_code=decoded["event_code"],
            event_qualifier=decoded["event_qualifier"],
            user_id=decoded["user_id"],
            group_name=decoded["group_name"],
            terminal_id=decoded["terminal_id"],
            job_name=decoded["job_name"],
            smf_user_id=decoded["smf_user_id"],
            product_name=decoded["product_name"],
            product_version=decoded["product_version"],
            address_space_user_id=decoded["address_space_user_id"],
            address_space_group_name=decoded["address_space_group_name"],
            resource_name=decoded["resource_name"],
            class_name=decoded["class_name"],
            profile_name=decoded["profile_name"],
            authenticated_user_name=decoded["authenticated_user_name"],
            authenticated_user_registry=decoded["authenticated_user_registry"],
            authenticated_user_host=decoded["authenticated_user_host"],
            authenticated_user_oid=decoded["authenticated_user_oid"],
            distributed_identity_user_name=decoded["distributed_identity_user_name"],
            distributed_identity_registry=decoded["distributed_identity_registry"],
            action_hint=decoded["action_hint"],
            initialization_context=decoded["initialization_context"],
            compliance_context=decoded["compliance_context"],
            compliance_summary=decoded["compliance_summary"],
            compliance_findings=decoded["compliance_findings"],
            user_id_candidates=decoded["user_id_candidates"],
            resource_candidates=decoded["resource_candidates"],
            text_tokens=decoded["text_tokens"],
            tags=[],
        )


def iter_security_records(
    path: str | Path,
    *,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
    dataset_input: bool = False,
    include_all: bool = False,
    zos_unix_subtypes: set[int] | None = None,
) -> Iterator[SmfRecord]:
    """
    Iterate records and tag security-relevant records.

    Defaults:
    - RACF security events: SMF type 80
    - z/OS UNIX security records: SMF type 83, subtypes 2/3/4
    """

    unix_subtypes = zos_unix_subtypes or {2, 3, 4}
    for record in iter_smf_records(
        path,
        record_format=record_format,
        strict_man=strict_man,
        dataset_input=dataset_input,
    ):
        record.tags = _classify(record.record_type, record.subtype, unix_subtypes)
        if include_all or record.tags:
            yield record
