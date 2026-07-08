from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import date, datetime, time, timedelta
import os
from pathlib import Path
import re
import struct
import tempfile
from typing import Iterator, Literal, TypedDict


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


def _decode_smf_timestamp(payload: bytes) -> str | None:
    if len(payload) < 13:
        return None

    hundredths = struct.unpack(">I", payload[5:9])[0]
    date_digits = _packed_decimal_digits(payload[9:13])
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


def _decode_type80_fields(payload: bytes) -> _DecodedFieldPatch:
    event_code = payload[19] if len(payload) >= 20 else None
    event_qualifier = payload[20] if len(payload) >= 21 else None
    user_id = _decode_ebcdic_field(payload[21:29]) if len(payload) >= 29 else None
    group_name = _decode_ebcdic_field(payload[29:37]) if len(payload) >= 37 else None
    terminal_id = _decode_ebcdic_field(payload[45:53]) if len(payload) >= 53 else None
    job_name = _decode_ebcdic_field(payload[53:61]) if len(payload) >= 61 else None
    smf_user_id = _decode_ebcdic_field(payload[69:77]) if len(payload) >= 77 else None
    action_hint = _EVENT_CODE_NAMES.get(event_code) if event_code is not None else None

    hints_action, user_candidates, resource_candidates, text_tokens = _decode_racf_hints(payload, None)
    if action_hint is None:
        action_hint = hints_action

    if user_id:
        user_candidates = _unique_preserve_order([user_id, *user_candidates])

    return {
        "subtype": None,
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


def _classify(record_type: int, subtype: int | None, zos_unix_subtypes: set[int]) -> list[str]:
    tags: list[str] = []
    if record_type == 80:
        tags.append("RACF")

    if record_type == 83:
        if subtype is None or subtype in zos_unix_subtypes:
            tags.append("ZOS_UNIX_SECURITY")

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

    record_type = payload[4]
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
        "user_id_candidates": (),
        "resource_candidates": (),
        "text_tokens": (),
    }

    if record_type == 80:
        decoded.update(_decode_type80_fields(payload))
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
