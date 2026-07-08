from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import struct
from typing import Iterator, Literal


RecordFormat = Literal["auto", "rdw", "smf", "man"]


@dataclass(slots=True)
class SmfRecord:
    """Minimal representation of an SMF record."""

    offset: int
    total_length: int
    record_length: int
    record_type: int
    subtype: int | None
    system_id: str | None
    tags: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


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


def _classify(record_type: int, subtype: int | None, zos_unix_subtypes: set[int]) -> list[str]:
    tags: list[str] = []
    if record_type == 80:
        tags.append("RACF")

    if record_type == 83:
        if subtype is None or subtype in zos_unix_subtypes:
            tags.append("ZOS_UNIX_SECURITY")

    return tags


def _extract_fields(payload: bytes) -> tuple[int, int | None, str | None]:
    """
    Extract common fields from an SMF payload.

    Assumptions follow standard SMF common header conventions:
    - byte 2: record type (SMFRTY)
    - bytes 12-15: system identifier
    - bytes 18-19: subtype (for subtype-capable records)
    """

    if len(payload) < 3:
        raise ValueError("Record payload too short to determine record type")

    record_type = payload[2]
    system_id = _decode_system_id(payload[12:16]) if len(payload) >= 16 else None
    subtype = struct.unpack(">H", payload[18:20])[0] if len(payload) >= 20 else None
    return record_type, subtype, system_id


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
) -> Iterator[SmfRecord]:
    file_path = Path(path)
    data = file_path.read_bytes()

    active_format = _detect_format(data) if record_format == "auto" else record_format
    if active_format == "rdw":
        iterator = _iter_records_rdw(data)
    elif active_format == "man":
        iterator = _iter_records_man(data, strict=strict_man)
    else:
        iterator = _iter_records_smf(data)

    for offset, total_length, payload in iterator:
        record_type, subtype, system_id = _extract_fields(payload)
        yield SmfRecord(
            offset=offset,
            total_length=total_length,
            record_length=len(payload),
            record_type=record_type,
            subtype=subtype,
            system_id=system_id,
            tags=[],
        )


def iter_security_records(
    path: str | Path,
    *,
    record_format: RecordFormat = "auto",
    strict_man: bool = False,
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
    for record in iter_smf_records(path, record_format=record_format, strict_man=strict_man):
        record.tags = _classify(record.record_type, record.subtype, unix_subtypes)
        if include_all or record.tags:
            yield record
