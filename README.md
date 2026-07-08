# racf-smf

Python program to fetch and filter RACF and z/OS UNIX security SMF records from binary SMF exports.

The package is designed for two use cases:

- CLI extraction to JSON lines (`racf-smf ...`)
- Direct Python integration for pySEAR and analytics pipelines

## What this implementation does

- Reads SMF binary data in either:
  - MAN dataset BDW/VBS format (`--format man`)
  - RDW-framed VB format (`--format rdw`)
  - Raw concatenated SMF record format (`--format smf`)
  - Auto-detected mode (`--format auto`, default)
- Emits JSON records with key fields for each matching record.
- Filters by default to security-relevant records:
  - RACF security events: SMF type 80
  - z/OS UNIX security events: SMF type 83 with subtypes 2, 3, or 4
- Supports `--all` to emit all SMF records.

## Project structure

- `racf_smf/parser.py`: SMF parsing and security classification logic
- `racf_smf/cli.py`: command-line interface
- `pyproject.toml`: packaging and `racf-smf` console script

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

For DataFrame-based analysis:

```powershell
pip install -e .[analytics]
```

For z/OS dataset access through ZOAU:

```powershell
pip install -e .[zos]
```

## Usage

```powershell
racf-smf path\to\smf.bin
```

Force RDW format:

```powershell
racf-smf path\to\smf.bin --format rdw
```

Parse a raw MAN dataset extract directly:

```powershell
racf-smf path\to\SYS1.MAN01.bin --format man --json-out security_records.jsonl
```

Read directly from an MVS dataset using ZOAU (USS on z/OS):

```sh
racf-smf SYS1.MANX --dataset-input --json-out /u/you/security_records.jsonl
```

Read a specific generation dataset:

```sh
racf-smf HLQ.SMF.DAILY.G0001V00 --dataset-input --json-out /u/you/security_records.jsonl
```

Validate MAN extract integrity while parsing (fail fast on malformed BDW/RDW segments):

```powershell
racf-smf path\to\SYS1.MAN01.bin --format man --strict-man --json-out security_records.jsonl
```

Note: `--strict-man` applies to byte-stream MAN files. ZOAU dataset reads are record-oriented.

Write JSON lines to a file and limit output:

```powershell
racf-smf path\to\smf.bin --json-out security_records.jsonl --max-records 50000
```

Override z/OS UNIX type 83 subtypes considered security-related:

```powershell
racf-smf path\to\smf.bin --zos-unix-subtypes 2,3,4,5
```

Emit all records (not only security):

```powershell
racf-smf path\to\smf.bin --all
```

## Output

Each emitted line is JSON, for example:

```json
{"offset":0,"total_length":612,"record_length":608,"record_type":80,"subtype":1,"system_id":"SYSA","tags":["RACF"]}
```

At the end, the CLI prints summary counters by record type and tag.

## Python API for pySEAR and analytics

Use the normalized event API to avoid custom unpacking in downstream code:

```python
from racf_smf import iter_security_events, read_security_events

for event in iter_security_events("smf.bin", strict_man=True):
  # event is a dict with stable keys suitable for pySEAR ingest:
  # source, offset, total_length, record_length, record_type,
  # subtype, system_id, event_family, tags
  process(event)

events = read_security_events("smf.bin", include_all=False)
```

DataFrame workflow:

```python
from racf_smf import read_security_dataframe

df = read_security_dataframe("smf.bin")
print(df.groupby(["event_family", "record_type"]).size())
```

If pySEAR expects iterable rows/dicts, `iter_security_events(...)` can be passed directly into your ingest function.

For dataset input in Python APIs, set `dataset_input=True`:

```python
from racf_smf import iter_security_events

for event in iter_security_events("SYS1.MANX", dataset_input=True):
  process(event)
```

## Notes and assumptions

- The parser extracts common SMF header fields using standard offsets:
  - Record type at byte 2
  - System ID at bytes 12-15
  - Subtype at bytes 18-19
- Depending on how your site exports SMF data, header layouts and subtypes may vary.
- If your data source uses different framing or custom exits, adjust parsing logic in `racf_smf/parser.py`.
