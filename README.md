# can-engineering-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI agents deterministically inspect, author, convert, validate, and diagnose Controller Area Network (Classical CAN & CAN FD) databases and trace logs.

LLMs are good at systems reasoning and root-cause synthesis, but bad at raw hex parsing, Motorola bit-numbering math, and scanning million-line trace files. This server does the deterministic heavy lifting — bit-packing validation, streaming log aggregation, transport-protocol reassembly, statistical anomaly detection — and hands the agent compact, token-efficient summaries instead of raw bytes.

## What it does

19 tools across six stages:

- **DBC discovery** — inspect a database, fuzzy-search messages/signals/IDs/units, render an exact Intel/Motorola bit-layout grid, validate for bit overlaps and structural errors.
- **DBC authoring** — atomic, backed-up (`.bak`) mutation of nodes, messages, and signals, with an auto-packer that finds free bit ranges and rejects overlapping writes with a structured conflict map.
- **Templates & conversion** — generate clean-room J1939, CANopen (CiA 301), and UDS/ISO-TP skeleton databases from scratch; convert between `.dbc`/`.dbf`/`.arxml`/`.kcd`/`.sym`/`.xlsx`; diff two databases into an engineering changelog (bit shifts, scale changes, cycle-time changes).
- **Trace ingestion** — stream `.asc`/`.blf`/`.trc`/`.log`/`.csv`/`.parquet` traces (tested against real files up to 500MB+), summarize per-arbitration-ID statistics, query decoded signal trends, and filter/export with a safe (non-`eval`) signal-condition expression language.
- **Transport protocol & UDS** — a real ISO 15765-2 (ISO-TP) state machine for SF/FF/FC/CF reassembly, UDS (ISO 14229) service and negative-response-code decoding, J1939-21 BAM/CMDT multi-packet reassembly.
- **Bus health & reverse engineering** — bus-load/microburst analysis, error-storm and Bus-Off detection, cycle-time jitter and alive-counter fault detection, and a heuristic classifier that reverse-engineers undocumented frames (constant masks, counters, checksums, continuous signals, discrete flags) into a draft candidate DBC.

## Install

```bash
pip install can-engineering-mcp
```

Or from source, editable:

```bash
git clone https://github.com/kankan-sarkar/canbus-mcp.git
cd canbus-mcp
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Register with an MCP client

Add to your client's MCP server config (e.g. Claude Code's `.mcp.json` for a single project, or its user-scope config to enable it everywhere):

```json
{
  "mcpServers": {
    "can-engineering-mcp": {
      "command": "/path/to/python",
      "args": ["-m", "can_mcp.server"]
    }
  }
}
```

File access is sandboxed to the current working directory the server is launched in (override with the `CAN_MCP_WORKSPACE_ROOT` environment variable).

## Development

```bash
pytest   # full suite runs offline in well under 15s, against synthetic generated fixtures only
```

Every fixture is generated deterministically in-memory (`tests/fixtures/generator.py`) — nothing proprietary, nothing downloaded.

## Dependency & license guardrails

Only permissively-licensed (MIT/BSD-2-Clause/BSD-3-Clause/LGPLv3-dynamic-link) dependencies are used: `mcp`, `cantools`, `canmatrix`, `python-can`, `polars`, `duckdb`, `pydantic`, `lxml`, `openpyxl`, `canopen`. No proprietary database content (e.g. the SAE J1939 Digital Annex) is bundled; protocol templates (J1939, CANopen, UDS/ISO-TP) are clean-room structural generators built from public framing specifications.

## License

MIT — see [`LICENSE`](LICENSE).
