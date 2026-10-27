"""Deterministic synthetic DBC fixture generator for Stage 1 tests.

Builds every fixture purely in-memory via the `cantools` object model (never
hand-written DBC text) so fixtures stay valid against future cantools
versions, then dumps them to `.dbc` files under `tests/fixtures/`.
"""
from __future__ import annotations

import math
from collections import OrderedDict
from pathlib import Path

import can as python_can
import cantools.database.can as can
from cantools.database.can.formats.dbc import DbcSpecifics
from cantools.database.can.formats.dbc.dbc_attribute import DbcAttribute
from cantools.database.can.formats.dbc.dbc_attribute_definition import DbcAttributeDefinition
from cantools.database.conversion import BaseConversion

FIXTURES_DIR = Path(__file__).parent
SAMPLE_POWERTRAIN_PATH = FIXTURES_DIR / "sample_powertrain.dbc"
OVERLAP_INJECTED_PATH = FIXTURES_DIR / "overlap_injected.dbc"

SAMPLE_BAUDRATE = 500_000

# Bit positions (in bytes/bits-from-LSB DBC convention) for the Motorola
# 12-bit signal that intentionally spans a byte boundary (Gate 1.3).
WHEEL_SPEED_FL_START = 23  # sawtooth bit -> network bit 16 (MSB of byte 2)
WHEEL_SPEED_FL_LENGTH = 12  # spans byte2 (full) + upper nibble of byte3


def _bus_speed_specifics(baudrate: int) -> DbcSpecifics:
    definition = DbcAttributeDefinition(
        name="BusSpeed", default_value=baudrate, kind=None, type_name="INT",
        minimum=0, maximum=10_000_000,
    )
    attribute = DbcAttribute(value=baudrate, definition=definition)
    return DbcSpecifics(
        attributes=OrderedDict({"BusSpeed": attribute}),
        attribute_definitions=OrderedDict({"BusSpeed": definition}),
    )


def build_sample_powertrain_db() -> can.Database:
    """A valid powertrain DBC covering Intel/Motorola, signed/unsigned, and
    multiplexed signals (Gate 1.1).
    """
    nodes = [
        can.Node(name="ECU_Engine"),
        can.Node(name="ECU_TCU"),
        can.Node(name="ECU_ABS"),
        can.Node(name="Gateway"),
    ]

    engine_speed = can.Signal(
        name="EngineSpeed", start=0, length=16, byte_order="little_endian",
        is_signed=False, conversion=BaseConversion.factory(scale=0.25, offset=0),
        minimum=0, maximum=16000, unit="rpm", receivers=["ECU_TCU", "Gateway"],
    )
    coolant_temp = can.Signal(
        name="CoolantTemp", start=16, length=8, byte_order="little_endian",
        is_signed=True, conversion=BaseConversion.factory(scale=1, offset=-40),
        minimum=-40, maximum=215, unit="degC", receivers=["Gateway"],
    )
    engine_data = can.Message(
        frame_id=0x100, name="EngineData", length=8,
        signals=[engine_speed, coolant_temp], senders=["ECU_Engine"],
        cycle_time=10,
    )

    gear_mux = can.Signal(
        name="GearSelector_Mux", start=0, length=8, byte_order="little_endian",
        is_signed=False, is_multiplexer=True, receivers=["Gateway"],
    )
    gear_position_m0 = can.Signal(
        name="GearPosition_Auto", start=8, length=8, byte_order="little_endian",
        is_signed=False, multiplexer_ids=[0], multiplexer_signal="GearSelector_Mux",
        conversion=BaseConversion.factory(scale=1, offset=0, choices=OrderedDict({
            0: "Park", 1: "Reverse", 2: "Neutral", 3: "Drive",
        })), receivers=["Gateway"],
    )
    gear_position_m1 = can.Signal(
        name="GearPosition_Manual", start=8, length=8, byte_order="little_endian",
        is_signed=False, multiplexer_ids=[1], multiplexer_signal="GearSelector_Mux",
        conversion=BaseConversion.factory(scale=1, offset=0, choices=OrderedDict({
            0: "Gear1", 1: "Gear2", 2: "Gear3", 3: "Gear4",
        })), receivers=["Gateway"],
    )
    transmission_status = can.Message(
        frame_id=0x120, name="TransmissionStatus", length=8,
        signals=[gear_mux, gear_position_m0, gear_position_m1],
        senders=["ECU_TCU"], cycle_time=20,
    )

    wheel_speed_fl = can.Signal(
        name="WheelSpeedFL", start=WHEEL_SPEED_FL_START, length=WHEEL_SPEED_FL_LENGTH,
        byte_order="big_endian", is_signed=False,
        conversion=BaseConversion.factory(scale=0.1, offset=0),
        minimum=0, maximum=300, unit="km/h", receivers=["Gateway"],
    )
    steering_torque = can.Signal(
        name="SteeringTorque", start=55, length=16, byte_order="big_endian",
        is_signed=True, conversion=BaseConversion.factory(scale=1, offset=0),
        minimum=-500, maximum=500, unit="Nm", receivers=["Gateway"],
    )
    wheel_speeds = can.Message(
        frame_id=0x140, name="WheelSpeeds", length=8,
        signals=[wheel_speed_fl, steering_torque], senders=["ECU_ABS"],
        cycle_time=10,
    )

    return can.Database(
        messages=[engine_data, transmission_status, wheel_speeds],
        nodes=nodes,
        dbc_specifics=_bus_speed_specifics(SAMPLE_BAUDRATE),
        strict=True,
    )


def build_overlap_injected_db() -> can.Database:
    """An intentionally-invalid DBC with a 2-bit overlap between two Intel
    signals, for Gate 1.4 (`validate_database_integrity`).

    SignalA occupies LSB bits [10..17], SignalB occupies [16..23]: bits 16
    and 17 collide.
    """
    signal_a = can.Signal(name="SignalA", start=10, length=8, byte_order="little_endian", is_signed=False)
    signal_b = can.Signal(name="SignalB", start=16, length=8, byte_order="little_endian", is_signed=False)
    corrupt_frame = can.Message(
        frame_id=0x200, name="CorruptFrame", length=8,
        signals=[signal_a, signal_b], senders=["ECU_X"], strict=False,
    )
    return can.Database(
        messages=[corrupt_frame], nodes=[can.Node(name="ECU_X")], strict=False,
    )


def write_database(db: can.Database, path: Path) -> Path:
    path.write_text(db.as_dbc_string())
    return path


def generate_sample_powertrain(path: Path = SAMPLE_POWERTRAIN_PATH) -> Path:
    return write_database(build_sample_powertrain_db(), path)


def generate_overlap_injected(path: Path = OVERLAP_INJECTED_PATH) -> Path:
    return write_database(build_overlap_injected_db(), path)


def generate_all_fixtures() -> None:
    generate_sample_powertrain()
    generate_overlap_injected()


# --------------------------------------------------------------------------
# Stage 4: synthetic trace fixtures
# --------------------------------------------------------------------------

VEHICLE_TRACE_DBC_PATH = FIXTURES_DIR / "vehicle_trace.dbc"
VEHICLE_STATUS_FRAME_ID = 0x400


def build_vehicle_trace_db() -> can.Database:
    """A tiny DBC for Stage 4 trace fixtures: one message carrying
    VehicleSpeed (km/h) and EngineRPM, decodable by the trace engine's
    signal-condition filter and query tools.
    """
    vehicle_speed = can.Signal(
        name="VehicleSpeed", start=0, length=16, byte_order="little_endian", is_signed=False,
        conversion=BaseConversion.factory(scale=0.1, offset=0), minimum=0, maximum=300, unit="km/h",
    )
    engine_rpm = can.Signal(
        name="EngineRPM", start=16, length=16, byte_order="little_endian", is_signed=False,
        conversion=BaseConversion.factory(scale=1, offset=0), minimum=0, maximum=8000, unit="rpm",
    )
    vehicle_status = can.Message(
        frame_id=VEHICLE_STATUS_FRAME_ID, name="VehicleStatus", length=8,
        signals=[vehicle_speed, engine_rpm], senders=["ECU_Body"],
    )
    return can.Database(messages=[vehicle_status], nodes=[can.Node(name="ECU_Body")], strict=True)


def generate_vehicle_trace_dbc(path: Path = VEHICLE_TRACE_DBC_PATH) -> Path:
    return write_database(build_vehicle_trace_db(), path)


def generate_synthetic_trace(
    path: Path,
    frame_count: int = 5000,
    start_timestamp: float = 1_700_000_000.0,
    dt: float = 0.01,
) -> Path:
    """Write `frame_count` VehicleStatus frames to `path` (any python-can
    native format, chosen by extension), with VehicleSpeed sweeping a
    deterministic 0 -> 250 -> 0 km/h triangle wave so signal-condition
    filtering (Gate 4.2) has a real, verifiable mix of matching/non-matching
    frames.
    """
    db = build_vehicle_trace_db()
    message_def = db.get_message_by_name("VehicleStatus")

    logger = python_can.Logger(filename=str(path))
    try:
        for i in range(frame_count):
            phase = i / frame_count
            speed_kmh = round(250.0 * (1 - abs(2 * phase - 1)), 1)
            rpm = 800 + (i * 37) % 6000
            data = message_def.encode({"VehicleSpeed": speed_kmh, "EngineRPM": rpm})
            msg = python_can.Message(
                timestamp=start_timestamp + i * dt, arbitration_id=VEHICLE_STATUS_FRAME_ID,
                is_extended_id=False, data=data, channel=0,
            )
            logger.on_message_received(msg)
    finally:
        logger.stop()
    return path


# --------------------------------------------------------------------------
# Stage 5: ISO-TP / UDS and J1939 transport-protocol trace fixtures
# --------------------------------------------------------------------------

ISOTP_REQUEST_ID = 0x7E0
ISOTP_RESPONSE_ID = 0x7E8


def _build_isotp_ff_cf_frames(payload: bytes) -> list[bytes]:
    """Classic 8-byte ISO-TP First-Frame + Consecutive-Frame chunking."""
    length = len(payload)
    frames = [bytes([0x10 | ((length >> 8) & 0x0F), length & 0xFF]) + payload[:6]]
    remaining = payload[6:]
    sn = 1
    while remaining:
        chunk = remaining[:7]
        frame = bytes([0x20 | (sn & 0x0F)]) + chunk
        frame += bytes([0xFF] * (8 - len(frame)))
        frames.append(frame)
        remaining = remaining[7:]
        sn = (sn + 1) % 16
    return frames


def generate_isotp_long_read_trace(path: Path, start_timestamp: float = 1_700_000_000.0, dt: float = 0.002) -> tuple[Path, bytes]:
    """A 64-byte ReadDataByIdentifier(0x22 F1 90) response split across
    exactly 1 First Frame + 1 Flow Control + 9 Consecutive Frames (Gate 5.1).
    """
    response_payload = bytes([0x62, 0xF1, 0x90]) + bytes(range(61))
    assert len(response_payload) == 64
    frames = _build_isotp_ff_cf_frames(response_payload)
    assert len(frames) == 1 + 9  # 1 FF + 9 CF, per Gate 5.1

    logger = python_can.Logger(filename=str(path))
    t = start_timestamp
    try:
        request_sf = bytes([0x03, 0x22, 0xF1, 0x90]) + bytes([0xFF] * 4)
        logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=ISOTP_REQUEST_ID, is_extended_id=False, data=request_sf, channel=0))
        t += dt
        logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=ISOTP_RESPONSE_ID, is_extended_id=False, data=frames[0], channel=0))
        t += dt
        flow_control = bytes([0x30, 0x00, 0x00]) + bytes([0xFF] * 5)
        logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=ISOTP_REQUEST_ID, is_extended_id=False, data=flow_control, channel=0))
        t += dt
        for cf in frames[1:]:
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=ISOTP_RESPONSE_ID, is_extended_id=False, data=cf, channel=0))
            t += dt
    finally:
        logger.stop()
    return path, response_payload


def generate_security_access_failure_trace(path: Path, start_timestamp: float = 1_700_000_000.0, dt: float = 0.01) -> Path:
    """0x27 01 Seed Request -> 0x67 01 Seed Response -> 0x27 02 Bad Key ->
    0x7F 27 35 InvalidKey -> 0x7F 27 36 ExceededNumberOfAttempts (Gate 5.2).
    """
    def sf(payload: bytes) -> bytes:
        return bytes([len(payload)]) + payload + bytes([0xFF] * (7 - len(payload)))

    steps = [
        (ISOTP_REQUEST_ID, bytes([0x27, 0x01])),
        (ISOTP_RESPONSE_ID, bytes([0x67, 0x01, 0x12, 0x34, 0x56, 0x78])),
        (ISOTP_REQUEST_ID, bytes([0x27, 0x02, 0xAA, 0xBB, 0xCC, 0xDD])),
        (ISOTP_RESPONSE_ID, bytes([0x7F, 0x27, 0x35])),
        (ISOTP_RESPONSE_ID, bytes([0x7F, 0x27, 0x36])),
    ]

    logger = python_can.Logger(filename=str(path))
    t = start_timestamp
    try:
        for arb_id, payload in steps:
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=arb_id, is_extended_id=False, data=sf(payload), channel=0))
            t += dt
    finally:
        logger.stop()
    return path


def generate_isotp_sequence_error_trace(path: Path, start_timestamp: float = 1_700_000_000.0, dt: float = 0.005) -> tuple[Path, float]:
    """FF + CF(sn=1) + CF(sn=2) + [CF(sn=3) dropped] + CF(sn=4): the engine
    must report ISOTP_SEQUENCE_ERROR at the exact timestamp of the sn=4
    frame (Gate 5.3).
    """
    payload = bytes(range(41))  # FF carries 6, then exactly 5 CF x 7 bytes = 41
    frames = _build_isotp_ff_cf_frames(payload)
    assert len(frames) == 1 + 5

    logger = python_can.Logger(filename=str(path))
    t = start_timestamp
    try:
        for frame in frames[0:3]:  # FF, CF(sn=1), CF(sn=2)
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=ISOTP_RESPONSE_ID, is_extended_id=False, data=frame, channel=0))
            t += dt
        # frames[3] (CF sn=3) intentionally dropped to simulate the fault.
        t += dt
        error_timestamp = t
        logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=ISOTP_RESPONSE_ID, is_extended_id=False, data=frames[4], channel=0))
    finally:
        logger.stop()
    return path, error_timestamp


# --------------------------------------------------------------------------
# Stage 5: J1939-21 transport protocol (BAM) trace fixture
# --------------------------------------------------------------------------

J1939_TP_CM_PF = 0xEC
J1939_TP_DT_PF = 0xEB
J1939_BAM_SOURCE_ADDRESS = 0x05
J1939_BAM_PGN = 0xFEC1


def generate_j1939_bam_trace(
    path: Path,
    payload: bytes = b"HELLO-FROM-ECU1",
    pgn: int = J1939_BAM_PGN,
    source_address: int = J1939_BAM_SOURCE_ADDRESS,
    start_timestamp: float = 1_700_000_000.0,
    dt: float = 0.05,
) -> tuple[Path, bytes]:
    """A J1939 BAM broadcast session (TP.CM control + TP.DT data frames)
    carrying an arbitrary multi-byte payload under `pgn`.
    """
    total_size = len(payload)
    total_packets = -(-total_size // 7)
    cm_data = bytes([0x20]) + total_size.to_bytes(2, "little") + bytes([total_packets, 0xFF]) + pgn.to_bytes(3, "little")
    cm_id = (6 << 26) | (J1939_TP_CM_PF << 16) | (0xFF << 8) | source_address
    dt_id = (7 << 26) | (J1939_TP_DT_PF << 16) | (0xFF << 8) | source_address

    logger = python_can.Logger(filename=str(path))
    t = start_timestamp
    try:
        logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=cm_id, is_extended_id=True, data=cm_data, channel=0))
        t += dt
        for i in range(total_packets):
            chunk = payload[i * 7:(i + 1) * 7]
            frame = bytes([i + 1]) + chunk + bytes([0xFF] * (7 - len(chunk)))
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=dt_id, is_extended_id=True, data=frame, channel=0))
            t += dt
    finally:
        logger.stop()
    return path, payload


# --------------------------------------------------------------------------
# Stage 6: bus health & unknown-signal reverse-engineering fixtures
# --------------------------------------------------------------------------

BUS_HEALTH_DB_PATH = FIXTURES_DIR / "bus_health.dbc"
CYCLIC_FRAME_ID = 0x100
CYCLIC_CYCLE_MS = 10
NODE_A_FRAME_ID = 0x200
NODE_A_CYCLE_MS = 20


def build_bus_health_db() -> can.Database:
    counter_sig = can.Signal(name="Counter", start=0, length=8, byte_order="little_endian", is_signed=False)
    cyclic_msg = can.Message(
        frame_id=CYCLIC_FRAME_ID, name="CyclicMsg100", length=8, signals=[counter_sig],
        senders=["ECU_A"], cycle_time=CYCLIC_CYCLE_MS,
    )
    status_sig = can.Signal(name="Status", start=0, length=8, byte_order="little_endian", is_signed=False)
    node_a_msg = can.Message(
        frame_id=NODE_A_FRAME_ID, name="NodeAStatus", length=8, signals=[status_sig],
        senders=["ECU_A"], cycle_time=NODE_A_CYCLE_MS,
    )
    return can.Database(
        messages=[cyclic_msg, node_a_msg], nodes=[can.Node(name="ECU_A"), can.Node(name="Gateway")], strict=True,
    )


def generate_bus_health_dbc(path: Path = BUS_HEALTH_DB_PATH) -> Path:
    return write_database(build_bus_health_db(), path)


def generate_cyclic_dropout_trace(
    path: Path,
    frame_id: int = CYCLIC_FRAME_ID,
    cycle_ms: float = CYCLIC_CYCLE_MS,
    frames_before: int = 50,
    dropout_extra_ms: float = 250.0,
    frames_after: int = 50,
    start_timestamp: float = 1_700_000_000.0,
) -> tuple[Path, float, float]:
    """A cyclic message at `cycle_ms` cadence with one abnormal gap: the
    frame right after the dropout arrives `cycle_ms + dropout_extra_ms`
    after the last normal frame (260ms for the defaults -> exactly 25
    missed 10ms cycles, Gate 6.1).
    """
    dt = cycle_ms / 1000.0
    logger = python_can.Logger(filename=str(path))
    t = start_timestamp
    counter = 0
    try:
        for _ in range(frames_before):
            data = bytes([counter % 256]) + bytes(7)
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=frame_id, is_extended_id=False, data=data, channel=0))
            counter += 1
            t += dt
        last_before_dropout = t - dt
        t += dropout_extra_ms / 1000.0
        gap_timestamp = t
        for _ in range(frames_after):
            data = bytes([counter % 256]) + bytes(7)
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=frame_id, is_extended_id=False, data=data, channel=0))
            counter += 1
            t += dt
    finally:
        logger.stop()
    return path, last_before_dropout, gap_timestamp


def generate_error_storm_busoff_trace(
    path: Path,
    frame_id: int = NODE_A_FRAME_ID,
    cycle_ms: float = NODE_A_CYCLE_MS,
    frames_before: int = 20,
    error_count: int = 128,
    error_spacing_ms: float = 0.5,
    silence_ms: float = 500.0,
    frames_after: int = 10,
    start_timestamp: float = 1_700_000_000.0,
) -> tuple[Path, float, float, float]:
    """`frames_before` normal NodeAStatus frames, then a burst of
    `error_count` error frames, then `silence_ms` of total silence on
    `frame_id` before it resumes (Gate 6.2: Node Bus-Off diagnosis).
    """
    dt = cycle_ms / 1000.0
    logger = python_can.Logger(filename=str(path))
    t = start_timestamp
    try:
        for i in range(frames_before):
            data = bytes([i % 256]) + bytes(7)
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=frame_id, is_extended_id=False, data=data, channel=0))
            t += dt
        storm_start = t
        error_dt = error_spacing_ms / 1000.0
        for _ in range(error_count):
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=0, is_error_frame=True, channel=0))
            t += error_dt
        storm_end = t - error_dt
        t = storm_end + silence_ms / 1000.0
        silence_end = t
        for i in range(frames_after):
            data = bytes([i % 256]) + bytes(7)
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=frame_id, is_extended_id=False, data=data, channel=0))
            t += dt
    finally:
        logger.stop()
    return path, storm_start, storm_end, silence_end


def generate_unknown_signal_trace(
    path: Path,
    frame_id: int = 0x555,
    frame_count: int = 1000,
    sine_period_frames: int = 50,
    start_timestamp: float = 1_700_000_000.0,
    dt: float = 0.01,
) -> Path:
    """A DBC-less 8-byte frame with three deliberately-recognizable
    bitfields for Gate 6.3: byte0-1 a smooth 16-bit sine wave, byte6's low
    nibble a 0..15 rolling counter, byte7 an XOR checksum of bytes 0-6.
    """
    logger = python_can.Logger(filename=str(path))
    t = start_timestamp
    try:
        for i in range(frame_count):
            sine_value = int(32767 + 32767 * math.sin(2 * math.pi * i / sine_period_frames))
            sine_value = max(0, min(65535, sine_value))
            counter = i % 16
            payload = bytes([
                sine_value & 0xFF, (sine_value >> 8) & 0xFF,
                0, 0, 0, 0,
                counter & 0x0F,
            ])
            checksum = 0
            for b in payload:
                checksum ^= b
            data = payload + bytes([checksum])
            logger.on_message_received(python_can.Message(timestamp=t, arbitration_id=frame_id, is_extended_id=False, data=data, channel=0))
            t += dt
    finally:
        logger.stop()
    return path


# --------------------------------------------------------------------------
# Regression fixtures for bugs found during real-world E2E testing
# --------------------------------------------------------------------------

def generate_multi_channel_collision_trace(
    path: Path,
    frame_id: int = 0x301,
    channel_a: int = 0,
    channel_b: int = 1,
    frame_count_per_channel: int = 30,
    cycle_a_s: float = 0.1,
    cycle_b_s: float = 0.04,
    start_timestamp: float = 1_700_000_000.0,
) -> Path:
    """Two independent periodic streams sharing the SAME arbitration ID on
    two different CAN channels (confirmed real-world pattern: a multi-bus
    logger reusing an ID range across physically separate buses). A
    channel-blind per-ID aggregator merges these into one timeline and
    produces negative/doubled delta-t; a channel-aware one keeps them
    separate with clean, always-positive per-channel delta-t.
    """
    events = []
    for i in range(frame_count_per_channel):
        events.append((start_timestamp + i * cycle_a_s, channel_a, bytes([i % 256]) + bytes(7)))
    for i in range(frame_count_per_channel):
        events.append((start_timestamp + i * cycle_b_s, channel_b, bytes([0xFF - (i % 256)]) + bytes(7)))
    events.sort(key=lambda e: e[0])

    logger = python_can.Logger(filename=str(path))
    try:
        for timestamp, channel, data in events:
            logger.on_message_received(python_can.Message(
                timestamp=timestamp, arbitration_id=frame_id, is_extended_id=False,
                data=data, channel=channel,
            ))
    finally:
        logger.stop()
    return path


def build_extended_id_db() -> can.Database:
    """A minimal non-J1939 DBC using an extended 29-bit arbitration ID —
    canmatrix's .dbf writer/reader round trip is confirmed broken for this
    exact combination (writer omits the extended-ID marker bit the reader
    needs, independent of file content)."""
    signal = can.Signal(name="Value", start=0, length=8, byte_order="little_endian", is_signed=False)
    message = can.Message(frame_id=0x18FF1234, name="ExtendedIdMsg", length=8, signals=[signal], is_extended_frame=True)
    return can.Database(messages=[message], nodes=[], strict=True)


def generate_extended_id_dbc(path: Path) -> Path:
    return write_database(build_extended_id_db(), path)


if __name__ == "__main__":
    generate_all_fixtures()
