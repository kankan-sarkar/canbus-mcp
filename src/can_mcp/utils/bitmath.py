"""Intel/Motorola bit-matrix & overlap calculator.

Every signal's occupied bits are expressed in one canonical coordinate space
("network" bit index P), so Intel and Motorola signals can be compared
directly for overlap regardless of their own byte order:

    P = byte_index * 8 + (7 - lsb_bit_offset)

i.e. P increases left-to-right, MSB-first, byte0 then byte1 then byte2...
exactly the order the bits are drawn in a Vector-style grid. This matches
cantools' own internal ``start_bit()`` convention (cantools.database.utils),
verified empirically against cantools encode/decode round-trips.
"""
from __future__ import annotations

from dataclasses import dataclass, field

VALID_CLASSIC_DLCS = frozenset(range(0, 9))
VALID_FD_DLCS = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64})


def network_bit_of_intel_lsb(byte_index: int, lsb_bit_offset: int) -> int:
    """Convert a little-endian (Intel) LSB-based bit position to network index P."""
    return byte_index * 8 + (7 - lsb_bit_offset)


def motorola_start_to_network_bit(start: int) -> int:
    """Convert a raw DBC big-endian (Motorola) 'start' field (sawtooth numbering)
    to the network bit index of the signal's MSB.

    Sawtooth byte layout: byte b spans sawtooth bits [8b+7 .. 8b] (MSB..LSB).
    Network layout:       byte b spans network  bits [8b   .. 8b+7] (MSB..LSB).
    """
    return 8 * (start // 8) + (7 - (start % 8))


def signal_bit_positions(signal) -> list[int]:
    """Return the sorted list of network bit indices (P) a signal occupies."""
    length = signal.length
    if signal.byte_order == "big_endian":
        msb_network = motorola_start_to_network_bit(signal.start)
        return list(range(msb_network, msb_network + length))
    # little_endian (Intel): signal.start is already an LSB-based global index.
    positions = []
    for offset in range(length):
        g = signal.start + offset
        byte_index, lsb_bit_offset = divmod(g, 8)
        positions.append(network_bit_of_intel_lsb(byte_index, lsb_bit_offset))
    return sorted(positions)


def network_bit_to_byte_bit(p: int) -> tuple[int, int]:
    """Convert a network index P to (byte_index, bit_number_0_to_7_from_lsb)."""
    byte_index, offset_from_msb = divmod(p, 8)
    bit_number = 7 - offset_from_msb
    return byte_index, bit_number


@dataclass
class OverlapResult:
    signal_a: str
    signal_b: str
    colliding_bits: list[int] = field(default_factory=list)

    @property
    def colliding_byte_bit_labels(self) -> list[str]:
        return [f"byte{b}.bit{bit}" for b, bit in (network_bit_to_byte_bit(p) for p in self.colliding_bits)]


def _mux_groups_can_coexist(sig_a, sig_b) -> bool:
    """True if sig_a and sig_b could both be "active" at the same time, i.e. a
    real bit collision rather than mutually-exclusive multiplexed branches.
    """
    ids_a = getattr(sig_a, "multiplexer_ids", None)
    ids_b = getattr(sig_b, "multiplexer_ids", None)
    if ids_a and ids_b:
        return bool(set(ids_a) & set(ids_b))
    # One or both are not conditioned on a multiplexer value (e.g. the mux
    # switch itself, or a plain non-muxed signal) -> always active -> collide.
    return True


def find_bit_overlaps(message) -> list[OverlapResult]:
    """Detect genuine bit collisions between every pair of signals in a message,
    skipping pairs that are mutually-exclusive multiplexed branches.
    """
    signals = list(message.signals)
    results: list[OverlapResult] = []
    for i in range(len(signals)):
        for j in range(i + 1, len(signals)):
            sig_a, sig_b = signals[i], signals[j]
            if not _mux_groups_can_coexist(sig_a, sig_b):
                continue
            bits_a = set(signal_bit_positions(sig_a))
            bits_b = set(signal_bit_positions(sig_b))
            collision = sorted(bits_a & bits_b)
            if collision:
                results.append(OverlapResult(sig_a.name, sig_b.name, collision))
    return results


def find_free_bit_block(
    message, length: int, byte_order: str, exclude_signal_name: str | None = None,
) -> int | None:
    """First-fit scan for a contiguous free span of `length` bits matching
    `byte_order`, returning the raw DBC 'start' value to use (LSB index for
    little_endian, sawtooth MSB index for big_endian), or None if no block
    of that size is free.

    `exclude_signal_name` lets a signal being updated ignore its own
    currently-occupied bits while scanning.
    """
    max_bits = message.length * 8
    occupied: set[int] = set()
    for signal in message.signals:
        if signal.name == exclude_signal_name:
            continue
        occupied |= set(signal_bit_positions(signal))

    if byte_order == "little_endian":
        for g in range(0, max_bits - length + 1):
            positions = {network_bit_of_intel_lsb(*divmod(g + i, 8)) for i in range(length)}
            if not positions & occupied:
                return g
        return None

    for p in range(0, max_bits - length + 1):
        positions = set(range(p, p + length))
        if not positions & occupied:
            return motorola_start_to_network_bit(p)  # involution: network -> sawtooth
    return None


def signals_exceeding_dlc(message) -> list[str]:
    """Names of signals whose occupied bits run past message.length * 8."""
    max_bit = message.length * 8
    offenders = []
    for signal in message.signals:
        positions = signal_bit_positions(signal)
        if positions and max(positions) >= max_bit:
            offenders.append(signal.name)
    return offenders


def is_valid_fd_dlc(byte_length: int) -> bool:
    return byte_length in VALID_FD_DLCS


@dataclass
class GridCell:
    byte_index: int
    bit_number: int  # 0 (LSB) .. 7 (MSB), matches DBC convention
    network_index: int
    occupant: str | None = None
    tag: str = ""


def build_bit_grid(message) -> list[GridCell]:
    """Build a flat list of cells (one per bit, MSB-first-per-byte order i.e.
    network order) describing which signal (if any) occupies each bit, plus
    multiplexer tags ([M] for the switch, [m<value>] for a branch).
    """
    total_bits = message.length * 8
    cells = [
        GridCell(byte_index=p // 8, bit_number=network_bit_to_byte_bit(p)[1], network_index=p)
        for p in range(total_bits)
    ]
    for signal in message.signals:
        tag = ""
        if getattr(signal, "is_multiplexer", False):
            tag = "[M]"
        elif getattr(signal, "multiplexer_ids", None):
            tag = "[m{}]".format(",".join(str(v) for v in signal.multiplexer_ids))
        for p in signal_bit_positions(signal):
            if 0 <= p < total_bits:
                cells[p].occupant = signal.name
                cells[p].tag = tag
    return cells


def render_ascii_grid(message) -> str:
    """Render an explicit ASCII byte/bit grid for a message.

    Columns are bit 7 (MSB) .. bit 0 (LSB) per byte, matching standard DBC
    bit-numbering display convention, with free spans marked '.'.
    """
    cells = build_bit_grid(message)
    num_bytes = message.length
    header = "      " + " ".join(f"b{n}" for n in range(7, -1, -1))
    lines = [f"Frame: {message.name} (DLC={message.length})", header]
    for byte_index in range(num_bytes):
        row_cells = [c for c in cells if c.byte_index == byte_index]
        row_cells.sort(key=lambda c: c.bit_number, reverse=True)  # bit7..bit0
        rendered = []
        for cell in row_cells:
            if cell.occupant is None:
                rendered.append(" . ")
            else:
                initials = "".join(w[0] for w in cell.occupant.replace("_", " ").split())[:2].upper()
                rendered.append(f"{initials:>2}{cell.tag[:1]}" if cell.tag else f"{initials:>2} ")
        lines.append(f"byte{byte_index}: " + " ".join(rendered))
    return "\n".join(lines)
