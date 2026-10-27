"""Stage 2 Test & Validation Gate (REQUIREMENTS.md section 4, Stage 2.2)."""
from __future__ import annotations

import cantools
import pytest

from can_mcp.engines import dbc_engine
from can_mcp.models.errors import CanMcpError
from tests.fixtures import generator

WORKING_DBC_NAME = "_stage2_working.dbc"


@pytest.fixture()
def working_dbc_path():
    """A private, per-test mutable copy of the sample powertrain DBC, so
    Stage 2 mutations never touch the shared Stage 1 fixture.
    """
    path = generator.FIXTURES_DIR / WORKING_DBC_NAME
    generator.generate_sample_powertrain(path)
    yield path
    for extra in (path, path.with_name(path.name + ".bak"), path.with_name(path.name + ".tmp")):
        if extra.exists():
            extra.unlink()


class TestGate2_1_AtomicBackup:
    """Gate 2.1: Every mutation creates a <filename>.dbc.bak file prior to
    modifying the target file.
    """

    def test_manage_ecu_node_creates_backup_with_prior_content(self, working_dbc_path):
        original = working_dbc_path.read_text()
        result = dbc_engine.manage_ecu_node(str(working_dbc_path), "add", "ECU_Brake")
        backup = working_dbc_path.with_name(working_dbc_path.name + ".bak")
        assert backup.exists()
        assert backup.read_text() == original
        assert result["backup_path"] == str(backup)

    def test_upsert_dbc_message_creates_backup(self, working_dbc_path):
        original = working_dbc_path.read_text()
        dbc_engine.upsert_dbc_message(str(working_dbc_path), 0x300, "BrakeStatus", 8, "ECU_ABS")
        backup = working_dbc_path.with_name(working_dbc_path.name + ".bak")
        assert backup.exists()
        assert backup.read_text() == original

    def test_add_or_update_signal_creates_backup(self, working_dbc_path):
        original = working_dbc_path.read_text()
        dbc_engine.add_or_update_signal(str(working_dbc_path), "EngineData", "NewSig", 4, auto_pack=True)
        backup = working_dbc_path.with_name(working_dbc_path.name + ".bak")
        assert backup.exists()
        assert backup.read_text() == original

    def test_delete_dbc_signal_creates_backup(self, working_dbc_path):
        original = working_dbc_path.read_text()
        dbc_engine.delete_dbc_signal(str(working_dbc_path), "EngineData", "CoolantTemp")
        backup = working_dbc_path.with_name(working_dbc_path.name + ".bak")
        assert backup.exists()
        assert backup.read_text() == original

    def test_delete_dbc_message_creates_backup(self, working_dbc_path):
        original = working_dbc_path.read_text()
        dbc_engine.delete_dbc_message(str(working_dbc_path), "WheelSpeeds")
        backup = working_dbc_path.with_name(working_dbc_path.name + ".bak")
        assert backup.exists()
        assert backup.read_text() == original

    def test_dry_run_never_writes_file_or_backup(self, working_dbc_path):
        original = working_dbc_path.read_text()
        result = dbc_engine.add_or_update_signal(
            str(working_dbc_path), "EngineData", "DryRunSig", 4, auto_pack=True, dry_run=True,
        )
        backup = working_dbc_path.with_name(working_dbc_path.name + ".bak")
        assert result["dry_run"] is True
        assert result["backup_path"] is None
        assert not backup.exists()
        assert working_dbc_path.read_text() == original


class TestGate2_2_CollisionRejection:
    """Gate 2.2: Attempting to add a signal overlapping an existing signal
    raises a structured validation error and leaves the original .dbc file
    untouched.
    """

    def test_explicit_overlap_raises_structured_error(self, working_dbc_path):
        with pytest.raises(CanMcpError) as excinfo:
            dbc_engine.add_or_update_signal(
                str(working_dbc_path), "EngineData", "Overlapper", 8,
                start_bit=4, byte_order="little_endian",
            )
        assert excinfo.value.error_code == "SIGNAL_BIT_OVERLAP"
        assert excinfo.value.suggested_fix
        assert "conflict_layout" in excinfo.value.extra

    def test_original_file_untouched_after_rejected_mutation(self, working_dbc_path):
        original = working_dbc_path.read_text()
        with pytest.raises(CanMcpError):
            dbc_engine.add_or_update_signal(
                str(working_dbc_path), "EngineData", "Overlapper", 8,
                start_bit=4, byte_order="little_endian",
            )
        assert working_dbc_path.read_text() == original
        assert not working_dbc_path.with_name(working_dbc_path.name + ".bak").exists()

    def test_motorola_overlap_also_rejected(self, working_dbc_path):
        with pytest.raises(CanMcpError) as excinfo:
            dbc_engine.add_or_update_signal(
                str(working_dbc_path), "WheelSpeeds", "MotorolaOverlap", 4,
                start_bit=23, byte_order="big_endian",
            )
        assert excinfo.value.error_code == "SIGNAL_BIT_OVERLAP"

    def test_auto_pack_reports_no_free_block_when_frame_is_full(self, working_dbc_path):
        # EngineData already uses bits [0..23] (EngineSpeed + CoolantTemp);
        # 4+12+16+8 = 40 bits exactly fills the remaining [24..63] space.
        specs = [("S1", 4), ("S2", 12), ("S3", 16), ("S4", 8)]
        for name, length in specs:
            dbc_engine.add_or_update_signal(str(working_dbc_path), "EngineData", name, length, auto_pack=True)
        with pytest.raises(CanMcpError) as excinfo:
            dbc_engine.add_or_update_signal(str(working_dbc_path), "EngineData", "Overflow", 1, auto_pack=True)
        assert excinfo.value.error_code == "NO_FREE_BIT_BLOCK"


class TestGate2_3_AutoPacker:
    """Gate 2.3: auto_pack=True packs five sequential signals (4-bit, 12-bit,
    16-bit, 8-bit, 24-bit) into an 8-byte frame with zero overlaps, verified
    by cantools round-trip encoding/decoding.
    """

    SPECS = [("Nibble4", 4), ("Field12", 12), ("Field16", 16), ("Byte8", 8), ("Block24", 24)]

    def test_five_signals_pack_with_zero_overlap(self, working_dbc_path):
        # EngineData already has EngineSpeed(16) + CoolantTemp(8) = 24 bits used;
        # pack into a dedicated fresh frame to pack the full 64 bits as specified.
        dbc_engine.upsert_dbc_message(str(working_dbc_path), 0x500, "PackTarget", 8, "ECU_Engine")
        starts = {}
        for name, length in self.SPECS:
            result = dbc_engine.add_or_update_signal(str(working_dbc_path), "PackTarget", name, length, auto_pack=True)
            starts[name] = result["details"]["start_bit"]

        assert starts == {"Nibble4": 0, "Field12": 4, "Field16": 16, "Byte8": 32, "Block24": 40}

        db = cantools.database.load_file(str(working_dbc_path))
        report = dbc_engine.validate_database_integrity(str(working_dbc_path))
        pack_issues = [i for i in report["issues"] if i["message_name"] == "PackTarget"]
        assert pack_issues == []

        message = db.get_message_by_name("PackTarget")
        assert message.length == 8
        values = {"Nibble4": 9, "Field12": 2047, "Field16": 54321, "Byte8": 200, "Block24": 7654321}
        encoded = message.encode(values)
        decoded = message.decode(encoded)
        assert decoded == values

    def test_auto_pack_respects_existing_signals_in_frame(self, working_dbc_path):
        # EngineData already occupies LSB bits [0..23] (EngineSpeed + CoolantTemp).
        result = dbc_engine.add_or_update_signal(str(working_dbc_path), "EngineData", "NewGauge", 8, auto_pack=True)
        assert result["details"]["start_bit"] == 24

        db = cantools.database.load_file(str(working_dbc_path))
        message = db.get_message_by_name("EngineData")
        encoded = message.encode({"EngineSpeed": 0, "CoolantTemp": -40, "NewGauge": 77})
        assert message.decode(encoded)["NewGauge"] == 77


class TestGate2_4_MultiplexingAndEnumValues:
    """Gate 2.4: Successfully creates a multiplexer switch signal (MuxId)
    and two multiplexed branches (m0, m1) occupying the same bits, plus a
    VAL_ state table (0="Init", 1="Active", 2="Fault").
    """

    @pytest.fixture()
    def mux_message_path(self, working_dbc_path):
        dbc_engine.upsert_dbc_message(str(working_dbc_path), 0x510, "MuxTarget", 2, "Gateway")
        dbc_engine.add_or_update_signal(str(working_dbc_path), "MuxTarget", "MuxId", 4, start_bit=0, mux_is_switch=True)
        dbc_engine.add_or_update_signal(
            str(working_dbc_path), "MuxTarget", "Branch_m0", 4, start_bit=4, mux_value=0,
            value_table={0: "Init", 1: "Active", 2: "Fault"},
        )
        dbc_engine.add_or_update_signal(
            str(working_dbc_path), "MuxTarget", "Branch_m1", 4, start_bit=4, mux_value=1,
            value_table={0: "Init", 1: "Active", 2: "Fault"},
        )
        return working_dbc_path

    def test_switch_and_branches_occupy_expected_bits(self, mux_message_path):
        db = cantools.database.load_file(str(mux_message_path))
        message = db.get_message_by_name("MuxTarget")
        mux_switch = next(s for s in message.signals if s.name == "MuxId")
        branch0 = next(s for s in message.signals if s.name == "Branch_m0")
        branch1 = next(s for s in message.signals if s.name == "Branch_m1")

        assert mux_switch.is_multiplexer is True
        assert branch0.start == branch1.start == 4
        assert branch0.multiplexer_ids == [0]
        assert branch1.multiplexer_ids == [1]
        assert branch0.multiplexer_signal == "MuxId"
        assert branch1.multiplexer_signal == "MuxId"

    def test_val_table_round_trips(self, mux_message_path):
        db = cantools.database.load_file(str(mux_message_path))
        message = db.get_message_by_name("MuxTarget")
        branch0 = next(s for s in message.signals if s.name == "Branch_m0")
        assert dict(branch0.choices) == {0: "Init", 1: "Active", 2: "Fault"}

    def test_mutually_exclusive_branches_report_no_overlap(self, mux_message_path):
        report = dbc_engine.validate_database_integrity(str(mux_message_path))
        mux_issues = [i for i in report["issues"] if i["message_name"] == "MuxTarget"]
        assert mux_issues == []

    def test_mux_switch_and_branches_round_trip_via_encode_decode(self, mux_message_path):
        db = cantools.database.load_file(str(mux_message_path))
        message = db.get_message_by_name("MuxTarget")
        encoded0 = message.encode({"MuxId": 0, "Branch_m0": 1})
        assert message.decode(encoded0) == {"MuxId": 0, "Branch_m0": "Active"}
        encoded1 = message.encode({"MuxId": 1, "Branch_m1": 2})
        assert message.decode(encoded1) == {"MuxId": 1, "Branch_m1": "Fault"}

    def test_deleting_switch_while_branches_exist_is_rejected(self, mux_message_path):
        with pytest.raises(CanMcpError) as excinfo:
            dbc_engine.delete_dbc_signal(str(mux_message_path), "MuxTarget", "MuxId")
        assert excinfo.value.error_code == "MUX_SWITCH_IN_USE"
