"""Stage 3 Test & Validation Gate (REQUIREMENTS.md section 4, Stage 3.2)."""
from __future__ import annotations

import cantools
import pytest

from can_mcp.engines import dbc_engine
from tests.fixtures import generator

ALL_TEMPLATE_TYPES = ["raw_can", "can_fd", "j1939_skeleton", "canopen_cia301", "uds_iso15765"]


@pytest.fixture()
def scratch_path():
    paths = []

    def _make(name: str):
        path = generator.FIXTURES_DIR / name
        paths.append(path)
        return path

    yield _make
    for path in paths:
        for extra in (path, path.with_name(path.name + ".bak"), path.with_name(path.stem + ".tmp" + path.suffix)):
            if extra.exists():
                extra.unlink()


@pytest.fixture()
def template_paths():
    paths = {t: generator.FIXTURES_DIR / f"_stage3_{t}.dbc" for t in ALL_TEMPLATE_TYPES}
    yield paths
    for path in paths.values():
        for extra in (path, path.with_name(path.name + ".bak")):
            if extra.exists():
                extra.unlink()


class TestGate3_1_Templates:
    """Gate 3.1: All 4 templates (raw_can, j1939_skeleton, canopen_cia301,
    uds_iso15765) generate from scratch and pass validate_database_integrity
    with zero warnings.
    """

    @pytest.mark.parametrize("template_type", ALL_TEMPLATE_TYPES)
    def test_template_generates_and_validates_clean(self, template_paths, template_type):
        path = template_paths[template_type]
        node_names = ["NodeA", "NodeB"] if template_type != "raw_can" and template_type != "can_fd" else ["NodeA"]
        result = dbc_engine.generate_database_from_template(str(path), template_type, node_names=node_names)
        assert result["success"] is True
        assert path.exists()

        report = dbc_engine.validate_database_integrity(str(path))
        assert report["issue_count"] == 0
        assert report["is_valid"] is True

    def test_unknown_template_type_rejected(self, template_paths):
        from can_mcp.models.errors import CanMcpError
        path = template_paths["raw_can"]
        with pytest.raises(CanMcpError) as excinfo:
            dbc_engine.generate_database_from_template(str(path), "not_a_real_template")
        assert excinfo.value.error_code == "UNKNOWN_TEMPLATE_TYPE"

    def test_j1939_skeleton_structure(self, template_paths):
        path = template_paths["j1939_skeleton"]
        dbc_engine.generate_database_from_template(str(path), "j1939_skeleton", node_names=["ECU_Brake"])
        db = cantools.database.load_file(str(path))

        address_claimed = db.get_message_by_name("AddressClaimed_ECU_Brake")
        assert address_claimed.is_extended_frame is True
        assert address_claimed.protocol == "j1939"
        assert hex(address_claimed.frame_id) == hex((6 << 26) | (0xEE << 16) | (0xFF << 8) | 0)

        request = db.get_message_by_name("RequestPGN")
        assert hex(request.frame_id) == hex((6 << 26) | (0xEA << 16) | (0xFF << 8) | 0xFE)

        tp_cm = db.get_message_by_name("TP_CM_BAM")
        assert hex(tp_cm.frame_id) == hex((7 << 26) | (0xEC << 16) | (0xFF << 8) | 0xFE)

        tp_dt = db.get_message_by_name("TP_DT")
        assert hex(tp_dt.frame_id) == hex((7 << 26) | (0xEB << 16) | (0xFF << 8) | 0xFE)

        dm1 = db.get_message_by_name("DM1_ActiveDTCs_ECU_Brake")
        assert hex(dm1.frame_id) == hex((6 << 26) | (0xFE << 16) | (0xCA << 8) | 0)

    def test_canopen_cia301_cob_ids(self, template_paths):
        path = template_paths["canopen_cia301"]
        dbc_engine.generate_database_from_template(str(path), "canopen_cia301", node_names=["Drive1"])
        db = cantools.database.load_file(str(path))

        assert db.get_message_by_name("NMT").frame_id == 0x000
        assert db.get_message_by_name("SYNC").frame_id == 0x080
        assert db.get_message_by_name("EMCY_Drive1").frame_id == 0x080 + 1
        assert db.get_message_by_name("TPDO1_Drive1").frame_id == 0x180 + 1
        assert db.get_message_by_name("RPDO1_Drive1").frame_id == 0x200 + 1
        assert db.get_message_by_name("TSDO_Drive1").frame_id == 0x580 + 1
        assert db.get_message_by_name("RSDO_Drive1").frame_id == 0x600 + 1
        assert db.get_message_by_name("Heartbeat_Drive1").frame_id == 0x700 + 1

        heartbeat_state = next(s for s in db.get_message_by_name("Heartbeat_Drive1").signals if s.name == "NMTState")
        assert dict(heartbeat_state.choices) == {0: "Boot-up", 4: "Stopped", 5: "Operational", 127: "Pre-operational"}

    def test_uds_iso15765_functional_and_physical_ids(self, template_paths):
        path = template_paths["uds_iso15765"]
        dbc_engine.generate_database_from_template(str(path), "uds_iso15765", node_names=["Tester", "ECU"])
        db = cantools.database.load_file(str(path))

        assert db.get_message_by_frame_id(0x7DF).name == "UDS_FunctionalRequest"
        physical_request_ids = {db.get_message_by_frame_id(0x7E0 + i).frame_id for i in range(8)}
        physical_response_ids = {db.get_message_by_frame_id(0x7E8 + i).frame_id for i in range(8)}
        assert physical_request_ids == set(range(0x7E0, 0x7E8))
        assert physical_response_ids == set(range(0x7E8, 0x7F0))


class TestGate3_2_FormatRoundTrip:
    """Gate 3.2: Round-trip conversion .dbc -> .dbf (Busmaster) -> .dbc
    preserves 100% of frame IDs, DLCs, signal start bits, lengths,
    endianness, scaling, and offsets.
    """

    @pytest.fixture()
    def roundtrip_paths(self):
        source = generator.generate_sample_powertrain()
        dbf_path = generator.FIXTURES_DIR / "_stage3_roundtrip.dbf"
        back_path = generator.FIXTURES_DIR / "_stage3_roundtrip_back.dbc"
        yield source, dbf_path, back_path
        for extra in (dbf_path, back_path, back_path.with_name(back_path.name + ".bak")):
            if extra.exists():
                extra.unlink()

    def test_dbc_to_dbf_to_dbc_preserves_structure(self, roundtrip_paths):
        source, dbf_path, back_path = roundtrip_paths

        to_dbf = dbc_engine.convert_database_format(str(source), str(dbf_path), target_format="dbf")
        assert to_dbf["success"] is True
        assert dbf_path.exists()

        back_to_dbc = dbc_engine.convert_database_format(str(dbf_path), str(back_path), target_format="dbc")
        assert back_to_dbc["success"] is True
        assert back_path.exists()

        original = cantools.database.load_file(str(source))
        roundtripped = cantools.database.load_file(str(back_path))

        assert len(original.messages) == len(roundtripped.messages)
        for orig_msg in original.messages:
            rt_msg = roundtripped.get_message_by_frame_id(orig_msg.frame_id)
            assert rt_msg.name == orig_msg.name
            assert rt_msg.length == orig_msg.length
            assert len(rt_msg.signals) == len(orig_msg.signals)
            for orig_sig in orig_msg.signals:
                rt_sig = next(s for s in rt_msg.signals if s.name == orig_sig.name)
                assert rt_sig.start == orig_sig.start
                assert rt_sig.length == orig_sig.length
                assert rt_sig.byte_order == orig_sig.byte_order
                assert rt_sig.is_signed == orig_sig.is_signed
                assert rt_sig.scale == orig_sig.scale
                assert rt_sig.offset == orig_sig.offset

    def test_roundtrip_reports_no_attribute_loss(self, roundtrip_paths):
        source, dbf_path, back_path = roundtrip_paths
        to_dbf = dbc_engine.convert_database_format(str(source), str(dbf_path), target_format="dbf")
        assert to_dbf["attribute_loss"] == []
        back_to_dbc = dbc_engine.convert_database_format(str(dbf_path), str(back_path), target_format="dbc")
        assert back_to_dbc["attribute_loss"] == []

    def test_dry_run_does_not_write_output(self, roundtrip_paths):
        source, dbf_path, _ = roundtrip_paths
        result = dbc_engine.convert_database_format(str(source), str(dbf_path), target_format="dbf", dry_run=True)
        assert result["dry_run"] is True
        assert not dbf_path.exists()


class TestGate3_3_DiffDatabases:
    """Gate 3.3: diff_databases accurately pinpoints a 1-bit shift and a
    changed scale factor (0.1 -> 0.01) between two test databases.
    """

    @pytest.fixture()
    def diff_db_paths(self):
        path_a = generator.FIXTURES_DIR / "_stage3_diff_a.dbc"
        path_b = generator.FIXTURES_DIR / "_stage3_diff_b.dbc"

        dbc_engine.generate_database_from_template(str(path_a), "raw_can", node_names=["N1"])
        dbc_engine.upsert_dbc_message(str(path_a), 0x200, "DiffMsg", 8, "N1")
        dbc_engine.add_or_update_signal(str(path_a), "DiffMsg", "SigShift", 8, start_bit=0)
        dbc_engine.add_or_update_signal(str(path_a), "DiffMsg", "SigScale", 8, start_bit=16, scale=0.1)
        dbc_engine.add_or_update_signal(str(path_a), "DiffMsg", "SigRemoved", 4, start_bit=24)

        dbc_engine.generate_database_from_template(str(path_b), "raw_can", node_names=["N1"])
        dbc_engine.upsert_dbc_message(str(path_b), 0x200, "DiffMsg", 8, "N1")
        dbc_engine.add_or_update_signal(str(path_b), "DiffMsg", "SigShift", 8, start_bit=1)
        dbc_engine.add_or_update_signal(str(path_b), "DiffMsg", "SigScale", 8, start_bit=16, scale=0.01)
        dbc_engine.add_or_update_signal(str(path_b), "DiffMsg", "SigAdded", 4, start_bit=28)

        yield path_a, path_b
        for path in (path_a, path_b):
            for extra in (path, path.with_name(path.name + ".bak")):
                if extra.exists():
                    extra.unlink()

    def test_detects_exact_one_bit_shift(self, diff_db_paths):
        path_a, path_b = diff_db_paths
        report = dbc_engine.diff_databases(str(path_a), str(path_b))
        shifts = report["bit_shift_changes"]
        assert len(shifts) == 1
        assert shifts[0]["message"] == "DiffMsg"
        assert shifts[0]["signal"] == "SigShift"
        assert shifts[0]["old_start_bit"] == 0
        assert shifts[0]["new_start_bit"] == 1
        assert shifts[0]["shift_bits"] == 1

    def test_detects_scale_factor_change(self, diff_db_paths):
        path_a, path_b = diff_db_paths
        report = dbc_engine.diff_databases(str(path_a), str(path_b))
        scale_changes = report["scaling_changes"]
        assert len(scale_changes) == 1
        assert scale_changes[0]["message"] == "DiffMsg"
        assert scale_changes[0]["signal"] == "SigScale"
        assert scale_changes[0]["old_scale"] == pytest.approx(0.1)
        assert scale_changes[0]["new_scale"] == pytest.approx(0.01)

    def test_detects_added_and_removed_signals(self, diff_db_paths):
        path_a, path_b = diff_db_paths
        report = dbc_engine.diff_databases(str(path_a), str(path_b))
        assert report["added_signals"] == [{"message": "DiffMsg", "signal": "SigAdded"}]
        assert report["removed_signals"] == [{"message": "DiffMsg", "signal": "SigRemoved"}]

    def test_no_message_level_changes_when_identical(self, diff_db_paths):
        path_a, _ = diff_db_paths
        report = dbc_engine.diff_databases(str(path_a), str(path_a))
        assert report == {
            "added_messages": [], "removed_messages": [],
            "added_signals": [], "removed_signals": [],
            "bit_shift_changes": [], "scaling_changes": [], "cycle_time_changes": [],
        }


class TestConvertDatabaseFormatCriticalFailureRegression:
    """Regression for a bug found testing against a real DBC: canmatrix's
    .dbf writer doesn't set the extended-ID marker bit for non-J1939
    protocol frames, so its own .dbf reader then rejects the file it just
    wrote ("ID out of range") — and convert_database_format was reporting
    success=True anyway, burying a fatal failure inside attribute_loss.
    """

    def test_unreadable_dbf_output_raises_instead_of_silently_succeeding(self, scratch_path):
        from can_mcp.models.errors import CanMcpError

        dbc_path = scratch_path("extended_id_source.dbc")
        generator.generate_extended_id_dbc(dbc_path)
        dbf_path = scratch_path("extended_id_source.dbf")

        with pytest.raises(CanMcpError) as excinfo:
            dbc_engine.convert_database_format(str(dbc_path), str(dbf_path))

        assert excinfo.value.error_code == "CONVERSION_UNREADABLE"
        assert not dbf_path.exists()
