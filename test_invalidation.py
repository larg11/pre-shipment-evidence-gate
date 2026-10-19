"""
test_invalidation.py
Production regression suite for Pre-Shipment Evidence Gate.
Verifies cryptographic hash binding, staleness invalidation, audit preservation, and blast-radius isolation.
"""

import copy
import os
import pytest
from gate_kernel import (
    DeterministicGateController,
    EpistemicState,
    EvidenceGraph,
)

FIXTURE_V1_PATH = os.path.join(os.path.dirname(__file__), "fixtures_v1.json")
FIXTURE_V2_MUTATION_PATH = os.path.join(os.path.dirname(__file__), "fixtures_v2_mutation.json")


@pytest.fixture
def test_setup():
    controller = DeterministicGateController()
    graph_inverter = EvidenceGraph.from_fixture(FIXTURE_V1_PATH)

    # Secondary SKU to test blast-radius isolation
    graph_battery = copy.deepcopy(graph_inverter)
    graph_battery.packet_id = "PRE-SHIP-2026-USMCA-0999"
    graph_battery.sku_id = "SKU-BATTERY-PACK-B2"

    graph_registry = {
        graph_inverter.sku_id: graph_inverter,
        graph_battery.sku_id: graph_battery,
    }

    # Grant baseline approvals for both SKUs
    # Chain: Catalog -> CoO (v2) -> FTA (v2) -> Trade Readiness
    dependent_slots = [
        "slot_01_commercial_invoice",
        "slot_04_material_origin_declaration",
        "slot_05_iso_17025_lab_report",
        "slot_06_qima_aql_inspection",
        "slot_07_coo_declaration",
        "slot_11_rvc_calculation",
    ]

    approval_inverter = controller.issue_readiness_approval(
        approval_id="APP-SOLAR-X1-001",
        target_sku=graph_inverter.sku_id,
        determination_chain=["Catalog", "CoO_v2", "FTA_v2", "TradeReadiness"],
        dependent_slots=dependent_slots,
        graph=graph_inverter,
    )

    approval_battery = controller.issue_readiness_approval(
        approval_id="APP-BATT-B2-002",
        target_sku=graph_battery.sku_id,
        determination_chain=["Catalog", "CoO_v2", "FTA_v2", "TradeReadiness"],
        dependent_slots=dependent_slots,
        graph=graph_battery,
    )

    return {
        "controller": controller,
        "graph_inverter": graph_inverter,
        "graph_battery": graph_battery,
        "graph_registry": graph_registry,
        "approval_inverter": approval_inverter,
        "approval_battery": approval_battery,
    }


def test_baseline_valid_approval_grants_release(test_setup):
    """
    Baseline invariant: If all 18 slots match their approved hashes,
    the container can be physically sealed and release cleared.
    """
    controller = test_setup["controller"]
    graph_inverter = test_setup["graph_inverter"]
    app_id = test_setup["approval_inverter"].approval_id

    can_seal, msg = controller.attempt_container_sealing(
        approval_id=app_id,
        graph=graph_inverter,
        container_number="MSKU-982145-0",
    )

    assert can_seal is True
    assert "CONTAINER_SEAL_APPROVED" in msg
    assert graph_inverter.get_slot("slot_17_container_seal_record").data["sealed"] is True
    assert graph_inverter.get_slot("slot_18_pre_shipment_auth").data["release_cleared"] is True


def test_stale_approval_blocks_container_release_on_evidence_mutation(test_setup):
    """
    Core vulnerability test:
    Late-arriving automated recurring SFTP catalog batch updates Slot 4 (material origin).
    Before Trade Readiness manual refresh is clicked, container sealing must be BLOCKED
    because the live hash assertion detects the mutation.
    """
    controller = test_setup["controller"]
    graph_inverter = test_setup["graph_inverter"]
    graph_registry = test_setup["graph_registry"]
    app_id = test_setup["approval_inverter"].approval_id

    # Ingest recurring SFTP catalog mutation (simulates Oct 2026 early access batch)
    invalidated = controller.ingest_recurring_sftp_mutation(
        mutation_fixture_path=FIXTURE_V2_MUTATION_PATH,
        graph_registry=graph_registry,
    )

    assert app_id in invalidated

    # Attempt container sealing with stale approval
    can_seal, msg = controller.attempt_container_sealing(
        approval_id=app_id,
        graph=graph_inverter,
        container_number="MSKU-982145-0",
    )

    assert can_seal is False
    assert "CONTAINER_SEALING_BLOCKED" in msg
    assert "STALE_EVIDENCE_HASH_MISMATCH" in msg or "AUTHORITY_DENIED" in msg
    assert graph_inverter.get_slot("slot_17_container_seal_record").data["sealed"] is False
    assert graph_inverter.get_slot("slot_18_pre_shipment_auth").data["release_cleared"] is False


def test_audit_log_preservation_on_invalidation(test_setup):
    """
    Production Invariant 1 (GPT 6.1 Max synthesis):
    When release authority is revoked due to stale evidence, the approval record
    must NEVER be deleted. It is demoted from Release Authority to Historical Audit Record.
    """
    controller = test_setup["controller"]
    graph_registry = test_setup["graph_registry"]
    app_id = test_setup["approval_inverter"].approval_id

    controller.ingest_recurring_sftp_mutation(
        mutation_fixture_path=FIXTURE_V2_MUTATION_PATH,
        graph_registry=graph_registry,
    )

    # Record must still exist in memory / database
    assert app_id in controller.approvals
    approval = controller.approvals[app_id]

    # Authority stripped, audit preservation intact
    assert approval.status == "STALE_REVOKED"
    assert approval.in_audit_log is True
    assert approval.revoked_at is not None
    assert "STALE_EVIDENCE_HASH_MISMATCH" in approval.revocation_reason

    # Audit event history retained
    events = [entry.event_type for entry in controller.audit_log if entry.approval_id == app_id]
    assert "APPROVAL_ISSUED" in events
    assert "RELEASE_AUTHORITY_REVOKED_ON_EVIDENCE_MUTATION" in events


def test_blast_radius_isolation_unrelated_sku_remains_valid(test_setup):
    """
    Production Invariant 2 (GPT 6.1 Max synthesis):
    Blast-Radius Isolation: Mutating Slot 4 on SKU-SOLAR-INVERTER-X1 must NOT
    invalidate the independent approval for SKU-BATTERY-PACK-B2.
    """
    controller = test_setup["controller"]
    graph_battery = test_setup["graph_battery"]
    graph_registry = test_setup["graph_registry"]
    app_battery_id = test_setup["approval_battery"].approval_id

    # Ingest mutation targeting ONLY the solar inverter
    controller.ingest_recurring_sftp_mutation(
        mutation_fixture_path=FIXTURE_V2_MUTATION_PATH,
        graph_registry=graph_registry,
    )

    # Battery approval must remain fully valid
    battery_approval = controller.approvals[app_battery_id]
    assert battery_approval.status == "APPROVED"
    assert battery_approval.in_audit_log is True

    can_seal_battery, msg_battery = controller.attempt_container_sealing(
        approval_id=app_battery_id,
        graph=graph_battery,
        container_number="BATT-CONT-4401",
    )
    assert can_seal_battery is True
    assert "CONTAINER_SEAL_APPROVED" in msg_battery
