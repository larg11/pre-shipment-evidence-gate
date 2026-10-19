"""
pre-shipment-evidence-gate / gate_kernel.py
Deterministic kernel for pre-shipment evidence validation, hash binding, and staleness invalidation.
Separates deterministic kernel assertions from probabilistic LLM extraction.
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


class EpistemicState(str, enum.Enum):
    ASSERTED = "ASSERTED"
    CORROBORATED = "CORROBORATED"
    UNKNOWN = "UNKNOWN"


def compute_canonical_hash(payload: Any) -> str:
    """Computes a deterministic SHA-256 hash over canonical JSON bytes."""
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass
class EvidenceSlot:
    slot_id: str
    slot_name: str
    epistemic_state: EpistemicState
    source_uri: str
    data: Dict[str, Any]
    content_hash: str = ""

    def __post_init__(self):
        if not self.content_hash:
            self.recompute_hash()

    def recompute_hash(self) -> str:
        payload = {
            "slot_id": self.slot_id,
            "epistemic_state": self.epistemic_state.value,
            "source_uri": self.source_uri,
            "data": self.data,
        }
        self.content_hash = compute_canonical_hash(payload)
        return self.content_hash

    def update_data(self, new_data: Dict[str, Any], new_state: Optional[EpistemicState] = None, new_source_uri: Optional[str] = None) -> None:
        self.data = new_data
        if new_state is not None:
            self.epistemic_state = new_state
        if new_source_uri is not None:
            self.source_uri = new_source_uri
        self.recompute_hash()


@dataclass
class EvidenceGraph:
    packet_id: str
    sku_id: str
    slots: Dict[str, EvidenceSlot] = field(default_factory=dict)

    @classmethod
    def from_fixture(cls, fixture_path: str) -> EvidenceGraph:
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        graph = cls(packet_id=raw["packet_id"], sku_id=raw["sku_id"])
        for item in raw["slots"]:
            slot = EvidenceSlot(
                slot_id=item["slot_id"],
                slot_name=item["slot_name"],
                epistemic_state=EpistemicState(item["epistemic_state"]),
                source_uri=item["source_uri"],
                data=item["data"],
            )
            graph.slots[slot.slot_id] = slot
        return graph

    def get_slot(self, slot_id: str) -> EvidenceSlot:
        if slot_id not in self.slots:
            raise KeyError(f"Slot {slot_id} does not exist in graph {self.packet_id}")
        return self.slots[slot_id]

    def mutate_slot(self, slot_id: str, new_data: Dict[str, Any], new_state: Optional[EpistemicState] = None, new_source_uri: Optional[str] = None) -> str:
        slot = self.get_slot(slot_id)
        slot.update_data(new_data, new_state, new_source_uri)
        return slot.content_hash


@dataclass
class AuditEntry:
    timestamp: str
    event_type: str
    approval_id: str
    sku_id: str
    details: Dict[str, Any]


@dataclass
class ReadinessApproval:
    approval_id: str
    target_sku: str
    determination_chain: List[str]
    approved_evidence_hashes: Dict[str, str]
    created_at: str
    status: str = "APPROVED"  # APPROVED | STALE_REVOKED
    in_audit_log: bool = True  # Production Invariant 1: immutable historical retention
    revocation_reason: Optional[str] = None
    revoked_at: Optional[str] = None

    def evaluate_live_release_authority(self, current_graph: EvidenceGraph) -> Tuple[bool, str]:
        """
        Cryptographic verification gate.
        Checks current evidence graph against snapshot hashes bound at approval time.
        """
        if self.status != "APPROVED":
            return False, f"AUTHORITY_DENIED: Approval status is {self.status} (Reason: {self.revocation_reason})"

        for slot_id, expected_hash in self.approved_evidence_hashes.items():
            if slot_id not in current_graph.slots:
                return False, f"AUTHORITY_DENIED: Required evidence slot {slot_id} missing from live graph"
            
            current_slot = current_graph.slots[slot_id]
            if current_slot.content_hash != expected_hash:
                return (
                    False,
                    f"STALE_EVIDENCE_HASH_MISMATCH: Slot {slot_id} mutated. Expected {expected_hash[:12]}..., got {current_slot.content_hash[:12]}...",
                )

        return True, "RELEASE_AUTHORIZED: All cryptographic hash assertions verified against current evidence graph"

    def revoke_release_authority(self, reason: str) -> None:
        """Demotes release authority without destroying audit record."""
        self.status = "STALE_REVOKED"
        self.revocation_reason = reason
        self.revoked_at = datetime.now(timezone.utc).isoformat()
        # self.in_audit_log remains True permanently


class DeterministicGateController:
    """
    Manages deterministic gate approvals, automated recurring ingestion mutations,
    and container sealing verification.
    """

    def __init__(self):
        self.approvals: Dict[str, ReadinessApproval] = {}
        self.audit_log: List[AuditEntry] = []

    def issue_readiness_approval(
        self,
        approval_id: str,
        target_sku: str,
        determination_chain: List[str],
        dependent_slots: List[str],
        graph: EvidenceGraph,
    ) -> ReadinessApproval:
        # Snapshot exact slot hashes at the moment of approval
        bound_hashes: Dict[str, str] = {}
        for s_id in dependent_slots:
            slot = graph.get_slot(s_id)
            bound_hashes[s_id] = slot.content_hash

        now = datetime.now(timezone.utc).isoformat()
        approval = ReadinessApproval(
            approval_id=approval_id,
            target_sku=target_sku,
            determination_chain=determination_chain,
            approved_evidence_hashes=bound_hashes,
            created_at=now,
            status="APPROVED",
            in_audit_log=True,
        )
        self.approvals[approval_id] = approval
        self.audit_log.append(
            AuditEntry(
                timestamp=now,
                event_type="APPROVAL_ISSUED",
                approval_id=approval_id,
                sku_id=target_sku,
                details={"bound_slots": list(bound_hashes.keys()), "determination_chain": determination_chain},
            )
        )
        return approval

    def ingest_recurring_sftp_mutation(
        self,
        mutation_fixture_path: str,
        graph_registry: Dict[str, EvidenceGraph],
    ) -> List[str]:
        """
        Simulates late-arriving automated recurring SFTP catalog batch ingestion.
        Mutates the target graph and triggers deterministic staleness evaluation.
        """
        with open(mutation_fixture_path, "r", encoding="utf-8") as f:
            mutation_data = json.load(f)

        target_sku = mutation_data["target_sku"]
        if target_sku not in graph_registry:
            raise KeyError(f"Target SKU {target_sku} not in registry")

        graph = graph_registry[target_sku]
        invalidated_approvals: List[str] = []

        for mutated_slot in mutation_data["mutated_slots"]:
            s_id = mutated_slot["slot_id"]
            new_state = EpistemicState(mutated_slot["epistemic_state"])
            new_data = mutated_slot["data"]
            new_uri = mutated_slot["source_uri"]

            graph.mutate_slot(s_id, new_data, new_state, new_uri)

            # Invalidate any approval whose hash bindings are violated
            for app_id, app in self.approvals.items():
                if app.target_sku == target_sku and s_id in app.approved_evidence_hashes:
                    authorized, reason = app.evaluate_live_release_authority(graph)
                    if not authorized and app.status == "APPROVED":
                        app.revoke_release_authority(reason)
                        invalidated_approvals.append(app_id)
                        self.audit_log.append(
                            AuditEntry(
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                event_type="RELEASE_AUTHORITY_REVOKED_ON_EVIDENCE_MUTATION",
                                approval_id=app_id,
                                sku_id=target_sku,
                                details={"mutated_slot": s_id, "reason": reason, "in_audit_log": app.in_audit_log},
                            )
                        )

        return invalidated_approvals

    def attempt_container_sealing(
        self,
        approval_id: str,
        graph: EvidenceGraph,
        container_number: str,
    ) -> Tuple[bool, str]:
        """
        Physical container release gate.
        Container sealing is blocked if the approval has lost release authority.
        """
        if approval_id not in self.approvals:
            return False, f"SEAL_FAILED: Unknown approval ID {approval_id}"

        approval = self.approvals[approval_id]
        authorized, reason = approval.evaluate_live_release_authority(graph)

        if not authorized:
            self.audit_log.append(
                AuditEntry(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_type="CONTAINER_SEAL_BLOCKED",
                    approval_id=approval_id,
                    sku_id=graph.sku_id,
                    details={"container": container_number, "reason": reason},
                )
            )
            return False, f"CONTAINER_SEALING_BLOCKED: {reason}"

        # Mark slot 17 and 18 as sealed and cleared
        graph.get_slot("slot_17_container_seal_record").update_data(
            {"bolt_seal_number": "SEAL-USCBP-99812", "sealed": True, "sealed_at": datetime.now(timezone.utc).isoformat()},
            new_state=EpistemicState.CORROBORATED,
        )
        graph.get_slot("slot_18_pre_shipment_auth").update_data(
            {"gate_status": "RELEASE_CLEARED_CONFIRMED", "release_cleared": True},
            new_state=EpistemicState.CORROBORATED,
        )

        self.audit_log.append(
            AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="CONTAINER_SEAL_SUCCESSFUL",
                approval_id=approval_id,
                sku_id=graph.sku_id,
                details={"container": container_number, "seal": "SEAL-USCBP-99812"},
            )
        )
        return True, "CONTAINER_SEAL_APPROVED: Seal applied and gate cleared"
