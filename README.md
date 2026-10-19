# Pre-Shipment Evidence Gate

Deterministic invalidation kernel and cryptographic evidence gate for pre-shipment compliance workflows (Country of Origin v2, FTA v2, Trade Readiness).

```
                      +-------------------------------------------------------+
                      |         UNSTRUCTURED PRE-SHIPMENT EVIDENCE            |
                      |  - Alibaba RFQ / PO (Slot 01)                         |
                      |  - Supplier WhatsApp / WeChat Logs (Slot 04)          |
                      |  - ISO/IEC 17025 Spectrometry Lab Reports (Slot 05)   |
                      |  - QIMA AQL 2.5 Pre-Shipment Inspection (Slot 06)     |
                      +-------------------------------------------------------+
                                                 |
                                                 v
                      +-------------------------------------------------------+
                      |             18-SLOT EVIDENCE GRAPH                    |
                      |  - Deterministic SHA-256 Provenance Hashing           |
                      |  - Epistemic States: ASSERTED | CORROBORATED | UNKNOWN|
                      +-------------------------------------------------------+
                                                 |
                        +------------------------+------------------------+
                        |                                                 |
                        v                                                 v
         +-----------------------------+                   +-----------------------------+
         |   DETERMINATION CHAIN       |                   |  RECURRING INGESTION (SFTP) |
         |  - Catalog Changelog        |                   |  - Automated Late Drops     |
         |  - Country of Origin (v2)   |                   |  - Material Origin Mutated  |
         |  - FTA (v2) [USMCA/RVC]     |                   +-----------------------------+
         |  - Trade Readiness Approval |                                  |
         +-----------------------------+                                  |
                        |                                                 |
                        v                                                 v
         +-------------------------------------------------------------------------------+
         |                    DETERMINISTIC CRYPTOGRAPHIC GATE                           |
         |  - Hash-Bound Approval Snapshot: { slot_id: sha256_hash }                     |
         |  - Invariant 1: Audit Demotion (Record stays in Audit Log; Authority Stripped)|
         |  - Invariant 2: Blast-Radius Isolation (Unrelated SKU Approvals Intact)       |
         |  - Staleness Detection: live_hash != approved_hash -> BLOCK CONTAINER SEAL   |
         +-------------------------------------------------------------------------------+
                                                 |
                        +------------------------+------------------------+
                        |                                                 |
                 [Hashes Match]                                 [Hash Mismatch]
                        v                                                 v
         +-----------------------------+                   +-----------------------------+
         |   CONTAINER SEAL APPROVED   |                   |   CONTAINER SEAL BLOCKED    |
         |  - ISO 17712 Bolt Applied   |                   |  - Release Denied           |
         |  - Vessel Gate Cleared      |                   |  - Audit Log Event Recorded |
         +-----------------------------+                   +-----------------------------+
```

---

## Architectural Purpose

This repository implements the deterministic safety kernel that closes the **staleness window** in enterprise trade compliance platforms.

1. **The Staleness Vulnerability**: Platforms ingest automated catalog updates via recurring SFTP/S3 batch pipelines, while downstream determinations (Trade Readiness, CoO v2, FTA v2) are **explicitly refreshed rather than continuously recomputed**. Between an automated catalog ingestion event and the next manual compliance refresh, a container can be sealed and dispatched under an invalid, stale approval.
2. **The Kernel Solution**: An approval does not rely on a static boolean. Instead, it holds a cryptographic hash snapshot of the exact 18-slot evidence state on which it was predicated. When container sealing is requested, the gate recomputes live evidence hashes. Any delta immediately revokes release authority while preserving the historical approval inside the workspace audit log.

---

## Core Production Invariants

- **Separation of Extraction vs. Invalidation**: Probabilistic LLM extractors normalize raw PDFs and chat transcripts into structured slots with epistemic states (`ASSERTED`, `CORROBORATED`, `UNKNOWN`). Deterministic Python kernel rules enforce hash comparison and release gating.
- **Audit Preservation over Deletion**: When evidence mutates, the approval is demoted to `STALE_REVOKED`. It remains permanently set to `in_audit_log = True`. Downstream release authority is zero, but chain-of-custody audit history is preserved.
- **Blast-Radius Isolation**: Approvals bind strictly to their target SKU dependency graph. Mutating Tier-1 material origin on SKU A invalidates SKU A's approval while leaving SKU B's trade readiness intact.

---

## 18-Slot Pre-Shipment Evidence Schema

| Slot ID | Evidence Name | Epistemic State | Source Artifact Type |
|---|---|---|---|
| `slot_01` | Commercial Invoice & PO | CORROBORATED | Structured / Inbound PO |
| `slot_02` | Draft Waybill / Bill of Lading | CORROBORATED | Shipping Line EDI / PDF |
| `slot_03` | Export Packing List | CORROBORATED | Freight Forwarder Manifest |
| `slot_04` | Tier-1 Material Origin Declaration | CORROBORATED / ASSERTED | Supplier Chat (WhatsApp/WeChat) |
| `slot_05` | ISO 17025 Metallurgical Lab Spectrometry | CORROBORATED | Accredited Lab PDF Cert |
| `slot_06` | QIMA AQL 2.5 Pre-Shipment Inspection | CORROBORATED | Third-Party Inspector Certificate |
| `slot_07` | Country of Origin (Form E / USMCA) | CORROBORATED | Official Customs Declaration |
| `slot_08` | Sub-tier Tier-2 Bill of Materials | CORROBORATED | Supplier Catalog File |
| `slot_09` | Smelter / Refiner Minerals Audit | CORROBORATED | RMAP Conformant Smelter ID |
| `slot_10` | HTS 10-Digit Tariff Determination | CORROBORATED | Customs Tariff Schedule |
| `slot_11` | Regional Value Content (RVC) Worksheet | CORROBORATED | Net Cost / Transaction Calculation |
| `slot_12` | Direct Shipment & Non-Manipulation | CORROBORATED | In-Transit Bonded Guarantee |
| `slot_13` | ILO Forced Labor Prevention Audit | CORROBORATED | SMETA / Facility Audit |
| `slot_14` | Dual-Use ECCN License Exemption | CORROBORATED | BIS Screening Record |
| `slot_15` | Finished Goods Value Chain Link Map | CORROBORATED | Workspace Value Chain Graph |
| `slot_16` | AD/CVD Scope Exclusion Ruling | CORROBORATED | Department of Commerce Ruling |
| `slot_17` | ISO 17712 High-Security Container Seal | ASSERTED | Physical Yard Gate Check |
| `slot_18` | Pre-Shipment Release Authorization Gate | ASSERTED | Final Gate Controller State |

---

## Quickstart & Regression Suite

### 1. Run Baseline Test Suite
```bash
python -m pytest -v test_invalidation.py
```
*Expected: 4 tests pass in < 1 second.*

### 2. Key Invalidation Scenario
`test_stale_approval_blocks_container_release_on_evidence_mutation`:
- `fixtures_v1.json` establishes baseline USMCA qualifying material origin (Mexican silicon wafer).
- `fixtures_v2_mutation.json` simulates recurring SFTP batch ingestion updating Slot 4 to a non-qualifying supplier.
- `evaluate_live_release_authority()` detects hash divergence and halts container sealing before gate dispatch.

### 3. Blast-Radius Isolation Scenario
`test_blast_radius_isolation_unrelated_sku_remains_valid`:
- SKU-SOLAR-INVERTER-X1 is blocked.
- SKU-BATTERY-PACK-B2 retains release authority.
