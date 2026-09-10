"""
SecureRAG Dataset Re-Indexing & Vault Refresh
Clears previous collection and re-indexes all dataset files using the improved
sentence-boundary recursive semantic chunker.
"""

import os
import sys
import shutil
import chromadb

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline import SecureRAGPipeline, extract_text_from_file

DEMO_DATASET_DIR = "C:/securerag/SecureRAG_Demo_Dataset"

def reindex_all():
    print("=================================================================")
    print("       SecureRAG: Vault Re-Indexing with Semantic Chunker        ")
    print("=================================================================")

    # 1. Connect to ChromaDB and clear the existing securerag_vault collection
    client = chromadb.PersistentClient(path="./chroma_data")
    try:
        client.delete_collection("securerag_vault")
        print("[+] Existing collection 'securerag_vault' cleared.")
    except Exception as e:
        print(f"[*] Notice when clearing collection: {e}")

    pipeline = SecureRAGPipeline(
        collection_name="securerag_vault",
        persist_directory="./chroma_data",
        audit_log_file="retrieval_audit.jsonl"
    )

    # 2. Seed Default Standard Demo Documents
    seed_docs = [
        {
            "text": (
                "Acme Health Incident Response & Evidence Preservation Policy:\n"
                "1. All employees must report suspected security incidents within 24 hours to security@acmehealth.corp.\n"
                "2. Managers must preserve all digital evidence, forensic logs, and system states intact.\n"
                "3. Security operations team is the primary emergency contact during an active breach.\n"
                "4. All production credentials must be rotated immediately following containment."
            ),
            "filename": "acme_incident_policy.txt",
            "uploader": "compliance_officer@acmehealth.corp",
            "tenant_id": "acme_corp",
            "allowed_roles": ["employee", "manager", "admin"],
            "classification": "internal"
        },
        {
            "text": (
                "Acme Corp Remote Work & Equipment Policy:\n"
                "Employees working remotely must connect via the corporate WireGuard VPN at all times.\n"
                "Company-issued MacBooks must have FileVault full-disk encryption enabled.\n"
                "Personal devices are not permitted to sync corporate code repositories."
            ),
            "filename": "remote_work_policy.txt",
            "uploader": "it_admin@acmehealth.corp",
            "tenant_id": "acme_corp",
            "allowed_roles": ["employee", "manager", "admin"],
            "classification": "internal"
        },
        {
            "text": (
                "Beta Finance Q3 Confidential Strategic Plan & Revenue Projections:\n"
                "Beta Finance projects enterprise quarterly revenue of $12 million for Q3 2026.\n"
                "Projected EBITDA margin is 28%, driven by expansion into healthcare fintech.\n"
                "Strictly confidential. Authorized for finance managers and executive board members only."
            ),
            "filename": "beta_finance_revenue.txt",
            "uploader": "cfo@betafinance.corp",
            "tenant_id": "beta_finance",
            "allowed_roles": ["manager", "executive", "admin"],
            "classification": "confidential"
        }
    ]

    print("\n--- Seeding Base Tenant Documents ---")
    for d in seed_docs:
        rec = pipeline.ingest_document(
            text=d["text"],
            filename=d["filename"],
            uploader=d["uploader"],
            tenant_id=d["tenant_id"],
            allowed_roles=d["allowed_roles"],
            classification=d["classification"]
        )
        print(f"  [+] Ingested {d['filename']} ({d['tenant_id']}) -> {rec['document_status']} ({rec['chunks_count']} chunks)")

    # 3. Index SecureRAG Demo Dataset Documents
    dataset_configs = [
        # Company A (Tenant: company_a)
        ("company_a/employee_handbook.pdf", "company_a", ["employee", "manager", "admin"], "internal", "hr_admin@company_a.corp"),
        ("company_a/hr_leave_policy.pdf", "company_a", ["employee", "manager", "admin"], "internal", "hr_admin@company_a.corp"),
        ("company_a/it_security_policy.pdf", "company_a", ["it_admin", "security_officer", "admin"], "confidential", "security_lead@company_a.corp"),
        ("company_a/reimbursement_policy.pdf", "company_a", ["employee", "manager", "admin"], "internal", "finance@company_a.corp"),
        ("company_a/work_from_home_policy.pdf", "company_a", ["employee", "manager", "admin"], "internal", "hr_admin@company_a.corp"),

        # Company B (Tenant: company_b)
        ("company_b/benefits_policy.pdf", "company_b", ["employee", "manager", "admin"], "internal", "hr@company_b.corp"),
        ("company_b/hr_leave_policy.pdf", "company_b", ["employee", "manager", "admin"], "internal", "hr@company_b.corp"),
        ("company_b/it_policy.pdf", "company_b", ["it_admin", "security_officer", "admin"], "confidential", "secops@company_b.corp"),
        ("company_b/salary_policy.pdf", "company_b", ["hr_manager", "executive", "admin"], "confidential", "payroll@company_b.corp"),

        # Legitimate Imperative
        ("legitimate/legitimate_instruction_policy.pdf", "company_a", ["employee", "manager", "admin"], "internal", "compliance@company_a.corp"),

        # Attack vectors for Stage 1 Quarantine Verification
        ("attacks/poisoned_hr_document.pdf", "company_a", ["employee"], "internal", "external_contributor"),
        ("attacks/malicious_email.pdf", "company_a", ["employee"], "internal", "phisher@external-mail.net"),
        ("attacks/data_exfiltration_document.pdf", "company_a", ["employee"], "internal", "guest_user")
    ]

    print("\n--- Ingesting Demo Dataset ---")
    quarantined_count = 0
    approved_count = 0

    for rel_path, tenant, roles, classification, uploader in dataset_configs:
        full_path = os.path.join(DEMO_DATASET_DIR, rel_path)
        if not os.path.exists(full_path):
            print(f"  [!] Missing file: {full_path}")
            continue

        rec = pipeline.ingest_file(
            file_path=full_path,
            uploader=uploader,
            tenant_id=tenant,
            allowed_roles=roles,
            classification=classification
        )

        status = rec["document_status"]
        if status == "approved":
            approved_count += 1
            print(f"  [+] APPROVED: {rel_path} ({tenant}, {classification}) -> {rec['chunks_count']} chunk(s)")
        else:
            quarantined_count += 1
            print(f"  [!] QUARANTINED: {rel_path} -> Risk score: {rec['risk_score']} | Reasons: {rec['risk_reasons']}")

    total_chunks = pipeline.collection.count()
    print("\n" + "=" * 65)
    print(f"RE-INDEXING COMPLETE!")
    print(f"Total Approved Files   : {approved_count + len(seed_docs)}")
    print(f"Total Quarantined Files: {quarantined_count}")
    print(f"Total Chunks in Vault  : {total_chunks}")
    print("=" * 65)

if __name__ == "__main__":
    reindex_all()
