"""
SecureRAG Terminal Document Ingestion Tool (Stage 1)
Use this terminal tool to add any documents to the secure vault.
Documents added here are scanned for threats and stored in the persistent
ChromaDB database, immediately available for query in the Web Interface.

Usage:
  1. Interactive mode (prompts for everything):
       python ingest.py

  2. Ingest from local file:
       python ingest.py --file my_policy.txt --tenant acme_corp --roles employee,manager --classification internal

  3. Ingest raw text:
       python ingest.py --text "Policy content..." --filename "policy.txt" --tenant acme_corp --roles employee

  4. Seed initial demo documents:
       python ingest.py --seed
"""

import os
import sys
import argparse
from typing import List

# Ensure safe UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from pipeline import SecureRAGPipeline


def print_banner():
    print("=" * 75)
    print("       SecureRAG: Terminal Document Ingestion (Stage 1)")
    print("       Ingest, Scan Provenance & Store in Vector Vault")
    print("=" * 75)


def display_ingestion_result(record: dict):
    print("\n" + "-" * 75)
    print("STAGE 1 INGESTION OUTCOME:")
    print("-" * 75)
    print(f"  • Document ID   : {record.get('document_id')}")
    print(f"  • Source File   : {record.get('filename')}")
    print(f"  • Tenant ID     : {record.get('tenant_id')}")
    print(f"  • Classification: {record.get('classification')}")
    print(f"  • Allowed Roles : {record.get('allowed_roles')}")
    print(f"  • SHA-256 Hash  : {record.get('provenance', {}).get('doc_hash')}")
    print(f"  • Risk Score    : {record.get('risk_score')}/100")

    status = record.get("document_status")
    if status == "approved":
        print(f"  • STATUS        : [APPROVED] Document verified and indexed into ChromaDB.")
        print(f"  • Chunks Created: {record.get('chunks_count')}")
    else:
        print(f"  • STATUS        : [QUARANTINED] Document flagged as dangerous!")
        print(f"  • Reasons       : {record.get('risk_reasons')}")
        print("  • NOTE          : This document was NOT added to the searchable database.")
    print("-" * 75)


def seed_demo_documents(pipeline: SecureRAGPipeline):
    print("\n[SEEDING DEMO DOCUMENTS INTO CHROMADB VAULT]")
    
    docs = [
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

    for d in docs:
        print(f" -> Ingesting '{d['filename']}' for tenant '{d['tenant_id']}'...")
        rec = pipeline.ingest_document(
            text=d["text"],
            filename=d["filename"],
            uploader=d["uploader"],
            tenant_id=d["tenant_id"],
            allowed_roles=d["allowed_roles"],
            classification=d["classification"]
        )
        print(f"    Status: {rec['document_status']} | Chunks: {rec['chunks_count']}")

    print(f"\n[DONE] Successfully seeded! ChromaDB now contains {pipeline.collection.count()} chunks.")


def interactive_mode(pipeline: SecureRAGPipeline):
    print_banner()
    print("Select input method:")
    print("  1. Ingest from an existing file on disk (.pdf / .txt / .md)")
    print("  2. Type or paste document text directly")
    print("  3. Seed standard demo documents")
    print("  4. View current database stats")
    print("  5. Exit")

    choice = input("\nEnter choice (1-5): ").strip()

    if choice == "1":
        file_path = input("\nEnter path to file: ").strip().strip('"').strip("'")
        if not os.path.exists(file_path):
            print(f"[Error] File '{file_path}' does not exist.")
            return

        filename = os.path.basename(file_path)
        tenant_id = input(f"Enter tenant ID [default: acme_corp]: ").strip() or "acme_corp"
        roles_str = input("Enter allowed roles (comma-separated) [default: employee]: ").strip() or "employee"
        classification = input("Enter classification (public / internal / confidential) [default: internal]: ").strip().lower() or "internal"
        uploader = input("Enter uploader identity [default: terminal_user]: ").strip() or "terminal_user"

        try:
            record = pipeline.ingest_file(
                file_path=file_path,
                uploader=uploader,
                tenant_id=tenant_id,
                allowed_roles=roles_str,
                classification=classification
            )
            display_ingestion_result(record)
        except Exception as e:
            print(f"[Error ingesting file]: {e}")

    elif choice == "2":
        filename = input("\nEnter filename (e.g. travel_policy.txt): ").strip() or "custom_doc.txt"
        tenant_id = input("Enter tenant ID [default: acme_corp]: ").strip() or "acme_corp"
        roles_str = input("Enter allowed roles (comma-separated) [default: employee]: ").strip() or "employee"
        classification = input("Enter classification (public / internal / confidential) [default: internal]: ").strip().lower() or "internal"
        uploader = input("Enter uploader identity [default: terminal_user]: ").strip() or "terminal_user"

        print("\nEnter document text below. When done, type 'EOF' on a new line or hit Enter twice:")
        lines = []
        while True:
            line = input()
            if line.strip() == "EOF" or (not line and lines):
                break
            lines.append(line)
        text = "\n".join(lines).strip()

        if not text:
            print("[Cancelled] Empty text provided.")
            return

        record = pipeline.ingest_document(
            text=text,
            filename=filename,
            uploader=uploader,
            tenant_id=tenant_id,
            allowed_roles=roles_str,
            classification=classification
        )
        display_ingestion_result(record)

    elif choice == "3":
        seed_demo_documents(pipeline)

    elif choice == "4":
        stats = pipeline.get_status_summary()
        print("\n" + "=" * 50)
        print("CHROMADB VAULT STATUS:")
        print(f"  • Persistent Directory : ./chroma_data")
        print(f"  • Collection Name      : {stats['collection_name']}")
        print(f"  • Total Indexed Chunks : {stats['indexed_chunks_count']}")
        print(f"  • Quarantined Documents: {stats['quarantined_documents_count']}")
        print("=" * 50)

    elif choice == "5":
        print("Exiting.")
        return


def main():
    parser = argparse.ArgumentParser(description="SecureRAG Terminal Document Ingestion Tool")
    parser.add_argument("--file", "-f", help="Path to text or markdown file to ingest")
    parser.add_argument("--text", "-t", help="Raw document text string to ingest")
    parser.add_argument("--filename", help="Filename identifier for the document")
    parser.add_argument("--tenant", default="acme_corp", help="Tenant ID (e.g. acme_corp)")
    parser.add_argument("--roles", default="employee", help="Comma-separated roles (e.g. employee,manager)")
    parser.add_argument("--classification", default="internal", choices=["public", "internal", "confidential"], help="Data classification")
    parser.add_argument("--uploader", default="terminal_user", help="Uploader username / email")
    parser.add_argument("--seed", action="store_true", help="Seed default demo documents")
    parser.add_argument("--stats", action="store_true", help="Show database chunk count")

    args = parser.parse_args()

    # Initialize persistent pipeline
    pipeline = SecureRAGPipeline(
        collection_name="securerag_vault",
        persist_directory="./chroma_data",
        audit_log_file="retrieval_audit.jsonl"
    )

    if args.seed:
        seed_demo_documents(pipeline)
        return

    if args.stats:
        stats = pipeline.get_status_summary()
        print(f"Indexed Chunks: {stats['indexed_chunks_count']} | Quarantined Docs: {stats['quarantined_documents_count']}")
        return

    if args.file:
        record = pipeline.ingest_file(
            file_path=args.file,
            uploader=args.uploader,
            tenant_id=args.tenant,
            allowed_roles=args.roles,
            classification=args.classification
        )
        display_ingestion_result(record)
        return

    if args.text:
        record = pipeline.ingest_document(
            text=args.text,
            filename=args.filename or "cli_document.txt",
            uploader=args.uploader,
            tenant_id=args.tenant,
            allowed_roles=args.roles,
            classification=args.classification
        )
        display_ingestion_result(record)
        return

    # No command line arguments provided -> launch interactive mode
    interactive_mode(pipeline)


if __name__ == "__main__":
    main()
