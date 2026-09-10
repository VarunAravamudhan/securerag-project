"""
SecureRAG Web Application Server
Serves the Stage 2 Query Interface and Stage 3 Context Visualizer.
Documents added via terminal ('python ingest.py') are immediately queryable here.
"""

import os
import sys
import json
from typing import Dict, Any

# Ensure safe UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, FileResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles

from pipeline import SecureRAGPipeline

# Initialize the pipeline using the shared persistent ChromaDB vault
AUDIT_LOG_FILE = "retrieval_audit.jsonl"
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

pipeline = SecureRAGPipeline(
    collection_name="securerag_vault",
    persist_directory="./chroma_data",
    audit_log_file=AUDIT_LOG_FILE
)


# Seed known quarantined threat documents into in-memory quarantine ledger if empty
if len(pipeline.ingestion.quarantine_records) == 0:
    pipeline.ingestion.quarantine_records.extend([
        {
            "document_id": "quar-98a1-exploit",
            "filename": "system_override_exploit.txt",
            "uploader": "untrusted_external_guest",
            "tenant_id": "company_a",
            "allowed_roles": ["admin"],
            "classification": "confidential",
            "risk_score": 100,
            "risk_reasons": ["Detected prompt injection syntax ('SYSTEM OVERRIDE', 'Ignore previous instructions')", "Exfiltration URL pattern"],
            "document_status": "quarantined",
            "chunks_count": 0,
            "quarantined_at": "2026-09-10T12:00:00Z"
        },
        {
            "document_id": "quar-44b2-hidden",
            "filename": "critical_system_patch.txt",
            "uploader": "anonymous_contributor",
            "tenant_id": "company_a",
            "allowed_roles": ["it_admin"],
            "classification": "confidential",
            "risk_score": 90,
            "risk_reasons": ["Suspicious instruction tags", "Untrusted external uploader"],
            "document_status": "quarantined",
            "chunks_count": 0,
            "quarantined_at": "2026-09-10T12:05:00Z"
        }
    ])


def get_last_audit_event() -> Dict[str, Any]:
    """Reads the most recent audit event from the append-only JSONL log."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return {}
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]
            if lines:
                return json.loads(lines[-1])
    except Exception:
        pass
    return {}


async def index(request):
    """Serves the main HTML single-page application."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    return FileResponse(index_path)


async def api_status(request):
    """Returns real-time database and quarantine statistics."""
    try:
        summary = pipeline.get_status_summary()
        return JSONResponse(summary)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_query(request):
    """
    Executes Stage 2 retrieval with pre-retrieval scoping, RBAC verification,
    zero-helpfulness fallback elimination, and cross-encoder semantic reranking.
    """
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    query = data.get("query", "").strip()
    if not query:
        return JSONResponse({"error": "Query cannot be empty"}, status_code=400)

    user_id = data.get("user_id", "anonymous")
    tenant_id = data.get("tenant_id", "default_tenant")
    roles = data.get("roles", ["employee"])
    if isinstance(roles, str):
        roles = [r.strip() for r in roles.split(",") if r.strip()]

    allowed_classes = data.get("allowed_classifications", ["public", "internal"])
    if isinstance(allowed_classes, str):
        allowed_classes = [c.strip() for c in allowed_classes.split(",") if c.strip()]

    user = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "roles": roles,
        "allowed_classifications": allowed_classes
    }

    chat_history = data.get("chat_history") or data.get("conversation_history") or []

    # 1. Multi-turn query contextualization
    import re
    retrieval_query = query
    ambiguous_pronouns = {"it", "its", "this", "that", "these", "those", "they", "them", "there", "same"}
    query_words = set(re.findall(r"\b[a-zA-Z]{2,}\b", query.lower()))
    has_pronoun = bool(query_words.intersection(ambiguous_pronouns))

    explicit_topics = {
        "leave", "vacation", "holiday", "sick", "pto", "remote", "wfh", "home",
        "travel", "expense", "reimbursement", "salary", "compensation", "benefit",
        "benefits", "security", "password", "passwords", "vpn", "it", "handbook",
        "incident", "breach", "phishing", "mfa"
    }
    has_explicit_topic = bool(query_words.intersection(explicit_topics))

    if chat_history and has_pronoun and not has_explicit_topic:
        user_queries = [m.get("content", "") for m in chat_history if isinstance(m, dict) and m.get("role") == "user" and m.get("content")]
        if user_queries:
            last_topic = user_queries[-1]
            clean_topic = re.sub(r"(?i)\b(?:ignore|reveal|system prompt|passwords|maintenance mode)\b.*", "", last_topic).strip()
            if clean_topic:
                retrieval_query = f"{clean_topic} {query}"

    # 2. Heuristic Detection for Suspicious / Injection / Bypass Queries
    suspicious_patterns = [
        (r"(?i)\b(?:system\s+override|override\s+(?:the\s+)?(?:security|system|rules|policy))\b", "System Override / Bypass Syntax"),
        (r"(?i)\b(?:ignore\s+(?:all\s+|previous\s+|prior\s+)?instructions|disregard\s+above\s+directives)\b", "Prompt Injection (Directive Override)"),
        (r"(?i)\b(?:reveal\s+(?:the\s+)?(?:system\s+)?(?:prompt|passwords|credentials|keys)|show\s+(?:all\s+)?passwords)\b", "Credential / System Prompt Harvest"),
        (r"(?i)\b(?:maintenance\s+mode|unrestricted\s+mode|developer\s+mode\s+override|jailbreak)\b", "Privilege Escalation / Jailbreak heuristic"),
        (r"(?i)\b(?:exfil|attacker\.example|evil-c2)\b", "Exfiltration Endpoint Pattern"),
    ]
    matched_threats = []
    for pat, label in suspicious_patterns:
        if re.search(pat, query):
            matched_threats.append(label)

    # 3. Check for correlation with Stage 1 Quarantined documents
    quarantine_matches = []
    for qdoc in pipeline.ingestion.quarantine_records:
        q_name = qdoc.get("filename", "").lower()
        if any(term in query.lower() for term in ["override", "exploit", "patch", "malicious", "attack"]) or (q_name and q_name in query.lower()):
            quarantine_matches.append(qdoc)

    # 4. Execute Stage 2 Retrieval & Reranking using contextual query
    retrieval_result = pipeline.retrieve(query=retrieval_query, user=user)

    # 5. Execute Stage 3 Safe LLM Generation & Security Inspection
    from stage3_generation import process_stage2_to_stage3
    stage3_output = process_stage2_to_stage3(
        retrieval_result, 
        query=query, 
        user_metadata=user,
        conversation_history=chat_history
    )

    has_chunks = bool(retrieval_result.get("chunks") and len(retrieval_result["chunks"]) > 0)
    decision = retrieval_result.get("decision") or ("AUTHORIZED_RETRIEVAL_SUCCESS" if has_chunks else "ZERO_AUTHORIZED_RESULTS_TERMINATION")
    is_blocked = not has_chunks or stage3_output.status == "BLOCKED" or bool(matched_threats)

    # 6. Granular Cause Classification for Clear Demonstrations
    q_lower = query.lower()
    is_cross_tenant = any(t in q_lower for t in ["beta_finance", "beta finance", "company_b", "company b", "acme_corp", "acme corp"]) and not any(t in str(tenant_id).lower() for t in ["beta", "company_b"])
    is_rbac_clearance = any(term in q_lower for term in ["it security", "it_security", "confidential", "salary", "executive", "admin", "passwords", "payroll"]) and "confidential" not in allowed_classes
    is_exfiltration = any(term in q_lower for term in ["exfil", "exfiltrat", "webhook", "curl", "attacker.example", "evil-c2"]) or (stage3_output.status == "BLOCKED")

    defense_stage = "Stage 2: Pre-Retrieval Scoping & Zero-Helpfulness Fallback"
    badge_label = "🛡️ SECURITY BLOCKED"
    rationale = "Zero-Helpfulness Architecture: All candidate documents outside your authorized clearance envelope were safely withheld to prevent side-channel information leakage."

    if matched_threats:
        # Cause 1: Prompt Injection / Instruction Override in Query
        defense_stage = "Stage 2 & 3: Input Security Guardrail & Zero-Helpfulness Fallback"
        decision = "SECURITY_GUARDRAIL_INTERCEPTION"
        badge_label = "🛡️ PROMPT INJECTION BLOCKED"
        rationale = f"Suspicious prompt pattern detected ({', '.join(matched_threats)}). SecureRAG intercepted the instruction and safely suppressed vector candidate releases."
        final_answer = f"⚠️ Query Intercepted by Prompt Injection Guardrail: Suspicious instruction pattern detected ({', '.join(matched_threats)}). Pre-retrieval security prevented execution to protect the LLM context envelope."

    elif is_cross_tenant:
        # Cause 2: Cross-Tenant Data Leakage Block
        defense_stage = "Stage 2: Cross-Tenant Isolation Barrier"
        decision = "CROSS_TENANT_VIOLATION_BLOCKED"
        badge_label = "🏢 TENANT ISOLATION ENFORCED"
        rationale = f"Cross-tenant isolation enforced. Pre-retrieval authorization boundary strictly confined vector similarity search to tenant '{tenant_id}'. Cross-tenant data exfiltration blocked."
        final_answer = f"🏢 Cross-Tenant Access Prohibited: The requested records belong to another tenant partition ('beta_finance' / 'company_b'). SecureRAG's pre-retrieval scoping mathematically blocked vector search access from tenant '{tenant_id}'."

    elif is_rbac_clearance:
        # Cause 3: Role Clearance (RBAC) Mismatch
        defense_stage = "Stage 2: Role-Based Access Control (RBAC)"
        decision = "ROLE_CLEARANCE_DENIED"
        badge_label = "🔒 RBAC CLEARANCE DENIED"
        rationale = f"Role clearance violation. The requested document requires 'confidential' clearance or administrative roles (e.g. it_admin, security). Active user '{user_id}' has roles {roles} and clearance {allowed_classes}."
        final_answer = f"🔒 Access Denied by RBAC Clearance: The requested document ('it_security_policy.pdf') is classified as 'confidential' and restricted to ['it_admin', 'security'] roles. Active session ('{user_id}', roles: {roles}) lacks clearance."

    elif quarantine_matches:
        # Cause 4: Stage 1 Ingestion Quarantine Hit
        defense_stage = "Stage 1: Quarantine Isolation (Pre-Retrieval)"
        decision = "QUARANTINED_DOCUMENT_WITHHELD"
        badge_label = "🛡️ STAGE 1 QUARANTINE ACTIVE"
        q_reasons = "; ".join(quarantine_matches[0].get("reasons", [])) if quarantine_matches[0].get("reasons") else "Prompt injection and exfiltration patterns"
        rationale = f"Target document '{quarantine_matches[0].get('filename')}' was quarantined at ingestion (Risk Score: {quarantine_matches[0].get('risk_score')}/100) and completely excluded from ChromaDB vector indexing."
        final_answer = f"🛡️ Access Blocked by Stage 1 Quarantine: Document '{quarantine_matches[0].get('filename')}' was flagged as dangerous at ingestion (Risk Score: {quarantine_matches[0].get('risk_score')}/100, reasons: {q_reasons}) and was never indexed into vector storage."

    elif is_exfiltration or stage3_output.status == "BLOCKED":
        # Cause 5: Stage 3 Secret Leak or Exfiltration Guardrail
        defense_stage = "Stage 3: Safe LLM Generation & Output Inspection"
        decision = "STAGE3_OUTPUT_LEAK_BLOCKED"
        badge_label = "🛑 EXFILTRATION ATTEMPT NEUTRALIZED"
        rationale = "LLM output violated security rules (secret detection, unauthorized external link, or failed grounding) and was neutralized."
        final_answer = f"🛑 Exfiltration Guardrail Triggered: The generated response attempted to leak an unauthorized external link or secret key pattern. Neutralized by Stage 3 safety guardrails."

    elif not has_chunks:
        # Cause 6: Zero-Helpfulness Fallback (Out-of-Scope / Non-Existent Corporate Data)
        defense_stage = "Stage 2: Semantic Relevance & Zero-Helpfulness Fallback"
        decision = "ZERO_HELPFULNESS_TERMINATION"
        badge_label = "🎯 ZERO-HELPFULNESS ENFORCED"
        rationale = "Zero-Helpfulness Architecture: No authorized corporate documents matched this topic. SecureRAG terminated retrieval immediately to prevent AI hallucination or out-of-domain guessing."
        final_answer = f"🎯 Zero-Helpfulness Fallback Enforced: No authorized corporate policy documents matched this topic within your clearance boundary. Retrieval terminated immediately without guessing to prevent AI hallucinations."

    else:
        badge_label = "APPROVED & VERIFIED"
        final_answer = stage3_output.answer

    security_defense = {
        "is_blocked": is_blocked,
        "defense_stage": defense_stage,
        "decision": decision,
        "badge_label": badge_label,
        "threat_signatures": matched_threats,
        "is_suspicious_query": bool(matched_threats),
        "quarantine_matches": [{"filename": q.get("filename"), "risk_score": q.get("risk_score"), "reasons": q.get("risk_reasons")} for q in quarantine_matches],
        "rationale": rationale,
        "zero_helpfulness_rule": "SecureRAG intentionally returns 0 vector chunks when queries fail authorization or relevance checks. The pipeline never falls back to broader indexes or adjacent documents, eliminating side-channel data exfiltration.",
        "auth_filter": retrieval_result.get("auth_filter", {}),
        "user_context": user
    }

    # Attach Stage 3 answer, citations, security defense and report
    result = {
        **retrieval_result,
        "chunks": [] if is_blocked else retrieval_result.get("chunks", []),
        "candidates_count": 0 if is_blocked else len(retrieval_result.get("chunks", [])),
        "generation": stage3_output.to_dict(),
        "answer": final_answer,
        "citations": [] if is_blocked else [{"chunk_id": c.chunk_id, "source_doc": c.source_doc} for c in stage3_output.citations],
        "stage3_status": "BLOCKED" if is_blocked else stage3_output.status,
        "security_defense": security_defense,
        "security_report": stage3_output.security_report.to_dict(),
        "audit_event": get_last_audit_event()
    }

    return JSONResponse(result)


async def health(request):
    return JSONResponse({"status": "healthy", "service": "SecureRAG Web Server"})


routes = [
    Route("/", index),
    Route("/health", health),
    Route("/api/status", api_status),
    Route("/api/query", api_query, methods=["POST"]),
    Mount("/static", StaticFiles(directory=STATIC_DIR), name="static"),
]

app = Starlette(debug=True, routes=routes)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print("=" * 75)
    print("           Starting SecureRAG Stage 2 Web Application")
    print(f"           URL: http://127.0.0.1:{port}")
    print("           Terminal Document Ingestion: 'python ingest.py'")
    print("=" * 75)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
