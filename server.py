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

    # Execute Stage 2 Retrieval & Reranking
    result = pipeline.retrieve(query=query, user=user)

    # Attach the latest audit event generated for this decision
    last_event = get_last_audit_event()
    result["audit_event"] = last_event

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
