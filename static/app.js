/**
 * SecureRAG Stage 2 Frontend Logic
 * Connects web UI directly to the Stage 2 Retrieval & Reranking engine.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const vaultChunksCount = document.getElementById("vaultChunksCount");
  const quarantineCount = document.getElementById("quarantineCount");

  const userIdInput = document.getElementById("userIdInput");
  const tenantIdInput = document.getElementById("tenantIdInput");
  const rolesInput = document.getElementById("rolesInput");
  const clearanceSelect = document.getElementById("clearanceSelect");

  const personaButtons = document.querySelectorAll(".persona-btn");
  const queryForm = document.getElementById("queryForm");
  const queryInput = document.getElementById("queryInput");
  const submitQueryBtn = document.getElementById("submitQueryBtn");
  const btnSubmitText = document.getElementById("btnSubmitText");
  const btnSubmitSpinner = document.getElementById("btnSubmitSpinner");

  const emptyState = document.getElementById("emptyState");
  const loadingState = document.getElementById("loadingState");
  const resultContainer = document.getElementById("resultContainer");

  const decisionBanner = document.getElementById("decisionBanner");
  const bannerIcon = document.getElementById("bannerIcon");
  const bannerTitle = document.getElementById("bannerTitle");
  const bannerMessage = document.getElementById("bannerMessage");
  const metricRewrittenQuery = document.getElementById("metricRewrittenQuery");
  const metricChunkCount = document.getElementById("metricChunkCount");

  const contextTextDisplay = document.getElementById("contextTextDisplay");
  const btnCopyContext = document.getElementById("btnCopyContext");
  const chunksList = document.getElementById("chunksList");
  const auditJsonDisplay = document.getElementById("auditJsonDisplay");
  const auditTimestamp = document.getElementById("auditTimestamp");

  // Persona Templates
  const personas = {
    alice: {
      userId: "alice",
      tenantId: "acme_corp",
      roles: "employee",
      clearance: "public,internal"
    },
    bob: {
      userId: "bob",
      tenantId: "beta_finance",
      roles: "manager",
      clearance: "public,internal,confidential"
    },
    charlie: {
      userId: "charlie",
      tenantId: "beta_finance",
      roles: "intern",
      clearance: "public,internal"
    },
    dana: {
      userId: "dana",
      tenantId: "beta_finance",
      roles: "manager",
      clearance: "public,internal" // lacks confidential clearance
    }
  };

  // 1. Fetch Vault Status
  async function refreshVaultStatus() {
    try {
      const res = await fetch("/api/status");
      if (res.ok) {
        const data = await res.json();
        vaultChunksCount.textContent = data.indexed_chunks_count ?? "--";
        quarantineCount.textContent = data.quarantined_documents_count ?? "--";
      }
    } catch (err) {
      console.warn("Could not fetch vault status:", err);
    }
  }

  refreshVaultStatus();

  // 2. Persona Switcher
  personaButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      personaButtons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      const key = btn.dataset.persona;
      const p = personas[key];
      if (p) {
        userIdInput.value = p.userId;
        tenantIdInput.value = p.tenantId;
        rolesInput.value = p.roles;
        clearanceSelect.value = p.clearance;
      }
    });
  });

  // 3. Chip Suggestion Buttons
  document.querySelectorAll(".chip-btn").forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.dataset.query;
      if (q) {
        queryInput.value = q;
        queryForm.dispatchEvent(new Event("submit"));
      }
    });
  });

  // 4. Copy Context Button
  btnCopyContext.addEventListener("click", async () => {
    const text = contextTextDisplay.textContent;
    if (!text || text.startsWith("//")) return;

    try {
      await navigator.clipboard.writeText(text);
      const originalHtml = btnCopyContext.innerHTML;
      btnCopyContext.innerHTML = "<span>✓ Copied!</span>";
      btnCopyContext.style.borderColor = "var(--accent-emerald)";
      btnCopyContext.style.color = "var(--accent-emerald)";

      setTimeout(() => {
        btnCopyContext.innerHTML = originalHtml;
        btnCopyContext.style.borderColor = "";
        btnCopyContext.style.color = "";
      }, 1800);
    } catch (err) {
      console.error("Clipboard copy failed:", err);
    }
  });

  // 5. Query Submission Handler
  queryForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const query = queryInput.value.trim();
    if (!query) return;

    // Read current identity values
    const userId = userIdInput.value.trim() || "anonymous";
    const tenantId = tenantIdInput.value.trim() || "default_tenant";
    const roles = rolesInput.value.split(",").map(r => r.trim()).filter(Boolean);
    const clearances = clearanceSelect.value.split(",").map(c => c.trim()).filter(Boolean);

    // UI Loading State
    emptyState.classList.add("hidden");
    resultContainer.classList.add("hidden");
    loadingState.classList.remove("hidden");

    submitQueryBtn.disabled = true;
    btnSubmitText.textContent = "Searching...";
    btnSubmitSpinner.classList.remove("hidden");

    try {
      const response = await fetch("/api/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: query,
          user_id: userId,
          tenant_id: tenantId,
          roles: roles,
          allowed_classifications: clearances
        })
      });

      const data = await response.json();
      renderResults(data);
    } catch (err) {
      renderError(err);
    } finally {
      loadingState.classList.add("hidden");
      submitQueryBtn.disabled = false;
      btnSubmitText.textContent = "Search Vault";
      btnSubmitSpinner.classList.add("hidden");
      refreshVaultStatus();
    }
  });

  // 6. Render Query Results
  function renderResults(data) {
    resultContainer.classList.remove("hidden");

    const isSuccess = data.status === "success" && data.chunks && data.chunks.length > 0;

    // Decision Banner Styling
    if (isSuccess) {
      decisionBanner.className = "decision-banner success";
      bannerIcon.textContent = "✓";
      bannerTitle.textContent = "Access Authorized & Retrieved";
      bannerMessage.textContent = data.message || `Retrieved ${data.chunks.length} verified candidate chunk(s).`;
    } else {
      decisionBanner.className = "decision-banner denied";
      bannerIcon.textContent = "🛡️";
      bannerTitle.textContent = "Security Isolation Enforced";
      bannerMessage.textContent = data.message || "No authorized information found for your tenant, role, or clearance level.";
    }

    // Metrics
    metricRewrittenQuery.textContent = `Query Token: ${data.rewritten_query || data.query}`;
    metricChunkCount.textContent = `${data.candidates_count || 0} chunk(s)`;

    // Stage 3 Context Block
    if (data.context_text && data.context_text.trim()) {
      contextTextDisplay.textContent = data.context_text;
    } else {
      contextTextDisplay.textContent = "// No authorized context available for Stage 3 LLM synthesis.\n// Security policy returned 0 authorized chunks.";
    }

    // Chunks Cards
    chunksList.innerHTML = "";
    if (isSuccess) {
      data.chunks.forEach((c, idx) => {
        const card = document.createElement("div");
        card.className = "chunk-card";

        const classification = c.classification || "internal";
        const dist = typeof c.vector_distance === "number" ? c.vector_distance.toFixed(3) : "--";
        const rerankScore = typeof c.rerank_score === "number" ? c.rerank_score.toFixed(3) : "--";

        card.innerHTML = `
          <div class="chunk-top-meta">
            <span class="chunk-file">📄 [${idx + 1}] ${escapeHtml(c.source_file || "unknown")}</span>
            <div class="chunk-badges">
              <span class="badge-class ${classification}">${classification}</span>
              <span class="chunk-score">Rerank: ${rerankScore}</span>
              <span class="chunk-score">Dist: ${dist}</span>
            </div>
          </div>
          <div class="chunk-text">${escapeHtml(c.text || "")}</div>
        `;
        chunksList.appendChild(card);
      });
    } else {
      chunksList.innerHTML = `
        <div class="empty-state" style="padding: 24px; text-align: left;">
          <p style="color: var(--text-dim);">Zero chunks returned. Pre-retrieval scoping prevented any cross-tenant or unauthorized data from being exposed.</p>
        </div>
      `;
    }

    // Audit Event Display
    if (data.audit_event) {
      auditJsonDisplay.textContent = JSON.stringify(data.audit_event, null, 2);
      auditTimestamp.textContent = `Event logged at: ${data.audit_event.timestamp || "just now"}`;
    } else {
      auditJsonDisplay.textContent = JSON.stringify({
        event_type: isSuccess ? "RETRIEVAL_SUCCESS" : "RETRIEVAL_DECISION",
        user_id: data.stage3_payload?.user_id || "unknown",
        tenant_id: data.stage3_payload?.tenant_id || "unknown",
        query: data.query,
        chunks_returned: data.chunks ? data.chunks.length : 0
      }, null, 2);
      auditTimestamp.textContent = "Recorded in retrieval_audit.jsonl";
    }
  }

  function renderError(err) {
    resultContainer.classList.remove("hidden");
    decisionBanner.className = "decision-banner denied";
    bannerIcon.textContent = "⚠️";
    bannerTitle.textContent = "Server Communication Error";
    bannerMessage.textContent = err.message || "Failed to reach Stage 2 server.";
    contextTextDisplay.textContent = "// Error connecting to retrieval server.";
    chunksList.innerHTML = "";
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
});
