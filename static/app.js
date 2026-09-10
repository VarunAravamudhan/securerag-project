/**
 * SecureRAG Enterprise Application Logic
 * Single-Page Application Session Manager, Continuous Multi-Turn Engine & Stage 3 Visualizer
 * Aesthetics: ChatGPT / Gemini Centered New Chat & Continuous Message Stream (Black & White Monochromatic)
 */

document.addEventListener("DOMContentLoaded", () => {
  // Session State
  let currentUser = {
    userId: "alice",
    tenantId: "company_a",
    roles: ["employee"],
    clearance: ["public", "internal"]
  };

  let isDevMode = false;
  
  // Array of session objects: { id, title, turns: [ { query, data, timestamp } ] }
  let chatSessions = [];
  let activeSessionId = null;

  // DOM Elements - Gateway & Shell
  const loginGateway = document.getElementById("loginGateway");
  const appShell = document.getElementById("appShell");
  const loginForm = document.getElementById("loginForm");
  const loginUserId = document.getElementById("loginUserId");
  const loginTenantId = document.getElementById("loginTenantId");
  const loginRoles = document.getElementById("loginRoles");
  const loginClearance = document.getElementById("loginClearance");

  // Sidebar Elements
  const btnNewChat = document.getElementById("btnNewChat");
  const sidebarTenantName = document.getElementById("sidebarTenantName");
  const sidebarUserName = document.getElementById("sidebarUserName");
  const btnSidebarLogout = document.getElementById("btnSidebarLogout");
  const chatHistoryList = document.getElementById("chatHistoryList");

  // Navbar Elements
  const navTenantBreadcrumb = document.getElementById("navTenantBreadcrumb");
  const navTabBreadcrumb = document.getElementById("navTabBreadcrumb");
  const devModeToggle = document.getElementById("devModeToggle");
  const devModeStatusText = document.getElementById("devModeStatusText");
  const btnNavbarLogout = document.getElementById("btnNavbarLogout");

  // Assistant View Panels & Forms
  const viewAssistant = document.getElementById("viewAssistant");
  const newChatHero = document.getElementById("newChatHero");
  const heroQueryForm = document.getElementById("heroQueryForm");
  const heroQueryInput = document.getElementById("heroQueryInput");
  const heroSubmitBtn = document.getElementById("heroSubmitBtn");

  const activeChatView = document.getElementById("activeChatView");
  const chatMessagesStream = document.getElementById("chatMessagesStream");
  const streamQueryForm = document.getElementById("streamQueryForm");
  const streamQueryInput = document.getElementById("streamQueryInput");
  const streamSubmitBtn = document.getElementById("streamSubmitBtn");
  const streamSubmitText = document.getElementById("streamSubmitText");
  const streamSubmitSpinner = document.getElementById("streamSubmitSpinner");

  // Citation Stripper for Clean Natural Language Text
  function stripInlineCitations(text) {
    if (!text) return "";
    let cleaned = text.replace(/\s*\[\s*(?:doc|chunk)[^\]]*\]/gi, "");
    cleaned = cleaned.replace(/\s*\[\s*[a-zA-Z0-9_\-\.]+(?:\s*,\s*[a-zA-Z0-9_\-\.]+)*\s*\](?!\()/g, "");
    cleaned = cleaned.replace(/\s+([,\.\?!])/g, "$1");
    return cleaned.replace(/\s{2,}/g, " ").trim();
  }

  function escapeHtml(str) {
    if (!str) return "";
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // ============================================================================
  // 1. SESSION MANAGEMENT & RECENT CHATS UI
  // ============================================================================
  function renderChatHistoryUI() {
    if (!chatHistoryList) return;
    chatHistoryList.innerHTML = "";
    if (chatSessions.length === 0) {
      chatHistoryList.innerHTML = '<span class="history-empty">No previous chats</span>';
      return;
    }
    chatSessions.forEach(session => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "history-item" + (session.id === activeSessionId ? " active" : "");
      btn.textContent = session.title;
      btn.title = session.title;
      btn.addEventListener("click", () => {
        activeSessionId = session.id;
        renderChatHistoryUI();
        renderActiveSessionStream();
      });
      chatHistoryList.appendChild(btn);
    });
  }

  function createNewChatSession(initialQuery) {
    const session = {
      id: "session_" + Date.now(),
      title: initialQuery.length > 32 ? initialQuery.substring(0, 32) + "..." : initialQuery,
      turns: []
    };
    chatSessions.unshift(session);
    activeSessionId = session.id;
    renderChatHistoryUI();
    return session;
  }

  function resetToNewChat() {
    activeSessionId = null;
    renderChatHistoryUI();
    if (newChatHero) newChatHero.classList.remove("hidden");
    if (activeChatView) activeChatView.classList.add("hidden");
    if (chatMessagesStream) chatMessagesStream.innerHTML = "";
    if (heroQueryInput) heroQueryInput.value = "";
    if (streamQueryInput) streamQueryInput.value = "";
  }

  if (btnNewChat) btnNewChat.addEventListener("click", resetToNewChat);

  // ============================================================================
  // 2. AUTHENTICATION HANDLERS
  // ============================================================================
  loginForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const uid = loginUserId.value.trim() || "anonymous";
    const tid = loginTenantId.value.trim() || "default_tenant";
    const rls = loginRoles.value.split(",").map(r => r.trim()).filter(Boolean);
    const cls = loginClearance.value.split(",").map(c => c.trim()).filter(Boolean);

    currentUser = {
      userId: uid,
      tenantId: tid,
      roles: rls,
      clearance: cls
    };

    loginSession();
  });

  function loginSession() {
    if (sidebarTenantName) sidebarTenantName.textContent = currentUser.tenantId;
    if (sidebarUserName) sidebarUserName.textContent = currentUser.userId;
    if (navTenantBreadcrumb) navTenantBreadcrumb.textContent = currentUser.tenantId;

    loginGateway.classList.add("hidden");
    appShell.classList.remove("hidden");

    resetToNewChat();
    refreshVaultStatus();
  }

  function logoutSession() {
    appShell.classList.add("hidden");
    loginGateway.classList.remove("hidden");
    chatSessions = [];
    activeSessionId = null;
    renderChatHistoryUI();
    resetToNewChat();
  }

  if (btnSidebarLogout) btnSidebarLogout.addEventListener("click", logoutSession);
  if (btnNavbarLogout) btnNavbarLogout.addEventListener("click", logoutSession);

  // ============================================================================
  // 3. NAVIGATION TAB SWITCHER & DEVELOPER MODE TOGGLE
  // ============================================================================
  const navItems = document.querySelectorAll(".nav-item");
  const viewPanels = document.querySelectorAll(".view-panel");

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      navItems.forEach(n => n.classList.remove("active"));
      item.classList.add("active");

      const targetTab = item.dataset.tab;
      viewPanels.forEach(p => p.classList.add("hidden"));

      if (targetTab === "assistant") {
        document.getElementById("viewAssistant").classList.remove("hidden");
        if (navTabBreadcrumb) navTabBreadcrumb.textContent = "Assistant";
      } else if (targetTab === "vault") {
        document.getElementById("viewVault").classList.remove("hidden");
        if (navTabBreadcrumb) navTabBreadcrumb.textContent = "Knowledge Vault";
      } else if (targetTab === "security") {
        document.getElementById("viewSecurity").classList.remove("hidden");
        if (navTabBreadcrumb) navTabBreadcrumb.textContent = "Security Policy";
      }
    });
  });

  function toggleDevMode(forcedState = null) {
    isDevMode = forcedState !== null ? forcedState : !isDevMode;
    if (devModeToggle) {
      if (isDevMode) {
        devModeToggle.classList.add("active");
        if (devModeStatusText) { devModeStatusText.textContent = "ON"; devModeStatusText.className = "status-on"; }
      } else {
        devModeToggle.classList.remove("active");
        if (devModeStatusText) { devModeStatusText.textContent = "OFF"; devModeStatusText.className = "status-off"; }
      }
    }
    // Toggle all dev drawers in current stream
    document.querySelectorAll(".dev-drawer-mono").forEach(drawer => {
      if (isDevMode) drawer.classList.remove("hidden");
      else drawer.classList.add("hidden");
    });
  }

  if (devModeToggle) devModeToggle.addEventListener("click", () => toggleDevMode());

  // Quick Prompt Chips
  document.querySelectorAll(".prompt-chip-mono").forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.dataset.query;
      if (q) handleQuerySubmit(q);
    });
  });

  // Form Submissions
  if (heroQueryForm) {
    heroQueryForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const q = heroQueryInput.value.trim();
      if (q) handleQuerySubmit(q);
    });
  }

  if (streamQueryForm) {
    streamQueryForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const q = streamQueryInput.value.trim();
      if (q) handleQuerySubmit(q);
    });
  }

  // ============================================================================
  // 4. CONTINUOUS MULTI-TURN QUERY ENGINE WITH 3-TURN MEMORY
  // ============================================================================
  async function handleQuerySubmit(queryText) {
    if (!queryText) return;

    // Get or create session
    let session = chatSessions.find(s => s.id === activeSessionId);
    if (!session) {
      session = createNewChatSession(queryText);
    }

    // Prepare view
    if (newChatHero) newChatHero.classList.add("hidden");
    if (activeChatView) activeChatView.classList.remove("hidden");

    // Append User Question Turn immediately
    const userTurnElem = renderUserTurnBubble(queryText);
    chatMessagesStream.appendChild(userTurnElem);

    // Append Loading Indicator Turn
    const loadingTurnElem = renderLoadingTurnBubble();
    chatMessagesStream.appendChild(loadingTurnElem);
    scrollToStreamBottom();

    // Disable inputs while requesting
    setInputsDisabled(true);

    // Prepare last 3 Q&A turns (up to 6 messages) for conversation_history
    const last3Turns = session.turns.slice(-3);
    const chatHistoryPayload = [];
    last3Turns.forEach(turn => {
      chatHistoryPayload.push({ role: "user", content: turn.query });
      const cleanAnswer = stripInlineCitations(turn.data.answer || turn.data.generation?.answer || "");
      chatHistoryPayload.push({ role: "assistant", content: cleanAnswer });
    });

    try {
      const response = await fetch("/api/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: queryText,
          user_id: currentUser.userId,
          tenant_id: currentUser.tenantId,
          roles: Array.isArray(currentUser.roles) ? currentUser.roles : [currentUser.roles],
          allowed_classifications: Array.isArray(currentUser.clearance) ? currentUser.clearance : [currentUser.clearance],
          chat_history: chatHistoryPayload
        })
      });

      const data = await response.json();

      // Save turn to active session
      const turnObj = {
        query: queryText,
        data: data,
        timestamp: new Date().toISOString()
      };
      session.turns.push(turnObj);

      // Remove loading indicator
      loadingTurnElem.remove();

      // Append AI Response Turn
      const turnIdx = session.turns.length - 1;
      const aiTurnElem = renderAiTurnCard(turnObj, turnIdx);
      chatMessagesStream.appendChild(aiTurnElem);
      scrollToStreamBottom();

      // Clear input text
      if (heroQueryInput) heroQueryInput.value = "";
      if (streamQueryInput) streamQueryInput.value = "";

    } catch (err) {
      loadingTurnElem.remove();
      const errTurnElem = renderErrorTurnCard(err);
      chatMessagesStream.appendChild(errTurnElem);
      scrollToStreamBottom();
    } finally {
      setInputsDisabled(false);
      refreshVaultStatus();
    }
  }

  function setInputsDisabled(disabled) {
    if (heroSubmitBtn) heroSubmitBtn.disabled = disabled;
    if (streamSubmitBtn) streamSubmitBtn.disabled = disabled;
    if (streamSubmitSpinner) {
      if (disabled) streamSubmitSpinner.classList.remove("hidden");
      else streamSubmitSpinner.classList.add("hidden");
    }
    if (streamSubmitText) streamSubmitText.textContent = disabled ? "..." : "Send";
  }

  function scrollToStreamBottom() {
    if (chatMessagesStream) {
      chatMessagesStream.scrollTop = chatMessagesStream.scrollHeight;
    }
  }

  // ============================================================================
  // 5. STREAM RENDER HELPERS
  // ============================================================================
  function renderActiveSessionStream() {
    const session = chatSessions.find(s => s.id === activeSessionId);
    if (!session || session.turns.length === 0) {
      resetToNewChat();
      return;
    }

    if (newChatHero) newChatHero.classList.add("hidden");
    if (activeChatView) activeChatView.classList.remove("hidden");
    if (chatMessagesStream) chatMessagesStream.innerHTML = "";

    session.turns.forEach((turn, idx) => {
      const userElem = renderUserTurnBubble(turn.query);
      const aiElem = renderAiTurnCard(turn, idx);
      chatMessagesStream.appendChild(userElem);
      chatMessagesStream.appendChild(aiElem);
    });

    scrollToStreamBottom();
  }

  function renderUserTurnBubble(queryText) {
    const div = document.createElement("div");
    div.className = "chat-turn user-turn";
    div.innerHTML = `
      <div class="turn-avatar user-avatar">U</div>
      <div class="turn-content">
        <div class="user-bubble">${escapeHtml(queryText)}</div>
      </div>
    `;
    return div;
  }

  function renderLoadingTurnBubble() {
    const div = document.createElement("div");
    div.className = "chat-turn ai-turn";
    div.innerHTML = `
      <div class="turn-avatar ai-avatar">AI</div>
      <div class="turn-content">
        <div class="loading-bubble">
          <span class="spinner-ring-mono" style="width:14px;height:14px;border-width:2px;"></span>
          <span>Scoping retrieval &amp; generating answer...</span>
        </div>
      </div>
    `;
    return div;
  }

  function renderAiTurnCard(turnObj, turnIdx) {
    const data = turnObj.data;
    const isSuccess = data.status === "success" && data.chunks && data.chunks.length > 0;
    const rawAnswer = data.answer || (data.generation ? data.generation.answer : "");
    const cleanAnswer = stripInlineCitations(rawAnswer);
    const stage3Status = data.stage3_status || (data.generation ? data.generation.status : "SAFE");
    const citations = data.citations || (data.generation ? data.generation.citations : []);

    const div = document.createElement("div");
    div.className = "chat-turn ai-turn";

    // IF RESTRICTED / NO CHUNKS / BLOCKED: Render plain message bubble (NO CARD)
    if (!isSuccess || stage3Status === "BLOCKED") {
      const blockMsg = cleanAnswer || data.message || "Access restricted or no authorized documents found for your tenant scope.";
      div.innerHTML = `
        <div class="turn-avatar ai-avatar">AI</div>
        <div class="turn-content">
          <div class="user-bubble" style="background:#18181b; border-color:#27272a; color:#a1a1aa;">
            ${escapeHtml(blockMsg)}
          </div>
        </div>
      `;
      return div;
    }

    // AUTHORIZED ANSWER AVAILABLE: Build Citations with Document Name + Page Number
    let citationsHtml = "<span class='citation-pill-mono'>No citations</span>";
    if (data.chunks && data.chunks.length > 0) {
      const seen = new Set();
      const pills = [];
      data.chunks.forEach(c => {
        const docName = c.source_file || c.source_doc || c.chunk_id || "document";
        let pageStr = "Page 1";
        if (c.metadata && (c.metadata.page || c.metadata.page_number)) {
          pageStr = `Page ${c.metadata.page || c.metadata.page_number}`;
        } else if (c.text) {
          const match = c.text.match(/\[Page\s*(\d+)\]/i);
          if (match) pageStr = `Page ${match[1]}`;
        }
        const label = `[${docName}, ${pageStr}]`;
        if (!seen.has(label)) {
          seen.add(label);
          pills.push(`<span class="citation-pill-mono">${escapeHtml(label)}</span>`);
        }
      });
      if (pills.length > 0) citationsHtml = pills.join("");
    } else if (citations && citations.length > 0) {
      citationsHtml = citations.map(c => {
        const label = typeof c === "string" ? c : (c.source_doc || c.source_file || c.chunk_id);
        const text = label.startsWith("[") ? label : `[${label}]`;
        return `<span class="citation-pill-mono">${escapeHtml(text)}</span>`;
      }).join("");
    }

    // Chunks Cards for Dev Drawer
    let chunksHtml = "";
    if (data.chunks) {
      chunksHtml = data.chunks.map((c, idx) => {
        const classification = c.classification || "internal";
        const dist = typeof c.vector_distance === "number" ? c.vector_distance.toFixed(3) : "--";
        const rerankScore = typeof c.rerank_score === "number" ? c.rerank_score.toFixed(3) : "--";
        return `
          <div class="chunk-card">
            <div class="chunk-top-meta">
              <span class="chunk-file">[Chunk ${idx + 1}] ${escapeHtml(c.source_file || "unknown")}</span>
              <div class="chunk-badges">
                <span class="badge-class">${classification}</span>
                <span class="chunk-score">Rerank: ${rerankScore}</span>
                <span class="chunk-score">Dist: ${dist}</span>
              </div>
            </div>
            <div class="chunk-text">${escapeHtml(c.text || "")}</div>
          </div>
        `;
      }).join("");
    }

    const contextText = data.context_text || "// No authorized context available for Stage 3 LLM synthesis.";
    const auditJsonStr = JSON.stringify(data.audit_event || { event_type: "RETRIEVAL", query: turnObj.query }, null, 2);

    // Render SINGLE Simplified Card (ONLY Answer + Citations)
    div.innerHTML = `
      <div class="turn-avatar ai-avatar">AI</div>
      <div class="turn-content">
        <div class="ai-response-card-mono">
          <div class="ai-card-header-mono">
            <div class="ai-card-title-mono">
              <h4>AI Response</h4>
            </div>
            <div class="ai-card-actions-mono">
              <button type="button" class="btn-sub-dev-mono btn-toggle-drawer" data-drawer-id="drawer_${turnIdx}">
                Inspect RAG Chunks
              </button>
            </div>
          </div>

          <div class="ai-answer-box-mono">
            <p class="ai-answer-text-mono">${escapeHtml(cleanAnswer) || "// No response generated."}</p>
          </div>

          <div class="ai-card-footer-mono">
            <div class="footer-block-mono">
              <span class="footer-label-mono">VALIDATED SOURCE CITATIONS</span>
              <div class="citations-flex-mono">${citationsHtml}</div>
            </div>
          </div>
        </div>

        <!-- Developer Inspection Drawer -->
        <div id="drawer_${turnIdx}" class="dev-drawer-mono ${isDevMode ? "" : "hidden"}">
          <div class="dev-drawer-header-mono">
            <span class="dev-badge-mono">DEVELOPER INSPECTION MODE</span>
            <p>Stage 2 vector candidates, cross-encoder rerank scores, XML context, and JSON audit log.</p>
          </div>

          <div class="dev-section-mono">
            <div class="dev-section-header-mono">
              <h5>Stage 3 Prompt Context (&lt;untrusted_documents&gt;)</h5>
            </div>
            <pre class="code-block-mono">${escapeHtml(contextText)}</pre>
          </div>

          <div class="dev-section-mono">
            <h5 class="mb-2">Retrieved Vector Chunks &amp; Cross-Encoder Scores</h5>
            <div class="chunks-vertical-list-mono">${chunksHtml}</div>
          </div>

          <div class="dev-section-mono">
            <div class="dev-section-header-mono">
              <h5>Cryptographic Immutable Audit Event</h5>
            </div>
            <pre class="audit-code-mono">${escapeHtml(auditJsonStr)}</pre>
          </div>
        </div>
      </div>
    `;

    const btnToggle = div.querySelector(`.btn-toggle-drawer`);
    if (btnToggle) {
      btnToggle.addEventListener("click", () => {
        const drawer = div.querySelector(`#drawer_${turnIdx}`);
        if (drawer) {
          drawer.classList.toggle("hidden");
          btnToggle.textContent = drawer.classList.contains("hidden") ? "Inspect RAG Chunks" : "Hide RAG Inspection";
        }
      });
    }

    return div;
  }

  function renderErrorTurnCard(err) {
    const div = document.createElement("div");
    div.className = "chat-turn ai-turn";
    div.innerHTML = `
      <div class="turn-avatar ai-avatar">AI</div>
      <div class="turn-content">
        <div class="decision-banner-mono denied">
          <div class="banner-text">
            <strong>Server Communication Error</strong>
            <span>${escapeHtml(err.message || "Failed to connect to SecureRAG backend server.")}</span>
          </div>
        </div>
      </div>
    `;
    return div;
  }

  // ============================================================================
  // 6. VAULT STATUS SYNC ENGINE
  // ============================================================================
  async function refreshVaultStatus() {
    try {
      const res = await fetch("/api/status");
      if (res.ok) {
        const data = await res.json();
        const count = data.indexed_chunks_count ?? "--";
        const quar = data.quarantined_documents_count ?? "--";

        const vTotal = document.getElementById("vaultTotalChunks");
        const vQuar = document.getElementById("vaultTotalQuarantined");
        if (vTotal) vTotal.textContent = count;
        if (vQuar) vQuar.textContent = quar;
      }
    } catch (err) {
      console.warn("Status fetch failed:", err);
    }
  }

});
