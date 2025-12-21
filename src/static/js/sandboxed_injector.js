/* eslint-disable no-console */
/**
 * ISOL8R Project Sandtrap - PyJail Front-End Companion
 * ----------------------------------------------------
 * This script powers the interactive experience for the PyJail execution
 * console. Features include:
 *   - Asynchronous submission of code payloads
 *   - Animated status indicators with sarcastic color commentary
 *   - Session transcript logging because memory is a myth
 *   - Auto-fill examples for the impatient (or the cautious)
 *   - Console messages mocking the payloads just enough to entertain staff
 *
 * It is intentionally verbose to match the lab's "if it isn't documented,
 * it didn't happen" culture. Feel free to skim the jokes while pretending
 * to audit the security controls.
 */
(function () {
  "use strict";

  const state = {
    history: [],
    lastDuration: null,
    status: "idle",
  };

  const dom = {
    codeInput: document.getElementById("code-input"),
    executeBtn: document.getElementById("execute-btn"),
    clearBtn: document.getElementById("clear-btn"),
    backBtn: document.getElementById("view-index-btn"),
    statusDot: document.getElementById("status-dot"),
    statusText: document.getElementById("status-text"),
    durationText: document.getElementById("duration-text"),
    outputArea: document.getElementById("output-area"),
    errorArea: document.getElementById("error-area"),
    banner: document.getElementById("banner"),
    metadataTimestamp: document.getElementById("metadata-timestamp"),
    metadataKeywords: document.getElementById("metadata-keywords"),
    metadataFlag: document.getElementById("metadata-flag"),
    historyLog: document.getElementById("history-log"),
    autoFillButtons: Array.from(document.querySelectorAll(".auto-fill")),
  };

  const config = window.ISOL8R_PYJAIL || {
    endpoints: { execute: "/run-python" },
    consoleTagline: "PyJail: improvised restrictions edition",
    samples: [],
    user: "Unknown Operator",
  };

  function nowStamp() {
    const now = new Date();
    return now.toISOString().split("T")[1].replace("Z", "");
  }

  function pushHistory(message) {
    const stamp = `[${nowStamp()}]`;
    const entry = `${stamp} ${message}`;
    state.history.push(entry);
    if (state.history.length > 120) {
      state.history.shift();
    }
    dom.historyLog.textContent = state.history.join("\n");
  }

  function setStatus(status, detail) {
    state.status = status;
    dom.statusDot.classList.remove("ready", "error", "success");
    switch (status) {
      case "idle":
        dom.statusDot.classList.add("ready");
        dom.statusText.textContent = detail || "Awaiting input...";
        break;
      case "running":
        dom.statusDot.classList.add("ready");
        dom.statusText.textContent = detail || "Executing payload...";
        break;
      case "error":
        dom.statusDot.classList.add("error");
        dom.statusText.textContent = detail || "Containment sarcasm engaged.";
        break;
      case "success":
        dom.statusDot.classList.add("success");
        dom.statusText.textContent = detail || "Sandbox returned without fireworks.";
        break;
      default:
        dom.statusDot.classList.add("ready");
        dom.statusText.textContent = "Status uncertain. Consult the fortune cookies.";
    }
  }

  function clearOutput() {
    dom.outputArea.textContent = "";
    dom.errorArea.style.display = "none";
    dom.errorArea.textContent = "";
    dom.banner.style.display = "none";
    dom.banner.textContent = "";
    dom.metadataTimestamp.textContent = "—";
    dom.metadataKeywords.textContent = "—";
    dom.metadataFlag.textContent = "—";
    dom.durationText.textContent = "Duration: —";
    setStatus("idle");
    pushHistory("Output cleared by operator command.");
  }

  function renderResult(result) {
    const { output, stderr, error, banner, duration, banned_keywords: banned, fake_flag_dropped: flagDroppped } = result;
    dom.outputArea.textContent = output || (stderr ? "(stdout empty)" : "(no output)");
    dom.durationText.textContent = `Duration: ${duration ? duration.toFixed(4) + "s" : "—"}`;
    dom.metadataTimestamp.textContent = new Date().toLocaleString();
    dom.metadataKeywords.textContent = banned && banned.length ? banned.join(", ") : "none detected";
    dom.metadataFlag.textContent = flagDroppped ? "Fake flag deployed (/fake-flags)." : "No decoys dispensed.";

    if (banner) {
      dom.banner.style.display = "block";
      dom.banner.textContent = banner;
    } else {
      dom.banner.style.display = "none";
    }

    if (error || (stderr && stderr.trim().length)) {
      dom.errorArea.style.display = "block";
      dom.errorArea.textContent = error || stderr;
      setStatus("error");
      pushHistory(`PyJail returned an error: ${error || stderr}`);
    } else {
      dom.errorArea.style.display = "none";
      dom.errorArea.textContent = "";
      setStatus("success");
      pushHistory("PyJail execution completed without notable complaints.");
    }
  }

  function mockPayload(payload) {
    if (!payload) {
      console.info("[PyJail Console] Empty payload submitted. Bold move.");
      return;
    }
    if (payload.toLowerCase().includes("flag")) {
      console.info("[PyJail Console] Found 'flag' in payload. Dispensing disappointment.");
    } else if (payload.includes("import")) {
      console.warn("[PyJail Console] Import detected. The alarm button just lit up (again).");
    } else if (payload.length > 400) {
      console.info("[PyJail Console] Long form payload detected. Stretching before execution.");
    } else {
      console.debug(`[PyJail Console] Payload preview: ${payload.slice(0, 80)}${payload.length > 80 ? "..." : ""}`);
    }
  }

  async function executePayload() {
    const code = dom.codeInput.value;
    mockPayload(code);
    if (!code.trim()) {
      setStatus("error", "No payload submitted. The sandbox sighs.");
      dom.errorArea.style.display = "block";
      dom.errorArea.textContent = "Please provide some code. The watchdog refuses to evaluate boredom.";
      pushHistory("Execution blocked: empty payload provided.");
      return;
    }

    setStatus("running");
    dom.errorArea.style.display = "none";
    dom.errorArea.textContent = "";

    pushHistory("Dispatching payload to PyJail service endpoint.");

    try {
      const response = await fetch(config.endpoints.execute, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const result = await response.json();
      renderResult(result);

      if (!response.ok) {
        setStatus("error", "Payload triggered containment protocol.");
      }
    } catch (err) {
      console.error("[PyJail Console] Network failure:", err);
      setStatus("error", "Network error: the hamster fell off the treadmill.");
      dom.errorArea.style.display = "block";
      dom.errorArea.textContent = `Network or server issue: ${err}`;
      pushHistory(`Execution failed due to network issue: ${err}`);
    }
  }

  function bindEvents() {
    dom.executeBtn.addEventListener("click", executePayload);
    dom.clearBtn.addEventListener("click", clearOutput);
    dom.backBtn.addEventListener("click", () => {
      const url = dom.backBtn.getAttribute("data-url");
      pushHistory("Navigating back to the dashboard.");
      window.location.href = url;
    });

    dom.autoFillButtons.forEach((button) => {
      button.addEventListener("click", () => {
        const payload = button.getAttribute("data-payload") || "";
        dom.codeInput.value = payload;
        setStatus("idle", "Sample payload loaded.");
        pushHistory(`Inserted auto-fill snippet: ${payload.slice(0, 60)}${payload.length > 60 ? "..." : ""}`);
      });
    });

    dom.codeInput.addEventListener("keydown", (event) => {
      if (event.key === "Tab") {
        event.preventDefault();
        const { selectionStart, selectionEnd, value } = dom.codeInput;
        dom.codeInput.value = `${value.substring(0, selectionStart)}  ${value.substring(selectionEnd)}`;
        dom.codeInput.selectionStart = dom.codeInput.selectionEnd = selectionStart + 2;
      }
    });
  }

  function init() {
    bindEvents();
    pushHistory(`Console online for ${config.user}. Tagline: ${config.consoleTagline}`);
    setStatus("idle");
    if (config.samples && config.samples.length) {
      console.info(`[PyJail Console] ${config.samples.length} prepared payload(s) available.`);
    } else {
      console.info("[PyJail Console] No auto-fill samples provided. Going freestyle.");
    }
  }

  init();
})();
