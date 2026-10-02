const $ = (id) => document.getElementById(id);

let latestResult = null;

document.querySelectorAll(".tab").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    button.classList.add("active");
    $(button.dataset.tab).classList.add("active");
  });
});

$("exampleBtn").addEventListener("click", () => {
  $("messageInput").value =
`URGENT! Your KYC will expire today.
Click http://example-login-verify.com immediately.
Pay ₹10 to avoid account suspension.
Send the OTP after payment to confirm verification.`;
});

async function postJSON(url, data) {
  const response = await fetch(url, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data)
  });
  if (!response.ok) throw new Error("Server request failed");
  return response.json();
}

$("analyzeBtn").addEventListener("click", async () => {
  const text = $("messageInput").value.trim();
  if (!text) return alert("Please enter a message first.");
  await runAnalysis(text);
});

async function runAnalysis(text) {
  try {
    $("analyzeBtn").disabled = true;
    const result = await postJSON("/api/analyze", {
      text,
      language: $("language").value
    });
    renderResult(result);
  } catch (error) {
    alert("Could not analyze the message. Is the server running?");
  } finally {
    $("analyzeBtn").disabled = false;
  }
}

$("checkUrlBtn").addEventListener("click", async () => {
  const url = $("urlInput").value.trim();
  if (!url) return alert("Enter a URL.");
  try {
    const result = await postJSON("/api/check-url", {
      url,
      language: $("language").value
    });

    const syntheticText = result.result.flags.length
      ? `Please review this suspicious URL: ${url}`
      : `Please review this URL: ${url}`;

    const analysis = await postJSON("/api/analyze", {
      text: syntheticText,
      language: $("language").value
    });

    analysis.urls = [result.result];
    renderResult(analysis);
  } catch {
    alert("Could not check the URL.");
  }
});

$("ocrBtn").addEventListener("click", async () => {
  const file = $("imageInput").files[0];
  if (!file) return alert("Choose a screenshot first.");

  $("ocrStatus").textContent = "Reading screenshot… this can take a moment.";

  try {
    const worker = await Tesseract.createWorker("eng");
    const { data: { text } } = await worker.recognize(file);
    await worker.terminate();

    $("ocrStatus").textContent = "Screenshot text extracted.";
    $("messageInput").value = text.trim();

    document.querySelector('[data-tab="message"]').click();
    await runAnalysis(text.trim());
  } catch (error) {
    console.error(error);
    $("ocrStatus").textContent = "OCR failed. Try a clearer screenshot.";
  }
});

let recognition = null;

$("voiceBtn").addEventListener("click", () => {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

  if (!SpeechRecognition) {
    $("voiceStatus").textContent =
      "Speech recognition is not supported in this browser. Use Chrome/Edge or paste text instead.";
    return;
  }

  recognition = new SpeechRecognition();
  recognition.lang = $("language").value === "hi" ? "hi-IN" : "en-IN";
  recognition.interimResults = true;
  recognition.continuous = false;

  $("voiceStatus").textContent = "Listening…";

  recognition.onresult = (event) => {
    let transcript = "";
    for (let i = event.resultIndex; i < event.results.length; i++) {
      transcript += event.results[i][0].transcript;
    }
    $("voiceText").value = transcript;
  };

  recognition.onerror = (event) => {
    $("voiceStatus").textContent = "Voice input error: " + event.error;
  };

  recognition.onend = () => {
    $("voiceStatus").textContent = "Voice input finished.";
  };

  recognition.start();
});

$("voiceAnalyzeBtn").addEventListener("click", async () => {
  const text = $("voiceText").value.trim();
  if (!text) return alert("No transcription available.");
  await runAnalysis(text);
});

function renderResult(data) {
  latestResult = data;
  $("result").classList.remove("hidden");

  $("riskTitle").textContent = data.risk_label || data.risk_level;
  $("riskBadge").textContent = data.risk_level.toUpperCase();
  $("riskBadge").className = "risk-badge risk-" + data.risk_level;

  $("riskScore").textContent = data.score + "/100";
  $("confidence").textContent = data.confidence + "%";
  $("flagCount").textContent = data.flags.length;

  const evidence = $("evidence");
  evidence.innerHTML = "";

  if (!data.evidence.length) {
    evidence.innerHTML = `<div class="evidence-item"><strong>No rule-based red flag was detected.</strong><p>That does not prove the message is safe. Verify independently when money or sensitive information is involved.</p></div>`;
  } else {
    data.evidence.forEach(item => {
      const div = document.createElement("div");
      div.className = "evidence-item";
      div.innerHTML = `<strong>${escapeHTML(item.rule)}</strong>
        <p>${escapeHTML(item.explanation)}</p>
        ${item.snippets.map(s => `<code>${escapeHTML(s)}</code>`).join("")}`;
      evidence.appendChild(div);
    });
  }

  const steps = $("safeSteps");
  steps.innerHTML = "";
  data.safe_steps.forEach(step => {
    const li = document.createElement("li");
    li.textContent = step;
    steps.appendChild(li);
  });

  $("redactedText").textContent = data.redacted_text;

  const urlBox = $("urlResults");
  urlBox.innerHTML = "";
  if (data.urls && data.urls.length) {
    const title = document.createElement("h3");
    title.textContent = "🔗 Link inspection";
    urlBox.appendChild(title);

    data.urls.forEach(u => {
      const div = document.createElement("div");
      div.className = "url-item";
      div.innerHTML = `<strong>${escapeHTML(u.url)}</strong>
        <p>Domain: ${escapeHTML(u.domain || "unknown")}</p>
        <p>${u.flags.length ? u.flags.map(escapeHTML).join(" • ") : "No obvious URL-string warning detected."}</p>`;
      urlBox.appendChild(div);
    });
  }

  $("disclaimer").textContent = data.disclaimer;
  $("result").scrollIntoView({behavior: "smooth", block: "start"});
}

$("clearBtn").addEventListener("click", () => {
  latestResult = null;
  $("result").classList.add("hidden");
});

$("reportBtn").addEventListener("click", () => {
  if (!latestResult) return;

  const report = {
    product: "ScamShield",
    generated_at: new Date().toISOString(),
    risk_level: latestResult.risk_level,
    risk_score: latestResult.score,
    rule_confidence: latestResult.confidence,
    flags: latestResult.flags,
    evidence: latestResult.evidence,
    redacted_text: latestResult.redacted_text,
    safe_steps: latestResult.safe_steps,
    note: "Prototype report. Sensitive details are masked where recognized."
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json"
  });

  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "scamshield-incident-report.json";
  a.click();
  URL.revokeObjectURL(a.href);
});

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
