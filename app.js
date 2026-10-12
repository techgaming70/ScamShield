
const $ = (id) => document.getElementById(id);

let latestResult = null;

// Switch between the existing tabs.
document.querySelectorAll(".tab").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b =>
      b.classList.remove("active")
    );
    document.querySelectorAll(".tab-content").forEach(c =>
      c.classList.remove("active")
    );

    button.classList.add("active");
    const panel = $(button.dataset.tab);
    if (panel) panel.classList.add("active");
  });
});

// Load the demo message.
$("exampleBtn").addEventListener("click", () => {
  $("messageInput").value =
`URGENT! Your KYC will expire today.
Click http://example-login-verify.com immediately.
Pay ₹10 to avoid account suspension.
Send the OTP after payment to confirm verification.`;
});

// Common suspicious patterns.
const RULES = [
  {
    id: "urgency",
    pattern: /\b(urgent|immediately|right now|act now|expires today|final warning|limited time|within \d+ hours?)\b/i,
    points: 18,
    rule: "Urgent or pressuring language",
    explanation: "The message pressures the recipient to act quickly without taking time to verify."
  },
  {
    id: "otp",
    pattern: /\b(otp|one[- ]time password|verification code|security code)\b/i,
    points: 25,
    rule: "Verification code mentioned",
    explanation: "Never share an OTP or verification code with another person or an unverified website."
  },
  {
    id: "credentials",
    pattern: /\b(password|passcode|login details|account credentials|pin number|share your pin)\b/i,
    points: 25,
    rule: "Account credentials requested or mentioned",
    explanation: "Requests involving passwords, PINs, or login details need independent verification."
  },
  {
    id: "payment",
    pattern: /\b(pay|payment|transfer money|send money|processing fee|registration fee|deposit|upi|bank transfer|gift card)\b|₹\s?\d+/i,
    points: 18,
    rule: "Payment or money transfer mentioned",
    explanation: "Verify payment requests through an official channel before sending money."
  },
  {
    id: "threat",
    pattern: /\b(account suspended|account blocked|legal action|police case|arrest|account will be closed|kyc will expire|penalty)\b/i,
    points: 22,
    rule: "Threat or account-related pressure",
    explanation: "Scam messages may use threats or account restrictions to pressure people into acting."
  },
  {
    id: "prize",
    pattern: /\b(you have won|winner selected|claim your prize|free reward|lottery winner|guaranteed profit)\b/i,
    points: 20,
    rule: "Unexpected prize or reward",
    explanation: "Unexpected prizes and guaranteed returns can be used to lure people into scams."
  },
  {
    id: "secrecy",
    pattern: /\b(keep this secret|do not tell anyone|don't tell anyone|act secretly)\b/i,
    points: 15,
    rule: "Request for secrecy",
    explanation: "Pressure to keep a financial or account-related request secret is a warning sign."
  }
];

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getURLs(text) {
  const matches = text.match(
    /\b(?:https?:\/\/|www\.)[^\s<>"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi
  ) || [];

  return [...new Set(matches.map(item =>
    item.replace(/[),.!?;]+$/, "")
  ))];
}

function inspectURL(input) {
  let parsed;

  try {
    const normalized = /^https?:\/\//i.test(input)
      ? input
      : "https://" + input;

    parsed = new URL(normalized);

    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error("Unsupported protocol");
    }
  } catch {
    return {
      url: input,
      domain: "invalid URL",
      flags: ["URL could not be parsed; verify it before opening."]
    };
  }

  const domain = parsed.hostname.toLowerCase();
  const flags = [];

  if (parsed.protocol === "http:") {
    flags.push("Uses HTTP instead of encrypted HTTPS.");
  }

  if (parsed.username || parsed.password || input.includes("@")) {
    flags.push("Contains an @ symbol or embedded credentials.");
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
    flags.push("Uses an IP address instead of a normal domain name.");
  }

  if (domain.startsWith("xn--") || domain.split(".").some(p => p.startsWith("xn--"))) {
    flags.push("Contains an internationalized domain label; check for look-alike characters.");
  }

  if (domain.split(".").length >= 5) {
    flags.push("Contains many subdomain levels.");
  }

  if (domain.length > 45) {
    flags.push("Has an unusually long domain name.");
  }

  if (/(login|verify|verification|secure|account|kyc|banking|wallet|update|claim|reward|free|gift|support)/i.test(domain)) {
    flags.push("Domain contains words commonly used in account, reward, or verification lures.");
  }

  const shorteners = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly"
  ];

  if (shorteners.some(s => domain === s || domain.endsWith("." + s))) {
    flags.push("Uses a link-shortening service, which hides the final destination.");
  }

  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    flags.push("Uses an unusual web port.");
  }

  if (parsed.href.length > 180) {
    flags.push("URL is unusually long.");
  }

  return {
    url: input,
    domain,
    flags
  };
}

function redactSensitiveText(text) {
  return text
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[EMAIL REDACTED]")
    .replace(/\b(?:\+?\d[\d ()-]{7,}\d)\b/g, "[PHONE REDACTED]");
}

function analyzeLocally(text) {
  const evidence = [];
  let score = 0;

  for (const rule of RULES) {
    const match = text.match(rule.pattern);

    if (match) {
      score += rule.points;
      evidence.push({
        rule: rule.rule,
        explanation: rule.explanation,
        snippets: [match[0].slice(0, 100)]
      });
    }
  }

  const urls = getURLs(text).map(inspectURL);

  for (const item of urls) {
    if (item.flags.length > 0) {
      score += Math.min(24, item.flags.length * 8);

      evidence.push({
        rule: "Suspicious URL indicators",
        explanation: "The link has characteristics worth checking carefully. These indicators alone do not prove that it is malicious.",
        snippets: [item.url.slice(0, 120)]
      });
    }
  }

  score = Math.min(100, score);

  const risk_level =
    score >= 60 ? "high" :
    score >= 30 ? "medium" : "low";

  const risk_label =
    risk_level === "high" ? "High risk indicators detected" :
    risk_level === "medium" ? "Some warning signs detected" :
    "Few warning signs detected";

  return {
    risk_level,
    risk_label,
    score,
    confidence: evidence.length ? Math.min(95, 55 + evidence.length * 8) : 60,
    flags: evidence.map(item => item.rule),
    evidence,
    urls,
    redacted_text: redactSensitiveText(text),
    safe_steps: [
      "Do not share passwords, PINs, OTPs, or banking details.",
      "Do not click suspicious links or pay unexpected fees.",
      "Verify requests through the organisation's official website or phone number.",
      "If you already sent money, contact your bank or payment provider promptly."
    ],
    disclaimer: "ScamShield uses local rule-based checks. This result is an indicator, not proof that a message or link is safe or fraudulent. No external threat database is queried."
  };
}

// Analyse a message without a backend server.
$("analyzeBtn").addEventListener("click", async () => {
  const text = $("messageInput").value.trim();

  if (!text) {
    alert("Please enter a message first.");
    return;
  }

  await runAnalysis(text);
});

async function runAnalysis(text) {
  $("analyzeBtn").disabled = true;

  try {
    const result = analyzeLocally(text);
    renderResult(result);
  } catch (error) {
    console.error(error);
    alert("Analysis failed. Please try again.");
  } finally {
    $("analyzeBtn").disabled = false;
  }
}

// Check a URL locally, without calling an API.
$("checkUrlBtn").addEventListener("click", async () => {
  const url = $("urlInput").value.trim();

  if (!url) {
    alert("Enter a URL.");
    return;
  }

  const result = inspectURL(url);
  const analysis = analyzeLocally(
    result.flags.length
      ? `Please review this suspicious URL: ${url}`
      : `Please review this URL: ${url}`
  );

  analysis.urls = [result];

  // Include URL warnings in the overall result too.
  if (result.flags.length) {
    analysis.score = Math.min(
      100,
      analysis.score + Math.min(24, result.flags.length * 8)
    );
    analysis.risk_level =
      analysis.score >= 60 ? "high" :
      analysis.score >= 30 ? "medium" : "low";
    analysis.risk_label =
      analysis.risk_level === "high" ? "High risk indicators detected" :
      analysis.risk_level === "medium" ? "Some warning signs detected" :
      "Few warning signs detected";
  }

  renderResult(analysis);
});

// Extract text from an uploaded screenshot using the existing Tesseract library.
$("ocrBtn").addEventListener("click", async () => {
  const file = $("imageInput").files[0];

  if (!file) {
    alert("Choose a screenshot first.");
    return;
  }

  $("ocrStatus").textContent = "Reading screenshot… this can take a moment.";

  let worker;

  try {
    worker = await Tesseract.createWorker("eng");
    const { data: { text } } = await worker.recognize(file);

    $("messageInput").value = text.trim();
    $("ocrStatus").textContent = "Screenshot text extracted.";

    document.querySelector('[data-tab="message"]').click();

    if (text.trim()) await runAnalysis(text.trim());
  } catch (error) {
    console.error(error);
    $("ocrStatus").textContent =
      "OCR failed. Check your internet connection and try a clearer screenshot.";
  } finally {
    if (worker) await worker.terminate();
  }
});

// Voice input.
let recognition = null;

$("voiceBtn").addEventListener("click", () => {
  const SpeechRecognition =
    window.SpeechRecognition || window.webkitSpeechRecognition;

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

  recognition.onresult = event => {
    let transcript = "";

    for (let i = event.resultIndex; i < event.results.length; i++) {
      transcript += event.results[i][0].transcript;
    }

    $("voiceText").value = transcript;
  };

  recognition.onerror = event => {
    $("voiceStatus").textContent = "Voice input error: " + event.error;
  };

  recognition.onend = () => {
    $("voiceStatus").textContent = "Voice input finished.";
  };

  recognition.start();
});

$("voiceAnalyzeBtn").addEventListener("click", async () => {
  const text = $("voiceText").value.trim();

  if (!text) {
    alert("No transcription available.");
    return;
  }

  await runAnalysis(text);
});

// Display the analysis using the existing HTML elements.
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
    evidence.innerHTML =
      `<div class="evidence-item">
        <strong>No rule-based red flag was detected.</strong>
        <p>This does not prove the message is safe. Verify independently when money or sensitive information is involved.</p>
      </div>`;
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
        <p>${u.flags.length
          ? u.flags.map(escapeHTML).join(" • ")
          : "No obvious URL-string warning detected."}</p>`;

      urlBox.appendChild(div);
    });
  }

  $("disclaimer").textContent = data.disclaimer;
  $("result").scrollIntoView({ behavior: "smooth", block: "start" });
}

// Clear the displayed result.
$("clearBtn").addEventListener("click", () => {
  latestResult = null;
  $("result").classList.add("hidden");
});

// Download an incident report.
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
    note: "Prototype report based on local rule-based checks. Sensitive details are masked where recognized."
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json"
  });

  const objectURL = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objectURL;
  a.download = "scamshield-incident-report.json";
  a.click();

  setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
});

