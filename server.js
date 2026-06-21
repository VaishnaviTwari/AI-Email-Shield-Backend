// MailGuard AI Backend v4
// ─────────────────────────────────────────────────────────────
// Secure Groq API proxy. Users never see the API key.
// Includes rate limiting, abuse protection, and daily quotas.
// ─────────────────────────────────────────────────────────────

require("dotenv").config();

const express  = require("express");
const cors     = require("cors");
const helmet   = require("helmet");
const fetch    = require("node-fetch");
const rateLimit = require("express-rate-limit");

const app  = express();
const PORT = process.env.PORT || 3001;
const GROQ_API_KEY = process.env.GROQ_API_KEY || "";

// ── Validate config on startup ────────────────────────────────
if (!GROQ_API_KEY || GROQ_API_KEY.includes("PASTE_YOUR")) {
  console.error("\n❌  GROQ_API_KEY is not set in .env — server cannot start.\n");
  process.exit(1);
}

// ── In-memory daily quota tracker (resets at midnight) ────────
// In production, swap for Redis. Fine for small/medium scale.
const dailyUsage = new Map(); // IP -> { count, date }
const DAILY_LIMIT = parseInt(process.env.DAILY_LIMIT_PER_IP) || 50;

function getDailyCount(ip) {
  const today = new Date().toDateString();
  const entry = dailyUsage.get(ip);
  if (!entry || entry.date !== today) {
    dailyUsage.set(ip, { count: 0, date: today });
    return 0;
  }
  return entry.count;
}

function incrementDailyCount(ip) {
  const today = new Date().toDateString();
  const entry = dailyUsage.get(ip) || { count: 0, date: today };
  entry.count += 1;
  entry.date = today;
  dailyUsage.set(ip, entry);
}

// Clean up old entries every hour
setInterval(() => {
  const today = new Date().toDateString();
  for (const [ip, data] of dailyUsage.entries()) {
    if (data.date !== today) dailyUsage.delete(ip);
  }
}, 60 * 60 * 1000);

// ── Middleware ────────────────────────────────────────────────

// Security headers
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS — allow Chrome extensions and local dev
app.use(cors({
  origin: (origin, cb) => {
    if (
      !origin ||
      origin.startsWith("chrome-extension://") ||
      origin.startsWith("moz-extension://") ||
      origin === "http://localhost:3001" ||
      origin === "http://localhost:3000"
    ) {
      cb(null, true);
    } else {
      cb(null, true); // Keep open for now; tighten after getting extension ID
    }
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-Extension-ID"]
}));

app.use(express.json({ limit: "20kb" })); // Prevent oversized payloads

// Global rate limiter — 60 requests/minute per IP
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please slow down.", code: "RATE_LIMITED" }
}));

// Analyze-specific rate limiter — 20 requests/15min per IP
const analyzeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Analyze rate limit reached. Wait a few minutes.", code: "ANALYZE_RATE_LIMITED" }
});

// ── Routes ────────────────────────────────────────────────────

// Health check
app.get("/", (req, res) => {
  res.json({
    service: "MailGuard AI API",
    version: "4.0.0",
    status: "running",
    message: "API key is configured and ready."
  });
});

// Ping (for extension to check connectivity)
app.get("/ping", (req, res) => {
  res.json({ ok: true, timestamp: Date.now() });
});

// ── Main analyze endpoint ──────────────────────────────────────
app.post("/analyze", analyzeLimiter, async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || "unknown";

  // Daily quota check
  const usedToday = getDailyCount(ip);
  if (usedToday >= DAILY_LIMIT) {
    return res.status(429).json({
      error: `Daily limit of ${DAILY_LIMIT} analyses reached. Resets at midnight.`,
      code: "DAILY_LIMIT_REACHED",
      resetsAt: "midnight"
    });
  }

  // Validate request body
  const { from, subject, body, categories } = req.body || {};
  if (!subject && !body) {
    return res.status(400).json({ error: "Email subject or body is required.", code: "MISSING_CONTENT" });
  }

  // Sanitize inputs
  const safeFrom       = String(from    || "unknown").substring(0, 200);
  const safeSubject    = String(subject || "").substring(0, 500);
  const safeBody       = String(body    || "").substring(0, 3000);
  const safeCategories = Array.isArray(categories)
    ? categories.map(c => String(c).substring(0, 50)).slice(0, 20)
    : [];

  try {
    const result = await analyzeWithGroq({ from: safeFrom, subject: safeSubject, body: safeBody, categories: safeCategories });

    // Increment quota only on success
    incrementDailyCount(ip);

    return res.json({
      success: true,
      result,
      quota: {
        used: usedToday + 1,
        limit: DAILY_LIMIT,
        remaining: DAILY_LIMIT - usedToday - 1
      }
    });
  } catch (err) {
    console.error(`[analyze] error for IP ${ip}:`, err.message);
    return res.status(500).json({
      error: err.message || "Analysis failed. Please try again.",
      code: "ANALYSIS_FAILED"
    });
  }
});

// ── Groq API call ─────────────────────────────────────────────
async function analyzeWithGroq({ from, subject, body, categories }) {
  const prompt = `You are MailGuard AI, an expert email security assistant.
Analyze the email below and return ONLY a valid JSON object — no markdown, no code fences, no explanation.

EMAIL:
From: ${from}
Subject: ${subject}
Body: ${body}

User's priority categories: ${categories.length ? categories.join(", ") : "none set"}

Return exactly this JSON structure:
{
  "safety": {
    "level": "safe",
    "score": 10,
    "explanation": "Why this email is safe/cautious/risky in 1-2 sentences",
    "redFlags": [],
    "whatToDo": "Clear, specific action the user should take"
  },
  "priority": {
    "isImportant": false,
    "matchedCategory": null,
    "reason": "Why this does or doesn't match a priority category"
  },
  "summary": "One sentence summary of what this email is about"
}

RULES:
- level must be exactly one of: safe, cautious, risky
- score: 0 = completely safe, 100 = dangerous phishing/scam
- redFlags: array of specific warning signs (empty array [] if none found)
- isImportant: true ONLY if email clearly matches one of the user's priority categories
- matchedCategory: the exact category name it matched, or null`;

  const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${GROQ_API_KEY}`
    },
    body: JSON.stringify({
      model: "llama-3.3-70b-versatile",
      messages: [
        { role: "system", content: "You are an email security AI. Always respond with raw JSON only. Never use markdown." },
        { role: "user", content: prompt }
      ],
      temperature: 0.1,
      max_tokens: 700,
      response_format: { type: "json_object" }
    })
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData?.error?.message || `Groq API error (${response.status})`);
  }

  const data = await response.json();
  const raw = data?.choices?.[0]?.message?.content || "";

  if (!raw) throw new Error("Empty response from Groq.");

  // Strip accidental markdown fences
  const clean = raw.replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```\s*$/i, "").trim();

  let result;
  try {
    result = JSON.parse(clean);
  } catch {
    throw new Error("Could not parse AI response. Please try again.");
  }

  // Validate shape
  if (!result.safety || !result.priority || !result.summary) {
    throw new Error("Unexpected AI response format. Please try again.");
  }

  return result;
}

// ── 404 handler ───────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Not found", code: "NOT_FOUND" });
});

// ── Global error handler ──────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    error: "Internal server error",
    code: "SERVER_ERROR"
  });
});

// Export for Vercel
module.exports = app;
