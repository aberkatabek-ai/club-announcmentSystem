const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "12mb" }));
app.use(cookieParser());

// Paths
const DATA_DIR = path.join(__dirname, "data");
const ANN_PATH = path.join(DATA_DIR, "announcements.json");
const USERS_PATH = path.join(DATA_DIR, "users.json");
const UPLOAD_DIR = path.join(__dirname, "public", "uploads");
const LIMITS = {
  title: 80,
  body: 1000,
  tags: 200,
  username: 50,
  password: 200,
  imageBytes: 2 * 1024 * 1024,
  videoBytes: 10 * 1024 * 1024,
  eventDate: 40
};
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const LOGIN_WINDOW_MS = 1000 * 60 * 10; // 10 minutes
const LOGIN_MAX_ATTEMPTS = 8;
const loginAttempts = new Map();
const CSRF_COOKIE = "csrf";

// Helpers
function readJson(filePath, fallback) {
  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}
function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}

function ensureUploadDir() {
  if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  }
}

function saveImageFromDataUrl(dataUrl) {
  if (!dataUrl) return "";
  const match = String(dataUrl).match(/^data:(image\/png|image\/jpeg|image\/webp);base64,(.+)$/);
  if (!match) return "";

  const mime = match[1];
  const base64 = match[2];
  const buffer = Buffer.from(base64, "base64");
  if (!buffer.length || buffer.length > LIMITS.imageBytes) return "";

  const ext = mime === "image/png" ? "png" : mime === "image/webp" ? "webp" : "jpg";
  const filename = `${cryptoRandomId()}.${ext}`;
  const filePath = path.join(UPLOAD_DIR, filename);
  fs.writeFileSync(filePath, buffer);
  return `/uploads/${filename}`;
}

function saveVideoFromDataUrl(dataUrl) {
  if (!dataUrl) return "";
  const match = String(dataUrl).match(/^data:(video\/mp4|video\/webm);base64,(.+)$/);
  if (!match) return "";

  const mime = match[1];
  const base64 = match[2];
  const buffer = Buffer.from(base64, "base64");
  if (!buffer.length || buffer.length > LIMITS.videoBytes) return "";

  const ext = mime === "video/webm" ? "webm" : "mp4";
  const filename = `${cryptoRandomId()}.${ext}`;
  const filePath = path.join(UPLOAD_DIR, filename);
  fs.writeFileSync(filePath, buffer);
  return `/uploads/${filename}`;
}

function securityHeaders(req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'"
  );
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  next();
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 120000, 64, "sha512").toString("hex");
}

function verifyPassword(password, user) {
  if (!user.passwordHash || !user.passwordSalt) return false;
  const candidate = hashPassword(password, user.passwordSalt);
  return crypto.timingSafeEqual(Buffer.from(candidate, "hex"), Buffer.from(user.passwordHash, "hex"));
}

function ensurePasswordHash(user) {
  if (user.passwordHash && user.passwordSalt) return false;
  if (!user.password) return false;
  const salt = crypto.randomBytes(16).toString("hex");
  user.passwordSalt = salt;
  user.passwordHash = hashPassword(user.password, salt);
  delete user.password;
  return true;
}

function isLoginRateLimited(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > LOGIN_MAX_ATTEMPTS;
}

function csrfProtection(req, res, next) {
  const isApi = req.path.startsWith("/api/");
  const isSafe = req.method === "GET" || req.method === "HEAD";
  if (!isApi || isSafe || req.path === "/api/csrf") return next();

  const cookieToken = req.cookies[CSRF_COOKIE];
  const headerToken = req.get("X-CSRF-Token");
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: "CSRF validation failed" });
  }
  next();
}

function requireAuth(req, res, next) {
  const token = req.cookies.auth;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const users = readJson(USERS_PATH, []);
  const user = users.find((u) => u.token === token);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  if (user.tokenExpiresAt && Date.now() > Number(user.tokenExpiresAt)) {
    user.token = "";
    user.tokenExpiresAt = 0;
    writeJson(USERS_PATH, users);
    return res.status(401).json({ error: "Session expired" });
  }

  req.user = user;
  next();
}

// Serve public static
app.use(securityHeaders);
app.use(csrfProtection);
app.use("/", express.static(path.join(__dirname, "public")));

ensureUploadDir();

// --- API ---
// Public: list announcements
app.get("/api/announcements", (req, res) => {
  const list = readJson(ANN_PATH, []);
  list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

// CSRF token
app.get("/api/csrf", (req, res) => {
  const token = crypto.randomBytes(24).toString("hex");
  res.cookie(CSRF_COOKIE, token, {
    httpOnly: false,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  });
  res.json({ token });
});

// Club representative: add announcement
app.post("/api/announcements", requireAuth, (req, res) => {
  const { title, body, tags = [], imageData, videoData, eventDate } = req.body;

  if (!title || !body) {
    return res.status(400).json({ error: "title, body required" });
  }

  if (!req.user.club) {
    return res.status(400).json({ error: "user club missing" });
  }

  if (String(title).length > LIMITS.title) {
    return res.status(400).json({ error: "title too long" });
  }
  if (String(body).length > LIMITS.body) {
    return res.status(400).json({ error: "body too long" });
  }
  if (Array.isArray(tags) && tags.join(",").length > LIMITS.tags) {
    return res.status(400).json({ error: "tags too long" });
  }
  if (eventDate && String(eventDate).length > LIMITS.eventDate) {
    return res.status(400).json({ error: "event date too long" });
  }

  const imageUrl = saveImageFromDataUrl(imageData);
  const videoUrl = saveVideoFromDataUrl(videoData);
  if (imageData && !imageUrl) {
    return res.status(400).json({ error: "invalid image" });
  }
  if (videoData && !videoUrl) {
    return res.status(400).json({ error: "invalid video" });
  }

  const parsedEventDate = eventDate ? new Date(String(eventDate)) : null;
  if (eventDate && isNaN(parsedEventDate)) {
    return res.status(400).json({ error: "invalid event date" });
  }

  const list = readJson(ANN_PATH, []);
  const item = {
    id: cryptoRandomId(),
    title: String(title).trim(),
    club: String(req.user.club).trim(),
    body: String(body).trim(),
    tags: Array.isArray(tags) ? tags.map(String) : [],
    imageUrl,
    videoUrl,
    eventDate: parsedEventDate ? parsedEventDate.toISOString() : "",
    createdAt: new Date().toISOString(),
    createdBy: req.user.username
  };

  list.push(item);
  writeJson(ANN_PATH, list);
  res.status(201).json(item);
});

// Club representative: delete own club announcements
app.delete("/api/announcements/:id", requireAuth, (req, res) => {
  const { id } = req.params;
  const list = readJson(ANN_PATH, []);
  const item = list.find((x) => x.id === id);
  if (!item) return res.status(404).json({ error: "Not found" });

  if (String(item.club) !== String(req.user.club)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const nextList = list.filter((x) => x.id !== id);
  writeJson(ANN_PATH, nextList);
  res.json({ ok: true });
});

// Auth
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (isLoginRateLimited(req.ip)) {
    return res.status(429).json({ error: "Too many attempts. Try later." });
  }
  if (
    !username ||
    !password ||
    String(username).length > LIMITS.username ||
    String(password).length > LIMITS.password
  ) {
    return res.status(400).json({ error: "Invalid credentials" });
  }
  const users = readJson(USERS_PATH, []);

  const user = users.find((u) => u.username === username);
  if (!user) return res.status(401).json({ error: "Wrong credentials" });

  const migrated = ensurePasswordHash(user);
  const ok = user.passwordHash ? verifyPassword(password, user) : user.password === password;
  if (!ok) {
    if (migrated) writeJson(USERS_PATH, users);
    return res.status(401).json({ error: "Wrong credentials" });
  }

  const token = cryptoRandomId() + cryptoRandomId();
  user.token = token;
  user.tokenExpiresAt = Date.now() + SESSION_TTL_MS;
  writeJson(USERS_PATH, users);

  res.cookie("auth", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  });

  res.json({ ok: true, username: user.username, club: user.club || "" });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.auth;
  if (token) {
    const users = readJson(USERS_PATH, []);
    const u = users.find((x) => x.token === token);
    if (u) {
      u.token = "";
      u.tokenExpiresAt = 0;
      writeJson(USERS_PATH, users);
    }
  }
  res.clearCookie("auth");
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ username: req.user.username, club: req.user.club || "" });
});

// Fallback: go home
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running: http://localhost:${PORT}`);
  console.log(`Public: http://localhost:${PORT}/`);
});

// Tiny id helper (no extra dependency)
function cryptoRandomId() {
  if (crypto.randomUUID) return crypto.randomUUID().replaceAll("-", "");
  return crypto.randomBytes(16).toString("hex");
}
