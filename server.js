const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const { createClient } = require("@supabase/supabase-js");
const app = express();
const PORT = process.env.PORT || 3000;
const IS_VERCEL = Boolean(process.env.VERCEL);

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
const sessions = new Map();
let announcementsCache = null;
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const supabase =
  SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    : null;

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
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
    return true;
  } catch (err) {
    console.warn(`writeJson failed for ${filePath}: ${err.message}`);
    return false;
  }
}

function ensureUploadDir() {
  try {
    if (!fs.existsSync(UPLOAD_DIR)) {
      fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    }
  } catch (err) {
    console.warn(`ensureUploadDir failed: ${err.message}`);
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
  try {
    fs.writeFileSync(filePath, buffer);
    return `/uploads/${filename}`;
  } catch (err) {
    console.warn(`saveImageFromDataUrl failed: ${err.message}`);
    return "";
  }
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
  try {
    fs.writeFileSync(filePath, buffer);
    return `/uploads/${filename}`;
  } catch (err) {
    console.warn(`saveVideoFromDataUrl failed: ${err.message}`);
    return "";
  }
}

async function uploadToSupabase(dataUrl, kind) {
  if (!supabase || !dataUrl) return "";
  const isImage = kind === "image";
  const match = String(dataUrl).match(
    isImage
      ? /^data:(image\/png|image\/jpeg|image\/webp);base64,(.+)$/
      : /^data:(video\/mp4|video\/webm);base64,(.+)$/
  );
  if (!match) return "";

  const mime = match[1];
  const base64 = match[2];
  const buffer = Buffer.from(base64, "base64");
  if (!buffer.length) return "";
  if (isImage && buffer.length > LIMITS.imageBytes) return "";
  if (!isImage && buffer.length > LIMITS.videoBytes) return "";

  const ext = isImage
    ? mime === "image/png"
      ? "png"
      : mime === "image/webp"
      ? "webp"
      : "jpg"
    : mime === "video/webm"
    ? "webm"
    : "mp4";
  const filename = `${cryptoRandomId()}.${ext}`;
  const pathKey = `uploads/${filename}`;

  const { error } = await supabase.storage.from("uploads").upload(pathKey, buffer, {
    contentType: mime,
    upsert: false
  });
  if (error) {
    console.warn(`Supabase upload failed: ${error.message}`);
    return "";
  }

  const { data } = supabase.storage.from("uploads").getPublicUrl(pathKey);
  return data && data.publicUrl ? data.publicUrl : "";
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

function normalizeUser(raw) {
  if (!raw) return null;
  return {
    username: raw.username,
    club: raw.club || "",
    passwordHash: raw.passwordHash || raw.password_hash || "",
    passwordSalt: raw.passwordSalt || raw.password_salt || ""
  };
}

async function getUserByUsername(username) {
  if (!supabase) {
    const users = readJson(USERS_PATH, []);
    const user = users.find((u) => u.username === username);
    return normalizeUser(user);
  }

  const { data, error } = await supabase
    .from("users")
    .select("username, club, password_salt, password_hash")
    .eq("username", username)
    .maybeSingle();
  if (error || !data) return null;
  return normalizeUser(data);
}

async function upsertUserFromLocal(localUser) {
  if (!supabase || !localUser) return null;
  const normalized = normalizeUser(localUser);
  if (!normalized || !normalized.passwordHash || !normalized.passwordSalt) return null;
  const { error } = await supabase.from("users").upsert({
    username: normalized.username,
    club: normalized.club || "",
    password_salt: normalized.passwordSalt,
    password_hash: normalized.passwordHash
  });
  if (error) return null;
  return normalized;
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

function clearLoginAttempts(ip) {
  if (!ip) return;
  loginAttempts.delete(ip);
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

async function getSession(token) {
  if (!token) return null;
  if (!supabase) {
    const session = sessions.get(token);
    if (!session) return null;
    if (session.expiresAt && Date.now() > Number(session.expiresAt)) {
      sessions.delete(token);
      return null;
    }
    return session;
  }

  const { data, error } = await supabase
    .from("sessions")
    .select("token, username, club, expires_at")
    .eq("token", token)
    .maybeSingle();
  if (error || !data) return null;
  if (data.expires_at && Date.now() > new Date(data.expires_at).getTime()) {
    await supabase.from("sessions").delete().eq("token", token);
    return null;
  }
  return {
    token: data.token,
    user: { username: data.username, club: data.club || "" },
    expiresAt: data.expires_at ? new Date(data.expires_at).getTime() : 0
  };
}

async function saveSession(token, user) {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  if (!supabase) {
    sessions.set(token, { user, expiresAt });
    return true;
  }
  const { error } = await supabase.from("sessions").upsert({
    token,
    username: user.username,
    club: user.club || "",
    expires_at: new Date(expiresAt).toISOString()
  });
  return !error;
}

async function deleteSession(token) {
  if (!token) return;
  if (!supabase) {
    sessions.delete(token);
    return;
  }
  await supabase.from("sessions").delete().eq("token", token);
}

async function getAnnouncements() {
  if (!supabase) {
    if (!announcementsCache) {
      announcementsCache = readJson(ANN_PATH, []);
    }
    return announcementsCache;
  }
  const { data, error } = await supabase
    .from("announcements")
    .select("*")
    .order("created_at", { ascending: false });
  if (error || !data) return [];
  return data.map((item) => ({
    id: item.id,
    title: item.title,
    club: item.club,
    body: item.body,
    tags: Array.isArray(item.tags) ? item.tags : [],
    imageUrl: item.image_url || "",
    videoUrl: item.video_url || "",
    eventDate: item.event_date || "",
    createdAt: item.created_at,
    createdBy: item.created_by || ""
  }));
}

async function insertAnnouncement(item) {
  if (!supabase) {
    const list = announcementsCache ? announcementsCache : readJson(ANN_PATH, []);
    announcementsCache = list;
    list.push(item);
    writeJson(ANN_PATH, list);
    return item;
  }
  const payload = {
    id: item.id,
    title: item.title,
    club: item.club,
    body: item.body,
    tags: item.tags,
    image_url: item.imageUrl || "",
    video_url: item.videoUrl || "",
    event_date: item.eventDate || null,
    created_at: item.createdAt,
    created_by: item.createdBy || ""
  };
  const { error } = await supabase.from("announcements").insert(payload);
  return error ? null : item;
}

async function deleteAnnouncement(id, club) {
  if (!supabase) {
    const list = announcementsCache ? announcementsCache : readJson(ANN_PATH, []);
    announcementsCache = list;
    const item = list.find((x) => x.id === id);
    if (!item) return { ok: false, code: 404 };
    if (String(item.club) !== String(club)) return { ok: false, code: 403 };
    const nextList = list.filter((x) => x.id !== id);
    announcementsCache = nextList;
    writeJson(ANN_PATH, nextList);
    return { ok: true };
  }

  const { data: item, error: findErr } = await supabase
    .from("announcements")
    .select("id, club")
    .eq("id", id)
    .maybeSingle();
  if (findErr || !item) return { ok: false, code: 404 };
  if (String(item.club) !== String(club)) return { ok: false, code: 403 };
  await supabase.from("announcements").delete().eq("id", id);
  return { ok: true };
}

async function requireAuth(req, res, next) {
  const token = req.cookies.auth;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: "Unauthorized" });

  req.user = session.user;
  next();
}

// Serve public static
app.use(securityHeaders);
app.use(csrfProtection);
app.use("/", express.static(path.join(__dirname, "public")));

ensureUploadDir();

// --- API ---
// Public: list announcements
app.get("/api/announcements", async (req, res) => {
  const list = await getAnnouncements();
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
app.post("/api/announcements", requireAuth, async (req, res) => {
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

  const imageUrl = supabase
    ? await uploadToSupabase(imageData, "image")
    : saveImageFromDataUrl(imageData);
  const videoUrl = supabase
    ? await uploadToSupabase(videoData, "video")
    : saveVideoFromDataUrl(videoData);
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

  const saved = await insertAnnouncement(item);
  if (!saved) return res.status(500).json({ error: "Could not save" });
  res.status(201).json(item);
});

// Club representative: delete own club announcements
app.delete("/api/announcements/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const result = await deleteAnnouncement(id, req.user.club);
  if (!result.ok) {
    if (result.code === 404) return res.status(404).json({ error: "Not found" });
    if (result.code === 403) return res.status(403).json({ error: "Forbidden" });
    return res.status(500).json({ error: "Could not delete" });
  }
  res.json({ ok: true });
});

// Auth
app.post("/api/login", async (req, res) => {
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
  let user = null;
  if (!supabase) {
    const users = readJson(USERS_PATH, []);
    const localUser = users.find((u) => u.username === username);
    if (!localUser) return res.status(401).json({ error: "Wrong credentials" });

    const migrated = ensurePasswordHash(localUser);
    const normalized = normalizeUser(localUser);
    const ok = normalized.passwordHash
      ? verifyPassword(password, normalized)
      : localUser.password === password;
    if (!ok) {
      if (migrated) writeJson(USERS_PATH, users);
      return res.status(401).json({ error: "Wrong credentials" });
    }
    if (migrated) writeJson(USERS_PATH, users);
    user = normalized;
  } else {
    user = await getUserByUsername(username);
    const users = readJson(USERS_PATH, []);
    const localUser = users.find((u) => u.username === username);

    if (!user && localUser) {
      const migrated = ensurePasswordHash(localUser);
      const normalized = normalizeUser(localUser);
      const ok = normalized.passwordHash
        ? verifyPassword(password, normalized)
        : localUser.password === password;
      if (!ok) {
        if (migrated) writeJson(USERS_PATH, users);
        return res.status(401).json({ error: "Wrong credentials" });
      }
      if (migrated) writeJson(USERS_PATH, users);
      user = await upsertUserFromLocal(localUser);
    }

    if (user && (!user.passwordHash || !user.passwordSalt) && localUser) {
      const migrated = ensurePasswordHash(localUser);
      const normalized = normalizeUser(localUser);
      const ok = normalized.passwordHash
        ? verifyPassword(password, normalized)
        : localUser.password === password;
      if (!ok) {
        if (migrated) writeJson(USERS_PATH, users);
        return res.status(401).json({ error: "Wrong credentials" });
      }
      if (migrated) writeJson(USERS_PATH, users);
      user = await upsertUserFromLocal(localUser);
    }

    if (!user) return res.status(401).json({ error: "Wrong credentials" });
    const ok = verifyPassword(password, user);
    if (!ok) return res.status(401).json({ error: "Wrong credentials" });
  }

  const token = cryptoRandomId() + cryptoRandomId();
  const sessionSaved = await saveSession(token, {
    username: user.username,
    club: user.club || ""
  });
  if (!sessionSaved) {
    return res.status(500).json({ error: "Could not create session" });
  }

  clearLoginAttempts(req.ip);
  res.cookie("auth", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  });

  res.json({ ok: true, username: user.username, club: user.club || "" });
});

app.post("/api/logout", async (req, res) => {
  const token = req.cookies.auth;
  if (token) await deleteSession(token);
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

if (!IS_VERCEL && require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running: http://localhost:${PORT}`);
    console.log(`Public: http://localhost:${PORT}/`);
  });
}

// Tiny id helper (no extra dependency)
function cryptoRandomId() {
  if (crypto.randomUUID) return crypto.randomUUID().replaceAll("-", "");
  return crypto.randomBytes(16).toString("hex");
}

module.exports = app;
