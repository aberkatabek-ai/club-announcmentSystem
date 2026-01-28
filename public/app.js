const listEl = document.getElementById("list");
const emptyEl = document.getElementById("empty");
const qEl = document.getElementById("q");
const clubFilterEl = document.getElementById("club");

const titleEl = document.getElementById("title");
const clubBoxEl = document.getElementById("clubBox");
const clubDisplayEl = document.getElementById("clubDisplay");
const tagsEl = document.getElementById("tags");
const eventDateEl = document.getElementById("eventDate");
const bodyEl = document.getElementById("body");
const mediaEl = document.getElementById("media");
const mediaBtnEl = document.getElementById("mediaBtn");
const mediaNameEl = document.getElementById("mediaName");
const shareBtn = document.getElementById("share");
const newAnnouncementEl = document.getElementById("newAnnouncement");

const loginFormEl = document.getElementById("loginForm");
const loginInfoEl = document.getElementById("loginInfo");
const whoamiEl = document.getElementById("whoami");
const loginUserEl = document.getElementById("loginUser");
const loginPassEl = document.getElementById("loginPass");
const loginBtnEl = document.getElementById("loginBtn");
const authTabLogin = document.getElementById("authTabLogin");
const authTabLogout = document.getElementById("authTabLogout");
const authToggleBtn = document.getElementById("authToggle");
const authModalEl = document.getElementById("authModal");
const authCloseBtn = document.getElementById("authClose");

const LIMITS = {
  title: 80,
  body: 1000,
  tags: 200,
  imageBytes: 2 * 1024 * 1024,
  videoBytes: 10 * 1024 * 1024
};

let all = [];
let currentUser = null;
let csrfToken = "";

function showLoginForm() {
  loginFormEl.classList.remove("hidden");
  loginInfoEl.classList.add("hidden");
  if (authTabLogin) authTabLogin.classList.add("active");
  if (authTabLogout) authTabLogout.classList.remove("active");
}

function showLoginInfo() {
  loginFormEl.classList.add("hidden");
  loginInfoEl.classList.remove("hidden");
  if (authTabLogin) authTabLogin.classList.remove("active");
  if (authTabLogout) authTabLogout.classList.add("active");
}

function setAuth(user) {
  currentUser = user;
  shareBtn.disabled = !user;
  if (newAnnouncementEl) {
    newAnnouncementEl.classList.toggle("hidden", !user);
  }

  if (user) {
    whoamiEl.textContent = `Logged in: ${user.username} (${user.club})`;
    clubDisplayEl.textContent = user.club || "Club not set";
    if (clubBoxEl) {
      clubBoxEl.classList.toggle("hidden", !user.club);
    }
    authToggleBtn.textContent = "My Account";
    showLoginInfo();
  } else {
    whoamiEl.textContent = "";
    clubDisplayEl.textContent = "";
    if (clubBoxEl) clubBoxEl.classList.add("hidden");
    authToggleBtn.textContent = "Representative Login";
    showLoginForm();
  }

  render();
}

function openAuthModal() {
  authModalEl.classList.remove("hidden");
}

function closeAuthModal() {
  authModalEl.classList.add("hidden");
}

authToggleBtn.addEventListener("click", openAuthModal);
authCloseBtn.addEventListener("click", closeAuthModal);
authModalEl.addEventListener("click", (e) => {
  if (e.target === authModalEl) closeAuthModal();
});

async function doLogin() {
  const username = loginUserEl.value.trim();
  const password = loginPassEl.value.trim();
  if (!username || !password) {
    alert("Username and password are required.");
    return;
  }

  try {
    await ensureCsrf();
    const res = await fetch("/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {})
      },
      body: JSON.stringify({ username, password })
    });

    if (!res.ok) {
      alert("Login failed.");
      return;
    }

    const user = await res.json();
    setAuth({ username: user.username, club: user.club });
    loginUserEl.value = "";
    loginPassEl.value = "";
    closeAuthModal();
  } catch (err) {
    alert("Could not reach server. Is it running? (npm run dev)");
  }
}

function handleLoginEnter(e) {
  if (e.key !== "Enter") return;
  e.preventDefault();
  doLogin();
}

loginUserEl.addEventListener("keydown", handleLoginEnter);
loginPassEl.addEventListener("keydown", handleLoginEnter);
if (loginBtnEl) loginBtnEl.addEventListener("click", doLogin);

async function doLogout() {
  await ensureCsrf();
  await fetch("/api/logout", {
    method: "POST",
    headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {}
  });
  setAuth(null);
  closeAuthModal();
}

if (authTabLogin) {
  authTabLogin.addEventListener("click", async () => {
    if (currentUser) {
      showLoginInfo();
      return;
    }
    showLoginForm();
  });
}

if (authTabLogout) {
  authTabLogout.addEventListener("click", async () => {
    if (!currentUser) {
      showLoginForm();
      alert("You are not logged in.");
      return;
    }
    showLoginInfo();
    await doLogout();
  });
}

if (eventDateEl && typeof eventDateEl.showPicker === "function") {
  eventDateEl.addEventListener("click", () => eventDateEl.showPicker());
}

if (mediaBtnEl && mediaEl) {
  mediaBtnEl.addEventListener("click", () => mediaEl.click());
}

if (mediaEl && mediaNameEl) {
  mediaEl.addEventListener("change", () => {
    const name = mediaEl.files && mediaEl.files[0] ? mediaEl.files[0].name : "No file chosen";
    mediaNameEl.textContent = name;
  });
}

shareBtn.addEventListener("click", async () => {
  const title = titleEl.value.trim();
  const body = bodyEl.value.trim();
  const tags = tagsEl.value
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
  const eventDate = eventDateEl ? eventDateEl.value : "";

  if (!title || !body) {
    alert("Title and body are required.");
    return;
  }
  if (title.length > LIMITS.title) {
    alert(`Title must be at most ${LIMITS.title} characters.`);
    return;
  }
  if (body.length > LIMITS.body) {
    alert(`Body must be at most ${LIMITS.body} characters.`);
    return;
  }
  if (tagsEl.value.length > LIMITS.tags) {
    alert(`Tags must be at most ${LIMITS.tags} characters.`);
    return;
  }

  try {
    const { imageData, videoData } = await readMediaData();
    await ensureCsrf();
    const res = await fetch("/api/announcements", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {})
      },
      body: JSON.stringify({ title, body, tags, imageData, videoData, eventDate }),
    });

    if (!res.ok) {
      if (res.status === 401) {
        alert("Please log in first.");
        setAuth(null);
        return;
      }
      const msg = await safeText(res);
      alert("Could not save: " + msg);
      return;
    }

    titleEl.value = "";
    tagsEl.value = "";
    if (eventDateEl) eventDateEl.value = "";
    bodyEl.value = "";
    if (mediaEl) mediaEl.value = "";
    if (mediaNameEl) mediaNameEl.textContent = "No file chosen";

    await load();
  } catch (err) {
    alert("Could not reach server. Is it running? (npm run dev)");
  }
});

async function load() {
  const res = await fetch("/api/announcements");
  all = await res.json();

  const clubs = [...new Set(all.map((x) => x.club))].sort((a, b) =>
    a.localeCompare(b, "en")
  );

  clubFilterEl.innerHTML =
    `<option value="">All clubs</option>` +
    clubs
      .map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`)
      .join("");

  render();
}

function render() {
  const q = (qEl.value || "").toLowerCase().trim();
  const club = clubFilterEl.value;

  const filtered = all.filter((x) => {
    const hay = `${x.title} ${x.club} ${x.body} ${(x.tags || []).join(" ")}`
      .toLowerCase();
    const okQ = !q || hay.includes(q);
    const okClub = !club || x.club === club;
    return okQ && okClub;
  });

  listEl.innerHTML = filtered.map(cardHtml).join("");
  emptyEl.classList.toggle("hidden", filtered.length !== 0);

  if (currentUser) {
    document.querySelectorAll("[data-del]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-del");
        if (!confirm("Delete this announcement?")) return;

        await ensureCsrf();
        const r = await fetch(`/api/announcements/${encodeURIComponent(id)}`, {
          method: "DELETE",
          headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {}
        });

        if (!r.ok) {
          if (r.status === 401) {
            alert("Please log in first.");
            setAuth(null);
            return;
          }
          if (r.status === 403) {
            alert("You can only delete your own club's announcements.");
            return;
          }
          const msg = await safeText(r);
          alert("Could not delete: " + msg);
          return;
        }

        await load();
      });
    });
  }
}

function cardHtml(x) {
  const date = new Date(x.createdAt);
  const dateStr = isNaN(date) ? String(x.createdAt) : date.toLocaleString("en-US");
  const event = x.eventDate ? new Date(x.eventDate) : null;
  const eventStr = event && !isNaN(event) ? event.toLocaleString("en-US") : "";
  const countdownStr = event && !isNaN(event) ? formatCountdown(event) : "";

  const tagsHtml = (x.tags || [])
    .map((t) => `<span class="tag">#${escapeHtml(t)}</span>`)
    .join("");

  const imageHtml = x.imageUrl
    ? `<div class="media"><img src="${escapeHtml(x.imageUrl)}" alt="" loading="lazy" /></div>`
    : "";
  const videoHtml = x.videoUrl
    ? `<div class="media"><video controls preload="metadata" src="${escapeHtml(x.videoUrl)}"></video></div>`
    : "";

  const canDelete = currentUser && currentUser.club === x.club;
  const deleteBtn = canDelete
    ? `<button class="btn danger" data-del="${escapeHtml(x.id)}">Delete</button>`
    : "";

  const eventHtml = eventStr
    ? `<div class="event">
        <span>Event: ${escapeHtml(eventStr)}</span>
        ${countdownStr ? `<span class="countdown" data-event-ts="${escapeHtml(event.toISOString())}">${escapeHtml(countdownStr)}</span>` : ""}
      </div>`
    : "";

  return `
    <article class="card">
      <div class="row">
        <h3>${escapeHtml(x.title)}</h3>
        ${deleteBtn}
      </div>
      <div class="meta">
        <span>Club: ${escapeHtml(x.club)}</span>
        <span>Date: ${escapeHtml(dateStr)}</span>
      </div>
      ${eventHtml}
      <div>${linkifyText(x.body)}</div>
      ${imageHtml}
      ${videoHtml}
      <div class="tags">${tagsHtml}</div>
    </article>
  `;
}

qEl.addEventListener("input", render);
clubFilterEl.addEventListener("change", render);

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function linkifyText(text) {
  const raw = String(text || "");
  const regex = /((https?:\/\/|www\.)[^\s]+)/g;
  let last = 0;
  let out = "";
  for (const match of raw.matchAll(regex)) {
    const url = match[0];
    const index = match.index ?? 0;
    out += escapeHtml(raw.slice(last, index));
    const trimmed = url.replace(/[)\].,!?]+$/g, "");
    const suffix = url.slice(trimmed.length);
    const href = trimmed.startsWith("http") ? trimmed : `https://${trimmed}`;
    const safeHref = escapeHtml(href);
    const safeText = escapeHtml(trimmed);
    out += `<a href="${safeHref}" target="_blank" rel="noopener noreferrer">${safeText}</a>`;
    out += escapeHtml(suffix);
    last = index + url.length;
  }
  out += escapeHtml(raw.slice(last));
  return out.replaceAll("\n", "<br/>");
}

function formatCountdown(targetDate) {
  const diff = targetDate.getTime() - Date.now();
  if (diff <= 0) return "Started";
  const totalSeconds = Math.floor(diff / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

function updateCountdowns() {
  document.querySelectorAll("[data-event-ts]").forEach((el) => {
    const iso = el.getAttribute("data-event-ts");
    if (!iso) return;
    const date = new Date(iso);
    if (isNaN(date)) return;
    el.textContent = formatCountdown(date);
  });
}

async function safeText(res) {
  try {
    return await res.text();
  } catch {
    return "Unknown error";
  }
}

async function initCsrf() {
  try {
    const res = await fetch("/api/csrf");
    if (!res.ok) return;
    const data = await res.json();
    csrfToken = data.token || "";
  } catch {
    csrfToken = "";
  }
}

async function ensureCsrf() {
  if (csrfToken) return;
  await initCsrf();
}

async function readMediaData() {
  if (!mediaEl || !mediaEl.files || mediaEl.files.length === 0) {
    return { imageData: "", videoData: "" };
  }
  const file = mediaEl.files[0];
  const isImage = ["image/png", "image/jpeg", "image/webp"].includes(file.type);
  const isVideo = ["video/mp4", "video/webm"].includes(file.type);
  if (!isImage && !isVideo) {
    alert("Only jpg, png, webp, mp4, or webm files are allowed.");
    return { imageData: "", videoData: "" };
  }
  if (isImage && file.size > LIMITS.imageBytes) {
    alert(`Image must be at most ${Math.floor(LIMITS.imageBytes / 1024 / 1024)}MB.`);
    return { imageData: "", videoData: "" };
  }
  if (isVideo && file.size > LIMITS.videoBytes) {
    alert(`Video must be at most ${Math.floor(LIMITS.videoBytes / 1024 / 1024)}MB.`);
    return { imageData: "", videoData: "" };
  }
  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(new Error("read failed"));
    reader.readAsDataURL(file);
  });
  return {
    imageData: isImage ? dataUrl : "",
    videoData: isVideo ? dataUrl : ""
  };
}

// Start
load().catch(() => {
  listEl.innerHTML =
    `<div class="card">Could not load announcements. Is the server running? (npm run dev)</div>`;
});

initCsrf();
updateCountdowns();

// Refresh countdowns every minute without re-rendering.
setInterval(updateCountdowns, 60000);

// Check session
fetch("/api/me")
  .then((res) => (res.ok ? res.json() : null))
  .then((me) => setAuth(me))
  .catch(() => setAuth(null));
