"use strict";

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */
const $ = (sel) => document.querySelector(sel);
const COLORS = {
  bot: "#ff5b5b", human: "#58c6ff", unknown: "#6f6f73",
  breach: "#f2a93b", accent: "#f2a93b", accent2: "#f2a93b",
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}
function fmtTime(ts) {
  const d = new Date((ts || Date.now() / 1000) * 1000);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}
function classOf(c) { return c === "bot" || c === "human" ? c : "unknown"; }

/* ------------------------------------------------------------------ */
/* map                                                                */
/* ------------------------------------------------------------------ */
const map = L.map("map", {
  center: [25, 12], zoom: 2, minZoom: 2, maxZoom: 7,
  worldCopyJump: true, zoomControl: true, attributionControl: false,
});
L.tileLayer(
  "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
  { subdomains: "abcd", maxZoom: 19 }
).addTo(map);

const markers = new Map();   // session_id -> leaflet marker

function markerIcon(cls, fresh) {
  return L.divIcon({
    className: "",
    html: `<div class="ping ${classOf(cls)} ${fresh ? "fresh" : ""}"></div>`,
    iconSize: [12, 12],
  });
}

function upsertMarker(s, fresh) {
  if (s.lat == null || s.lon == null) return;
  let m = markers.get(s.session_id);
  if (m) {
    m.setIcon(markerIcon(s.classification, fresh));
  } else {
    m = L.marker([s.lat, s.lon], { icon: markerIcon(s.classification, fresh) }).addTo(map);
    m.bindPopup(
      `<b>${esc(s.ip)}</b><br>${esc(s.city || "")}${s.city ? ", " : ""}${esc(s.country || "")}` +
      `<br>${esc(s.protocol)} &middot; <b>${esc(s.classification)}</b>`
    );
    m.on("click", () => openDrawer(s.session_id));
    markers.set(s.session_id, m);
  }
  if (fresh) {
    setTimeout(() => {
      const cur = markers.get(s.session_id);
      if (cur) cur.setIcon(markerIcon(s.classification, false));
    }, 2600);
  }
  $("#mapCount").textContent = `${markers.size} origins`;
}

/* ------------------------------------------------------------------ */
/* charts                                                             */
/* ------------------------------------------------------------------ */
Chart.defaults.color = "#74747a";
Chart.defaults.font.family = "JetBrains Mono, monospace";
Chart.defaults.borderColor = "#222227";

const timeChart = new Chart($("#timeChart"), {
  type: "line",
  data: { labels: [], datasets: [{
    label: "attempts", data: [],
    borderColor: COLORS.accent, backgroundColor: "rgba(242,169,59,0.14)",
    fill: true, tension: 0.32, pointRadius: 0, borderWidth: 2,
  }] },
  options: {
    animation: false, plugins: { legend: { display: false } },
    scales: { x: { display: false }, y: { beginAtZero: true, ticks: { precision: 0 } } },
  },
});

const classChart = new Chart($("#classChart"), {
  type: "doughnut",
  data: {
    labels: ["bot", "human", "unknown"],
    datasets: [{ data: [0, 0, 0], backgroundColor: [COLORS.bot, COLORS.human, COLORS.unknown], borderWidth: 0 }],
  },
  options: { cutout: "62%", plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } } } },
});

const credChart = new Chart($("#credChart"), {
  type: "bar",
  data: { labels: [], datasets: [{ label: "tries", data: [], backgroundColor: COLORS.accent2, borderRadius: 5 }] },
  options: {
    indexAxis: "y", plugins: { legend: { display: false } },
    scales: { x: { beginAtZero: true, ticks: { precision: 0 } } },
  },
});

const intentPalette = ["#f2a93b", "#ff5b5b", "#58c6ff", "#c98a2b", "#8a8a90", "#5a5a60", "#3a3a40"];
const intentChart = new Chart($("#intentChart"), {
  type: "doughnut",
  data: { labels: [], datasets: [{ data: [], backgroundColor: intentPalette, borderWidth: 0 }] },
  options: { cutout: "55%", plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 10 } } } } },
});

let timeTick = 0;
function pushTime(n) {
  timeChart.data.labels.push(timeTick++);
  timeChart.data.datasets[0].data.push(n);
  if (timeChart.data.labels.length > 40) {
    timeChart.data.labels.shift();
    timeChart.data.datasets[0].data.shift();
  }
  timeChart.update();
}

/* ------------------------------------------------------------------ */
/* counters + feed                                                    */
/* ------------------------------------------------------------------ */
const counterEls = {
  sessions: $("#stat-sessions"), attempts: $("#stat-attempts"),
  bots: $("#stat-bots"), humans: $("#stat-humans"),
  breaches: $("#stat-breaches"), countries: $("#stat-countries"),
};
const counterVals = {};
function setCounter(key, val) {
  const el = counterEls[key];
  if (!el) return;
  if (counterVals[key] !== val) {
    el.textContent = val;
    el.classList.remove("bump"); void el.offsetWidth; el.classList.add("bump");
    counterVals[key] = val;
  }
}
function applyStats(stats) {
  setCounter("sessions", stats.sessions);
  setCounter("attempts", stats.attempts);
  setCounter("bots", stats.bots);
  setCounter("humans", stats.humans);
  setCounter("breaches", stats.breaches);
  setCounter("countries", stats.countries);
  classChart.data.datasets[0].data = [stats.bots, stats.humans, stats.unknown];
  classChart.update();
}
function applyCreds(creds) {
  credChart.data.labels = creds.map((c) => `${c.username}:${c.password}`);
  credChart.data.datasets[0].data = creds.map((c) => c.count);
  credChart.update();
}
function applyIntents(intents) {
  intentChart.data.labels = intents.map((i) => i.intent);
  intentChart.data.datasets[0].data = intents.map((i) => i.count);
  intentChart.update();
}

const feed = $("#feed");
const FEED_MAX = 120;
function addFeedAttempt(d) {
  const flags = [];
  if (d.is_default) flags.push('<span class="tag default">default</span>');
  if (d.is_common) flags.push('<span class="tag common">common</span>');
  const row = document.createElement("div");
  row.className = "feed-row attempt";
  row.innerHTML =
    `<span class="ts">${fmtTime(d.ts)}</span>` +
    `<span class="tag ${classOf(d.classification)}">${esc(d.classification)}</span>` +
    `<span class="body"><span class="ip">${esc(d.ip)}</span> ` +
    `<span style="color:#8092ad">[${esc(d.country || "?")}/${esc(d.protocol)}]</span> ` +
    `${esc(d.username)}:${esc(d.password)} ${flags.join(" ")}</span>`;
  pushFeed(row);
}
function addFeedCommand(d) {
  const tag = d.intent_tag ? `<span class="tag intent">${esc(d.intent_tag)}</span>` : "";
  const row = document.createElement("div");
  row.className = "feed-row command";
  row.innerHTML =
    `<span class="ts">${fmtTime(d.ts)}</span>` +
    `<span class="body"><span class="ip">${esc(d.ip)}</span> ` +
    `<span style="color:#c46bff">$</span> ${esc(d.command)} ${tag}</span>`;
  pushFeed(row);
}
function pushFeed(row) {
  feed.prepend(row);
  while (feed.childElementCount > FEED_MAX) feed.removeChild(feed.lastChild);
}

/* ------------------------------------------------------------------ */
/* websocket                                                          */
/* ------------------------------------------------------------------ */
let ws;
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    $("#connPill").classList.add("live");
    $("#connText").textContent = "LINK // LIVE";
  };
  ws.onclose = () => {
    $("#connPill").classList.remove("live");
    $("#connText").textContent = "RECONNECTING";
    setTimeout(connect, 1500);
  };
  ws.onmessage = (ev) => handleMessage(JSON.parse(ev.data));
}

function handleMessage(msg) {
  const d = msg.data;
  switch (msg.type) {
    case "snapshot":
      hydrate(d);
      break;
    case "session":
      upsertMarker(d, true);
      break;
    case "attempt":
      addFeedAttempt(d);
      // keep marker classification fresh as the engine relabels
      if (markers.has(d.session_id)) {
        const m = markers.get(d.session_id);
        m.setIcon(markerIcon(d.classification, true));
        setTimeout(() => m.setIcon(markerIcon(d.classification, false)), 2600);
      }
      break;
    case "command":
      addFeedCommand(d);
      break;
    case "stats":
      applyStats(d.stats);
      applyCreds(d.top_credentials);
      applyIntents(d.intents);
      pushTime(d.new_attempts);
      $("#demoToggle").checked = d.demo_running;
      break;
    case "clear":
      resetUi();
      break;
  }
}

function hydrate(d) {
  resetUi(false);
  applyStats(d.stats);
  applyCreds(d.top_credentials);
  applyIntents(d.intents);
  d.markers.forEach((m) => upsertMarker(m, false));
  // oldest first so newest ends on top
  [...d.events].reverse().forEach((e) => {
    if (e.kind === "attempt") addFeedAttempt(e); else addFeedCommand(e);
  });
  $("#demoToggle").checked = d.demo_running;
}

function resetUi(clearStats = true) {
  markers.forEach((m) => map.removeLayer(m));
  markers.clear();
  $("#mapCount").textContent = "0 origins";
  feed.innerHTML = "";
  if (clearStats) {
    ["sessions", "attempts", "bots", "humans", "breaches", "countries"].forEach((k) => setCounter(k, 0));
    applyCreds([]); applyIntents([]);
    classChart.data.datasets[0].data = [0, 0, 0]; classChart.update();
  }
}

/* ------------------------------------------------------------------ */
/* drawer (session detail)                                            */
/* ------------------------------------------------------------------ */
async function openDrawer(sessionId) {
  const res = await fetch(`/api/session/${sessionId}`);
  const d = await res.json();
  if (!d.session) return;
  const s = d.session;
  let html = `<div class="detail-meta">
    <div><div class="k">Source IP</div><div class="v">${esc(s.ip)}</div></div>
    <div><div class="k">Protocol</div><div class="v">${esc(s.protocol)}</div></div>
    <div><div class="k">Origin</div><div class="v">${esc(s.city || "?")}, ${esc(s.country || "?")}</div></div>
    <div><div class="k">Classification</div><div class="v" style="color:${COLORS[classOf(s.classification)]}">${esc(s.classification)}</div></div>
  </div>`;

  html += `<div class="detail-section"><h3>Credential attempts (${d.attempts.length})</h3>`;
  d.attempts.forEach((a) => {
    const delay = a.delay_ms == null ? "&mdash;" : `${Math.round(a.delay_ms)}ms`;
    const flags = [];
    if (a.is_default) flags.push('<span class="tag default">default</span>');
    if (a.is_common) flags.push('<span class="tag common">common</span>');
    html += `<div class="timeline-row"><span style="color:#8092ad">+${delay}</span> ` +
            `<span>${esc(a.username)}:${esc(a.password)}</span> ${flags.join(" ")}</div>`;
  });
  html += `</div>`;

  if (d.commands.length) {
    html += `<div class="detail-section"><h3>Shell transcript (${d.commands.length})</h3>`;
    d.commands.forEach((c) => {
      const tag = c.intent_tag ? `<span class="tag intent">${esc(c.intent_tag)}</span>` : "";
      html += `<div class="cmd-row"><span class="prompt">$</span> ${esc(c.command)} ${tag}</div>`;
    });
    html += `</div>`;
  } else {
    html += `<div class="detail-section"><h3>Shell transcript</h3>` +
            `<p style="color:#8092ad;font-size:12.5px">No shell access was granted for this session.</p></div>`;
  }

  $("#drawerBody").innerHTML = html;
  $("#drawer").classList.add("show");
  $("#drawerOverlay").classList.add("show");
}
function closeDrawer() {
  $("#drawer").classList.remove("show");
  $("#drawerOverlay").classList.remove("show");
}

/* ------------------------------------------------------------------ */
/* controls                                                           */
/* ------------------------------------------------------------------ */
async function post(url) {
  try { await fetch(url, { method: "POST" }); } catch (e) { /* ignore */ }
}

document.querySelectorAll("[data-action]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const a = btn.dataset.action;
    if (a === "bot") post("/api/attack/bot");
    else if (a === "human") post("/api/attack/human");
    else if (a === "swarm") post("/api/attack/swarm");
    else if (a === "real") post("/api/attack/real?profile=bot");
    else if (a === "custom") {
      const n = $("#customCount").value || 10;
      const p = $("#customProfile").value;
      post(`/api/attack/custom?count=${n}&profile=${p}`);
    } else if (a === "clear") {
      if (confirm("Clear all captured data?")) post("/api/clear");
    }
  });
});

$("#demoToggle").addEventListener("change", (e) => {
  post(e.target.checked ? "/api/demo/start" : "/api/demo/stop");
});

$("#drawerClose").addEventListener("click", closeDrawer);
$("#drawerOverlay").addEventListener("click", closeDrawer);
$("#helpBtn").addEventListener("click", () => {
  $("#helpOverlay").classList.add("show");
  $(".modal").classList.add("show");
});
function closeHelp() {
  $("#helpOverlay").classList.remove("show");
  $(".modal").classList.remove("show");
}
$("#helpClose").addEventListener("click", closeHelp);
$("#helpOverlay").addEventListener("click", closeHelp);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { closeDrawer(); closeHelp(); }
});

function tickClock() {
  const el = document.getElementById("slClock");
  if (el) el.textContent = new Date().toLocaleTimeString("en-GB", { hour12: false });
}
setInterval(tickClock, 1000);
tickClock();

connect();
