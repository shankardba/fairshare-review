// FairShare UI. Presentation only: every number shown here arrives
// pre-computed from the API. Nothing in this file derives shares, payouts or
// percentages -- that logic lives server-side (eventually in DB procedures).
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const store = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
};

const state = { persona: store.get("fs.persona", "me"), user: null, orgs: [], events: null, eventsOrg: null,
  filter: { q: "", type: "All", scenarios: false, hideExited: true, allCols: false } };

// Two modes. Live: the server checks the session cookie and answers each call from the
// database. Static review snapshot (window.FS_STATIC, GitHub Pages): every response was
// generated ahead of time and encrypted; the password unlocks it in this browser.
const STATIC = window.FS_STATIC || null;
let bundle = null;

async function api(path) {
  if (STATIC) {
    if (!bundle) throw Object.assign(new Error("locked"), { status: 401 });
    if (!(path in bundle)) throw Object.assign(new Error("not found"), { status: 404 });
    return structuredClone(bundle[path]);
  }
  const r = await fetch("/api/" + path, { headers: { "X-Demo-User": state.persona }, credentials: "same-origin" });
  if (r.status === 401) { showLogin(); throw Object.assign(new Error("unauthenticated"), { status: 401 }); }
  if (!r.ok) throw Object.assign(new Error(r.statusText), { status: r.status });
  return r.json();
}

// ---------- static snapshot crypto (AES-256-GCM, key = PBKDF2-SHA256 of the password) ----------
const b64 = { dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)), enc: (u) => btoa(String.fromCharCode(...u)) };
async function sha256hex(t) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t)));
  return [...h].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function deriveKeyBytes(password, env) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: b64.dec(env.salt), iterations: env.iter }, base, 256));
}
async function unlock(keyBytes) {
  const env = await (await fetch(STATIC.data, { cache: "no-store" })).json();
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.dec(env.iv) }, key, b64.dec(env.ct));
  const text = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
  bundle = JSON.parse(text);
}

// ---------- login ----------
function showLogin(msg) {
  $("#shell").hidden = true;
  $("#login").hidden = false;
  $("#loginErr").textContent = msg || "";
  setTimeout(() => $("#email").focus(), 0);
}
$("#loginForm").onsubmit = async (ev) => {
  ev.preventDefault();
  const email = $("#email").value.trim().toLowerCase(), password = $("#password").value;
  const btn = $("#loginBtn"); btn.disabled = true; btn.textContent = "Signing in…"; $("#loginErr").textContent = "";
  try {
    if (STATIC) {
      const env = await (await fetch(STATIC.data, { cache: "no-store" })).json();
      if (!STATIC.users.includes(await sha256hex(email))) throw new Error("bad");
      const kb = await deriveKeyBytes(password, env);
      await unlock(kb).catch(() => { throw new Error("bad"); });
      try { sessionStorage.setItem("fs.k", b64.enc(kb)); sessionStorage.setItem("fs.e", email); } catch {}
    } else {
      const r = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify({ email, password }) });
      if (!r.ok) throw new Error(r.status === 429 ? "throttled" : "bad");
    }
    $("#password").value = "";
    await start();
  } catch (e) {
    $("#loginErr").textContent = e.message === "throttled" ? "Too many attempts — wait a minute and try again." : "Incorrect email or password.";
  } finally {
    btn.disabled = false; btn.textContent = "Sign in";
  }
};
$("#signOut").onclick = async () => {
  if (STATIC) { try { sessionStorage.removeItem("fs.k"); sessionStorage.removeItem("fs.e"); } catch {} bundle = null; }
  else await fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
  store.set("fs.persona", "me"); state.persona = "me";
  location.hash = ""; showLogin();
};

// ---------- formatting (display only) ----------
const usd0 = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 });
const usd2 = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", minimumFractionDigits: 2, maximumFractionDigits: 2 });
const n2 = new Intl.NumberFormat("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function fmt(v, kind, compact) {
  if (v === null || v === undefined || v === "") return "";
  if (kind === "usd") return compact ? usdShort(v) : usd2.format(v);
  if (kind === "usd0") return usd0.format(v);
  if (kind === "pct") return (v * 100).toFixed(2) + "%";
  if (kind === "num") return n2.format(v);
  if (kind === "date") return fmtSheetDate(v);
  return String(v);
}
function usdShort(v) {
  const a = Math.abs(v);
  if (a >= 1e6) return "$" + (v / 1e6).toFixed(2) + "M";
  if (a >= 1e3) return "$" + (v / 1e3).toFixed(0) + "K";
  return usd0.format(v);
}
function fmtSheetDate(s) {
  if (/^\d{4}-\d{2}-\d{2}/.test(String(s))) return fmtIso(String(s).slice(0, 10));
  const m = String(s).match(/(\d{1,2})[.,/](\d{1,2})[.,/](\d{2,4})/);
  if (!m) return String(s);
  let y = +m[3]; if (y < 100) y += 2000;
  return `${MONTHS[+m[1] - 1] || m[1]} ${+m[2]}, ${y}`;
}
function fmtIso(d) {
  if (!d) return "—";
  const [y, mo, da] = d.split("-").map(Number);
  return `${MONTHS[mo - 1]} ${da}, ${y}`;
}
const slug = (t) => String(t).toLowerCase().replace(/[^a-z]+/g, "-").replace(/-+$/, "");
const chip = (type, status) => `<span class="chip t-${slug(type)} ${status === "Scenario" ? "s-scenario" : ""}"><i></i>${esc(type)}</span>`;
const initials = (n) => n.replace(/\(.*?\)/g, "").split(",").reverse().map((p) => p.trim()[0] || "").join("").slice(0, 2).toUpperCase();
const shortName = (n) => { const [last, first] = n.split(","); return first ? `${first.trim().replace(/\s+(M\.D\.|D\.O\.).*$/, "")} ${last.trim()}`.replace(/,$/, "") : n; };

// ---------- tooltip ----------
const tip = $("#tip");
function showTip(html, ev) {
  tip.innerHTML = html; tip.classList.add("show");
  const x = Math.min(ev.clientX + 14, innerWidth - tip.offsetWidth - 8);
  const y = Math.max(8, ev.clientY - tip.offsetHeight - 12);
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
const hideTip = () => tip.classList.remove("show");

// ---------- routing ----------
function route() {
  const p = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  return { org: p[0], view: p[1] || "overview", id: p[2] ? decodeURIComponent(p[2]) : null };
}
const go = (org, view, id) => { location.hash = `#/${org}/${view}${id ? "/" + encodeURIComponent(id) : ""}`; };

// ---------- boot ----------
async function boot() {
  if (STATIC) {
    let kb = null; try { kb = sessionStorage.getItem("fs.k"); } catch {}
    if (!kb) return showLogin();
    try { await unlock(b64.dec(kb)); } catch { return showLogin(); }
  }
  try { await start(); } catch (e) { if (e.status !== 401) showLogin("Couldn't reach the server."); }
}

async function start() {
  const s = await api("session");
  if (STATIC) { let e = ""; try { e = sessionStorage.getItem("fs.e") || ""; } catch {} s.user.name = e || s.user.name; }
  state.user = s.user;
  const sel = $("#persona");
  $("#viewAs").hidden = !s.personas.length;
  sel.innerHTML = s.personas.map((p) => `<option value="${p.id}" ${p.id === s.user.id ? "selected" : ""}>${esc(p.name)}</option>`).join("");
  sel.onchange = () => { store.set("fs.persona", sel.value); state.persona = sel.value; state.events = null; location.hash = ""; start(); };
  $("#whoName").textContent = s.user.email || s.user.name;
  $("#whoTitle").textContent = s.user.id !== "me" && s.user.email ? `Previewing as ${s.user.name} · ${s.user.title}` : s.user.title;
  state.orgs = await api("orgs");
  document.querySelectorAll("[data-admin]").forEach((a) => (a.hidden = s.user.role === "investor"));
  $("#login").hidden = true;
  $("#shell").hidden = false;
  render();
}

function depth(o) { let d = 0, p = o.parent; while (p) { d++; p = state.orgs.find((x) => x.id === p)?.parent; } return d; }
function ordered() {
  const out = [];
  const walk = (parent) => state.orgs.filter((o) => o.parent === parent).forEach((o) => { out.push(o); walk(o.id); });
  walk(null);
  return out;
}

function renderSide(r) {
  $("#orgTree").innerHTML = ordered().map((o) => `
    <a class="org lvl-${depth(o)} ${o.hasData ? "has-data" : ""} ${o.access ? "" : "locked"} ${o.id === r.org ? "active" : ""}"
       ${o.access ? `href="#/${o.id}/overview"` : `title="Shown for context — no access granted"`}>
      <span class="dot"></span><span>${esc(o.name)}</span>${o.access ? "" : `<span class="kind">🔒</span>`}
    </a>`).join("");
  document.querySelectorAll("#nav a[data-view]").forEach((a) => {
    a.classList.toggle("active", a.dataset.view === r.view);
    a.href = `#/${r.org}/${a.dataset.view}`;
  });
}

function crumbs(parts) { $("#crumbs").innerHTML = parts.map((p, i) => (i === parts.length - 1 ? `<b>${esc(p)}</b>` : esc(p))).join(" <span>/</span> "); }

async function render() {
  hideTip();
  const r = route();
  const first = state.orgs.find((o) => o.access && o.hasData) || state.orgs.find((o) => o.access);
  if (!r.org || !state.orgs.some((o) => o.id === r.org && o.access)) { if (first) go(first.id, "overview"); return; }
  if (r.view === "investors" && state.user.role === "investor") { go(r.org, "overview"); return; }
  renderSide(r);
  $("#side").classList.remove("open");
  const org = state.orgs.find((o) => o.id === r.org);
  const trail = []; let p = org; while (p) { trail.unshift(p.name); p = state.orgs.find((x) => x.id === p.parent); }
  const viewName = { overview: "Overview", events: "Events", investors: "Investors" }[r.view] || "Overview";
  crumbs([...trail, viewName]);
  const view = $("#view");
  try {
    if (!org.hasData) return renderNoData(view, org);
    if (r.view === "events") return await renderEvents(view, r);
    if (r.view === "investors") return await renderInvestors(view, r);
    return await renderOverview(view, r);
  } catch (e) {
    view.innerHTML = `<div class="empty">${e.status === 403 ? "You don't have access to this report." : "Couldn't load this report."}</div>`;
  }
}

function renderNoData(view, org) {
  const kids = state.orgs.filter((o) => o.parent === org.id);
  view.innerHTML = `
    <h1>${esc(org.name)}</h1><p class="sub">${esc(org.kind)}${org.demo ? " · sample organization" : ""}</p>
    ${kids.length ? `<div class="kpis">${kids.map((k) => `
      <a class="card kpi" ${k.access ? `href="#/${k.id}/overview"` : ""}>
        <div class="l">${esc(k.kind)}</div><div class="v" style="font-size:17px">${esc(k.name)}</div>
        <div class="s">${k.hasData ? "Ledger active" : "No events yet"}</div></a>`).join("")}</div>` : ""}
    <div class="card empty">
      <svg viewBox="0 0 20 20"><path d="M4 3h9l3 3v11H4zm8 1v3h3"/></svg>
      <p><b>No events recorded${kids.length ? " at this level" : ""}.</b><br>${kids.length ? "Ownership is tracked in the sub-organizations above." : "Import an ownership workbook or record the initial capitalization to begin."}</p>
      <button class="btn primary" disabled>Import workbook</button>
    </div>`;
}

// ---------- overview ----------
async function renderOverview(view, r) {
  const s = await api(`orgs/${r.org}/summary`);
  const inv = state.user.role === "investor";
  const last = s.distributions[s.distributions.length - 1] || {};
  const tiles = inv ? `
      <div class="card kpi hero"><div class="l">Your shares</div><div class="v">${fmt(s.me.shares, "num")}</div><div class="s">${fmt(s.me.pct, "pct")} of the partnership</div></div>
      <div class="card kpi"><div class="l">Your capital account</div><div class="v">${fmt(s.me.investment, "usd0")}</div><div class="s">as of ${esc(fmtSheetDate(s.asOf))}</div></div>
      <div class="card kpi"><div class="l">Lifetime distributions</div><div class="v">${fmt(s.me.lifetime, "usd0")}</div><div class="s">${s.distributions.filter((d) => d.mine).length} years paid</div></div>
      <div class="card kpi"><div class="l">${last.year || ""} distribution</div><div class="v">${fmt(last.mine, "usd0")}</div><div class="s">Partnership ROI ${fmt(last.roi, "pct")}</div></div>`
    : `
      <div class="card kpi hero"><div class="l">Committed capital</div><div class="v">${fmt(s.capital, "usd0")}</div><div class="s">held constant across every admission &amp; exit</div></div>
      <div class="card kpi"><div class="l">Shares outstanding</div><div class="v">${fmt(s.shares, "num")}</div><div class="s">$10,000 par</div></div>
      <div class="card kpi"><div class="l">Active members</div><div class="v">${s.activeMembers}</div><div class="s">as of ${esc(fmtSheetDate(s.asOf))}</div></div>
      <div class="card kpi"><div class="l">${last.year || ""} distribution</div><div class="v">${fmt(last.amount, "usd0")}</div><div class="s">ROI ${fmt(last.roi, "pct")} · ${fmt(last.perShareMonth, "usd")}/share-month</div></div>
      <div class="card kpi"><div class="l">Distributed since ${s.distributions[0]?.year || ""}</div><div class="v">${fmt(s.lifetimeDistributed, "usd0")}</div><div class="s">${s.distributions.length} annual distributions</div></div>`;

  const right = inv ? `
    <div class="card"><div class="card-h"><h2>Your recent events</h2></div><div class="card-b list">
      ${s.recent.map((e) => `<a class="li" href="#/${r.org}/events/${e.id}"><div><div class="t">${esc(e.title)}</div><div class="d">${fmtIso(e.date)}</div></div><div class="r">${chip(e.type)}</div></a>`).join("")}
    </div></div>`
    : `
    <div class="card"><div class="card-h"><h2>Current ownership</h2><span class="muted">${esc(s.asOfTitle)}</span></div>
      <div class="card-b own">${ownershipBars(s.owners)}</div></div>`;

  view.innerHTML = `
    <h1>${inv ? "Welcome back, " + esc(shortName(s.me.name).split(" ")[0]) : "Partnership overview"}</h1>
    <p class="sub">${inv ? "Your position in " + esc(state.orgs.find((o) => o.id === r.org)?.name || "this partnership") : `${s.eventsRecorded} events recorded · latest: <a href="#/${r.org}/events/${s.asOfEventId}" style="color:var(--accent-ink)">${esc(s.asOfTitle)}</a>`}</p>
    <div class="kpis">${tiles}</div>
    <div class="grid-2">
      <div class="card"><div class="card-h"><h2>${inv ? "Your annual distributions" : "Annual distributions"}</h2><span class="muted">click a bar to open the report</span></div>
        <div class="card-b"><div id="distChart"></div></div></div>
      ${right}
    </div>
    ${inv ? "" : `<div class="card" style="margin-top:16px"><div class="card-h"><h2>Recent events</h2><a class="muted" href="#/${r.org}/events" style="color:var(--accent-ink)">All events →</a></div><div class="card-b list">
      ${s.recent.map((e) => `<a class="li" href="#/${r.org}/events/${e.id}"><div><div class="t">${esc(e.title)}</div><div class="d">${fmtIso(e.date)} · as of ${esc(e.asOf)}</div></div><div class="r">${chip(e.type)}</div></a>`).join("")}
    </div></div>`}`;

  barChart($("#distChart"), s.distributions.map((d) => ({
    x: String(d.year), y: inv ? d.mine : d.amount, id: d.eventId,
    tip: `<b>${d.year} distribution</b>${inv ? `Your share: ${fmt(d.mine, "usd0")}<br>` : ""}Partnership: ${fmt(d.amount, "usd0")}<br>ROI ${fmt(d.roi, "pct")}`,
  })), (d) => go(r.org, "events", d.id));
}

function ownershipBars(owners) {
  const top = owners.slice(0, 9), rest = owners.slice(9);
  const max = owners[0]?.pct || 1;
  const row = (name, pct, sub) => `<div class="own-row" title="${esc(sub)}"><span class="n">${esc(name)}</span><span class="p">${fmt(pct, "pct")}</span>
     <div class="track"><div class="fill" style="width:${(pct / max) * 100}%"></div></div></div>`;
  let html = top.map((o) => row(shortName(o.name), o.pct, `${fmt(o.shares, "num")} shares`)).join("");
  if (rest.length) html += row(`${rest.length} other members`, rest.reduce((a, o) => a + o.pct, 0), "combined");
  return html;
}

// single-series bar chart with hover tooltip; bars anchored to baseline, 4px rounded tops
function barChart(el, data, onClick) {
  const W = Math.max(el.clientWidth, 320), H = 260, m = { t: 22, r: 8, b: 26, l: 52 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const max = Math.max(...data.map((d) => d.y || 0), 1);
  const step = niceStep(max / 4), top = Math.ceil(max / step) * step;
  const bw = iw / data.length, gap = Math.max(2, bw * 0.28);
  const y = (v) => m.t + ih - (v / top) * ih;
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Annual distributions bar chart">`;
  for (let v = 0; v <= top + 1e-9; v += step) s += `<line class="grid" x1="${m.l}" x2="${W - m.r}" y1="${y(v)}" y2="${y(v)}"/><text class="axis" x="${m.l - 8}" y="${y(v) + 4}" text-anchor="end">${usdShort(v)}</text>`;
  const lastI = data.length - 1;
  data.forEach((d, i) => {
    const x = m.l + i * bw + gap / 2, w = bw - gap, h = Math.max(0, ih - (y(d.y || 0) - m.t)), yy = y(d.y || 0);
    const r = Math.min(4, w / 2, h);
    s += `<rect class="hit" data-i="${i}" x="${m.l + i * bw}" y="${m.t}" width="${bw}" height="${ih}"/>`;
    s += `<path class="bar" d="M${x},${yy + h} V${yy + r} Q${x},${yy} ${x + r},${yy} H${x + w - r} Q${x + w},${yy} ${x + w},${yy + r} V${yy + h} Z"/>`;
    const every = Math.ceil(data.length / 12);
    if ((i % every === 0 && lastI - i >= every) || i === lastI) s += `<text class="axis" x="${x + w / 2}" y="${H - 8}" text-anchor="middle">${esc(d.x)}</text>`;
    if (i === lastI) s += `<text class="lbl" x="${x + w / 2}" y="${yy - 6}" text-anchor="middle">${usdShort(d.y || 0)}</text>`;
  });
  el.innerHTML = s + "</svg>";
  el.querySelectorAll(".hit").forEach((h) => {
    const d = data[+h.dataset.i];
    h.addEventListener("mousemove", (ev) => showTip(d.tip, ev));
    h.addEventListener("mouseleave", hideTip);
    h.addEventListener("click", () => onClick && onClick(d));
  });
}
function niceStep(raw) { const p = 10 ** Math.floor(Math.log10(raw || 1)); const f = raw / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p; }

// ---------- events ----------
const TYPES = ["All", "Distribution", "Admission", "Retirement", "Capital Call", "Scenario"];

async function renderEvents(view, r) {
  if (state.eventsOrg !== r.org || !state.events) { state.events = await api(`orgs/${r.org}/events`); state.eventsOrg = r.org; }
  const evs = state.events;
  if (!r.id) {
    const pick = [...evs].reverse().find((e) => e.status === "Final") || evs[0];
    if (pick) { history.replaceState(null, "", `#/${r.org}/events/${pick.id}`); r.id = pick.id; }
  }
  if (!$(".events", view)) {
    view.innerHTML = `<div class="events">
      <div class="card timeline">
        <div class="tl-filters">
          <input class="search" id="q" placeholder="Search events or tabs…" value="${esc(state.filter.q)}">
          <div class="seg" id="types">${TYPES.filter((t) => state.user.role !== "investor" || t !== "Scenario").map((t) => `<button data-t="${t}">${t}</button>`).join("")}</div>
          ${state.user.role === "investor" ? "" : `<label class="toggle"><input type="checkbox" id="scen"> Include scenarios, summaries &amp; superseded</label>`}
        </div>
        <div class="tl-list" id="tl"></div>
      </div>
      <div class="card" id="report"></div></div>`;
    $("#q").oninput = (e) => { state.filter.q = e.target.value; drawTimeline(r); };
    $("#types").onclick = (e) => { const t = e.target.dataset.t; if (!t) return; state.filter.type = t; if (t === "Scenario") state.filter.scenarios = true; drawTimeline(r); };
    const sc = $("#scen"); if (sc) { sc.checked = state.filter.scenarios; sc.onchange = () => { state.filter.scenarios = sc.checked; drawTimeline(r); }; }
  }
  drawTimeline(r);
  await drawReport(r);
}

function typeMatch(e, t) {
  if (t === "All") return true;
  if (t === "Scenario") return e.status !== "Final";
  if (t === "Admission") return /Admission|Admit/.test(e.type);
  if (t === "Retirement") return /Retire/.test(e.type);
  return e.type === t;
}

function drawTimeline(r) {
  const f = state.filter;
  document.querySelectorAll("#types button").forEach((b) => b.classList.toggle("on", b.dataset.t === f.type));
  const sc = $("#scen"); if (sc) sc.checked = f.scenarios;
  const q = f.q.trim().toLowerCase();
  const list = state.events.filter((e) => (f.scenarios || e.status === "Final" || e.id === r.id) && typeMatch(e, f.type)
    && (!q || `${e.title} ${e.sheet} ${e.asOf}`.toLowerCase().includes(q)));
  const groups = {};
  [...list].reverse().forEach((e) => { const y = e.status === "Scenario" ? "Scenarios & analyses" : (e.date || "").slice(0, 4) || "Undated"; (groups[y] = groups[y] || []).push(e); });
  const keys = Object.keys(groups).sort((a, b) => (a.startsWith("S") ? 1 : b.startsWith("S") ? -1 : b.localeCompare(a)));
  $("#tl").innerHTML = keys.map((k) => `<div class="tl-year">${esc(k)}</div>` + groups[k].map((e) => `
    <a class="tl-item ${e.id === r.id ? "on" : ""}" href="#/${r.org}/events/${e.id}">
      <span class="node"></span>
      <span><div class="tt">${esc(e.title)}</div>
      <div class="meta">${chip(e.type, e.status)}<span>${esc(e.asOf || "")}</span>${e.status !== "Final" ? `<span class="status">· ${e.status}</span>` : ""}</div></span>
    </a>`).join("")).join("") || `<div class="empty">No events match.</div>`;
  const on = $("#tl .tl-item.on"); if (on && !on._seen) { on.scrollIntoView({ block: "nearest" }); on._seen = 1; }
}

async function drawReport(r) {
  const box = $("#report");
  if (!r.id) { box.innerHTML = `<div class="empty">Select an event.</div>`; return; }
  const e = await api(`orgs/${r.org}/events/${encodeURIComponent(r.id)}`);
  const f = state.filter;
  const roleCol = (role) => e.columns.find((c) => c.role === role);
  const activity = ["post_shares", "pre_shares", "add_shares", "distribution", "notes"].map(roleCol).filter(Boolean);
  const isExited = (row) => activity.length && activity.every((c) => !row.values[c.id]);
  const cols = e.columns.filter((c) => f.allCols || !c.secondary);
  const rows = e.rows.filter((row) => !(f.hideExited && isExited(row)));
  const hiddenRows = e.rows.length - rows.length;
  const hiddenCols = e.columns.length - cols.length;

  // grouped header
  let g = `<th class="l sticky"></th>`, c = `<th class="l sticky">Member</th>`;
  for (let i = 0; i < cols.length;) {
    let j = i; while (j + 1 < cols.length && cols[j + 1].top && cols[j + 1].top === cols[i].top) j++;
    const span = j - i + 1;
    g += cols[i].top ? `<th class="span" colspan="${span}"><span>${esc(cols[i].top)}</span></th>` : `<th colspan="${span}"></th>`;
    i = j + 1;
  }
  cols.forEach((col) => (c += `<th class="${col.fmt === "text" || col.fmt === "date" ? "l" : ""}">${esc(col.sub)}</th>`));
  const td = (col, v) => {
    if (col.fmt === "text") return `<td class="note">${esc(v ?? "")}</td>`;
    if (col.fmt === "date") return `<td class="l">${esc(fmt(v, "date"))}</td>`;
    const cls = typeof v === "number" ? (v < 0 ? "neg" : v === 0 ? "zero" : "") : "";
    return `<td class="${cls}">${v === 0 ? "—" : esc(fmt(v, col.fmt))}</td>`;
  };
  const body = rows.map((row, i) => `<tr class="${isExited(row) ? "exited" : ""}"><td class="l sticky"><span class="idx">${i + 1}</span>${esc(row.name)}</td>${cols.map((col) => td(col, row.values[col.id])).join("")}</tr>`).join("");
  const foot = Object.keys(e.totals).length ? `<tfoot><tr><td class="l sticky">Total</td>${cols.map((col) => (col.fmt === "text" || col.fmt === "date" ? "<td></td>" : td(col, e.totals[col.id]))).join("")}</tr></tfoot>` : "";

  const k = e.kpis;
  const kp = [
    ["Members", e.scoped ? "—" : k.active != null ? `${k.active} <span class="muted" style="font-size:12px;font-weight:500">active of ${k.members}</span>` : k.members],
    k.totalInvestment != null && ["Total investment", fmt(k.totalInvestment, "usd0")],
    k.totalShares != null && ["Shares", fmt(k.totalShares, "num")],
    ...e.facts.filter((x) => x.fmt !== "text" && !/guaranty|prior to|post 20|initial capital|revised capital/i.test(x.label)).slice(0, 3).map((x) => [x.label, fmt(x.value, x.fmt === "usd" ? (x.value < 1000 ? "usd" : "usd0") : x.fmt)]),
  ].filter(Boolean);
  const otherFacts = e.facts.filter((x) => !kp.some((p) => p[0] === x.label));
  const ch = e.changes;

  $("#report").innerHTML = `
    <div class="rep-h">
      <div class="title">
        <div class="rep-meta">${chip(e.type, e.status)}<span>As of ${esc(e.asOf || "—")}</span><span>·</span><span>Source tab “${esc(e.sheet)}”</span>${e.status !== "Final" ? `<span>·</span><b>${esc(e.status)}</b>` : ""}</div>
        <h1>${esc(e.title)}</h1>
      </div>
      <div class="btns">
        <button class="btn" id="csv"><svg viewBox="0 0 20 20"><path d="M9 3h2v8l3-3 1.4 1.4L10 14.8 4.6 9.4 6 8l3 3zM4 16h12v2H4z"/></svg>CSV</button>
        <button class="btn" onclick="print()"><svg viewBox="0 0 20 20"><path d="M5 2h10v4H5zm-2 5h14a1 1 0 0 1 1 1v6h-3v4H5v-4H2V8a1 1 0 0 1 1-1zm4 7v2h6v-2z"/></svg>PDF</button>
      </div>
    </div>
    ${e.scoped ? `<div class="lock-note" style="margin:8px 22px 0"><svg viewBox="0 0 20 20"><path d="M10 1l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V4z"/></svg>Showing your line and partnership totals only. Other members' positions are not sent to your browser.</div>` : ""}
    <div class="rep-kpis">${kp.map(([l, v]) => `<div><div class="l">${esc(l)}</div><div class="v">${v}</div></div>`).join("")}</div>
    ${ch.length ? `<div class="changes"><h3>What changed</h3><ul id="chl">${ch.slice(0, 6).map((x) => `<li><b>${esc(shortName(x.name))}</b> — ${esc(x.note)}</li>`).join("")}</ul>${ch.length > 6 ? `<span class="more" id="chm">Show all ${ch.length} changes</span>` : ""}</div>` : ""}
    <div class="rep-tools">
      ${e.scoped ? "" : `<label class="toggle"><input type="checkbox" id="hx" ${f.hideExited ? "checked" : ""}> Hide exited members</label>`}
      ${hiddenCols || f.allCols ? `<label class="toggle"><input type="checkbox" id="ac" ${f.allCols ? "checked" : ""}> Show all source columns</label>` : ""}
      <span class="muted">${rows.length} rows${hiddenRows ? ` · ${hiddenRows} exited hidden` : ""}${hiddenCols ? ` · ${hiddenCols} legacy columns hidden` : ""}</span>
    </div>
    <div class="tbl-wrap"><table class="rep"><thead><tr class="g">${g}</tr><tr class="c">${c}</tr></thead><tbody>${body}</tbody>${foot}</table></div>
    ${otherFacts.length || e.notes.length ? `<div class="notes">
      ${otherFacts.length ? `<div class="facts">${otherFacts.map((x) => `<span class="fact">${esc(x.label)}: <b>${esc(x.fmt === "text" ? x.value : fmt(x.value, x.fmt === "usd" ? "usd0" : x.fmt))}</b></span>`).join("")}</div>` : ""}
      ${e.notes.map((n) => `<div>${esc(n)}</div>`).join("")}</div>` : ""}`;

  const hx = $("#hx"); if (hx) hx.onchange = () => { f.hideExited = hx.checked; drawReport(r); };
  const ac = $("#ac"); if (ac) ac.onchange = () => { f.allCols = ac.checked; drawReport(r); };
  const chm = $("#chm"); if (chm) chm.onclick = () => { $("#chl").innerHTML = ch.map((x) => `<li><b>${esc(shortName(x.name))}</b> — ${esc(x.note)}</li>`).join(""); chm.remove(); };
  $("#csv").onclick = () => downloadCsv(e, cols, rows);
}

function downloadCsv(e, cols, rows) {
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines = [["Member", ...cols.map((c) => `${c.top} ${c.sub}`.trim())].map(q).join(",")];
  rows.forEach((r) => lines.push([r.name, ...cols.map((c) => r.values[c.id])].map(q).join(",")));
  if (Object.keys(e.totals).length) lines.push(["Total", ...cols.map((c) => e.totals[c.id])].map(q).join(","));
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
  a.download = `${e.sheet.replace(/[^\w.-]+/g, "_")}.csv`;
  a.click();
}

// ---------- investors ----------
async function renderInvestors(view, r) {
  const list = await api(`orgs/${r.org}/investors`);
  const active = list.filter((x) => x.status === "Active");
  view.innerHTML = `
    <h1>Investors</h1><p class="sub">${active.length} active · ${list.length - active.length} exited · positions as of the latest recorded event</p>
    <div class="card" style="margin-top:18px; overflow:auto">
      <table class="plain"><thead><tr><th>Member</th><th>Invested since</th><th>Status</th><th class="r">Shares</th><th class="r">Capital account</th><th class="r">Lifetime distributions</th><th class="r">Events</th></tr></thead>
      <tbody>${list.map((x) => `<tr class="click" data-k="${esc(x.key)}">
        <td><span class="avatar">${esc(initials(x.name))}</span>${esc(x.name)}</td>
        <td>${esc(x.since ? fmtSheetDate(x.since) : "—")}</td>
        <td><span class="pill ${x.status.toLowerCase()}">${x.status}</span></td>
        <td class="r">${x.shares ? fmt(x.shares, "num") : "—"}</td>
        <td class="r">${x.investment ? fmt(x.investment, "usd0") : "—"}</td>
        <td class="r">${fmt(x.lifetime, "usd0")}</td>
        <td class="r">${x.events}</td></tr>`).join("")}</tbody></table>
    </div>`;
  view.querySelectorAll("tr[data-k]").forEach((tr) => (tr.onclick = () => go(r.org, "investors", tr.dataset.k)));
  if (r.id) openInvestor(r, r.id);
}

async function openInvestor(r, key) {
  const d = await api(`orgs/${r.org}/investors/${encodeURIComponent(key)}`);
  const close = () => { bg.remove(); dr.remove(); history.replaceState(null, "", `#/${r.org}/investors`); };
  const bg = document.createElement("div"); bg.className = "drawer-bg"; bg.onclick = close;
  const dr = document.createElement("div"); dr.className = "drawer";
  const total = d.distributions.reduce((a, x) => a + x.amount, 0);
  dr.innerHTML = `<button class="x" aria-label="Close">×</button>
    <div class="avatar" style="width:44px;height:44px;font-size:15px">${esc(initials(d.name))}</div>
    <h1 style="margin-top:10px">${esc(d.name)}</h1><p class="sub">${fmt(total, "usd0")} in lifetime distributions</p>
    <h2 style="margin:20px 0 6px">Distributions by year</h2><div id="invChart"></div>
    <h2 style="margin:18px 0 0">Ownership history</h2>
    <div class="hist">${d.history.filter((h, i, a) => i === 0 || h.note || Math.abs(h.shares - a[i - 1].shares) > 0.005).reverse().map((h) => `
      <div class="h"><a href="#/${r.org}/events/${h.eventId}"><b>${fmt(h.shares, "num")} shares</b> — ${esc(h.title)}</a>
      <div class="d">${fmtIso(h.date)}${h.note ? " · " + esc(h.note) : ""}</div></div>`).join("")}</div>`;
  dr.querySelector(".x").onclick = close;
  document.body.append(bg, dr);
  barChart($("#invChart"), d.distributions.map((x) => ({ x: String(x.year), y: x.amount, tip: `<b>${x.year}</b>${fmt(x.amount, "usd0")}` })));
}

$("#menuBtn").onclick = () => $("#side").classList.toggle("open");
addEventListener("hashchange", () => { if (state.user && !$("#shell").hidden) render(); });
let rt; addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => { if (route().view === "overview") render(); }, 200); });
boot();
