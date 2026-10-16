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
// the review snapshot has no sign-up: point to the landing-page preview instead
if (STATIC) { const lf = document.querySelector(".login-foot"); if (lf) lf.innerHTML = '<a href="./">About FairShare</a>'; }
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
// "Becker, Paul L., M.D." -> "Paul L. Becker"; company names ("Summit Group, LLC") stay as written
const ENTITY_SUFFIX = /,\s*(LLC|L\.L\.C\.|LP|LLP|Inc\.?|Ltd\.?|Co\.?|PLLC|PC|P\.C\.|Trust)\s*$/i;
const shortName = (n) => { if (ENTITY_SUFFIX.test(n)) return n; const [last, first] = n.split(","); return first ? `${first.trim().replace(/\s+(M\.D\.|D\.O\.).*$/, "")} ${last.trim()}`.replace(/,$/, "") : n; };

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
  // the superuser, and self-serve customers, can start partnerships of their own
  $("#newOrg").hidden = STATIC || !(s.user.superuser || s.user.canCreate);
  $("#newOrg").textContent = s.user.superuser ? "+ New organization" : "+ New partnership";
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

// ---------- organization tree (left panel) ----------
const kidsOf = (id) => state.orgs.filter((o) => o.parent === id);
const subtreeSize = (id) => kidsOf(id).reduce((n, k) => n + 1 + subtreeSize(k.id), 0);
// a partner that is itself an LLC or trust, with its own members
const entityTag = (o) => (!o.entityOf ? "" : /\btrust\b/i.test(o.name) ? "Trust" : "LLC");
// collapse state: remembered per viewer; otherwise top level and the path to the open org start expanded
let treePref = {};
try { treePref = JSON.parse(localStorage.getItem("fs.tree") || "{}"); } catch { treePref = {}; }
const saveTree = () => { try { localStorage.setItem("fs.tree", JSON.stringify(treePref)); } catch { /* storage unavailable */ } };

function renderSide(r) {
  const onPath = new Set();
  for (let p = state.orgs.find((o) => o.id === r.org); p; p = state.orgs.find((x) => x.id === p.parent)) onPath.add(p.id);
  const isOpen = (o, d) => (o.id in treePref ? treePref[o.id] : d === 0 || onPath.has(o.id));
  const node = (o, d) => {
    const kids = kidsOf(o.id), open = kids.length > 0 && isOpen(o, d), tag = entityTag(o);
    return `<div class="tnode">
      <div class="org ${o.hasData ? "has-data" : ""} ${o.access ? "" : "locked"} ${o.id === r.org ? "active" : ""}" style="--d:${d}">
        ${kids.length ? `<button class="tw ${open ? "open" : ""}" data-t="${o.id}" aria-expanded="${open}" aria-label="${open ? "Collapse" : "Expand"} ${esc(o.name)}"><svg viewBox="0 0 10 10"><path d="M3 1.5 7 5 3 8.5"/></svg></button>` : `<span class="tw-sp"></span>`}
        <a class="oname" ${o.access ? `href="#/${o.id}/overview"` : `title="Shown for context — no access granted"`}><span class="dot"></span><span class="nm">${esc(o.name)}</span></a>
        ${tag ? `<span class="otag" title="A partner with members of its own">${tag}</span>` : ""}
        ${kids.length && !open ? `<span class="ocnt" title="${subtreeSize(o.id)} nested ${subtreeSize(o.id) === 1 ? "organization" : "organizations"}">${subtreeSize(o.id)}</span>` : ""}
        ${o.access ? "" : `<span class="kind">🔒</span>`}
      </div>
      ${open ? `<div class="tkids" style="--d:${d}">${kids.map((k) => node(k, d + 1)).join("")}</div>` : ""}
    </div>`;
  };
  $("#orgTree").innerHTML = kidsOf(null).map((o) => node(o, 0)).join("");
  $("#orgTree").querySelectorAll(".tw").forEach((b) => (b.onclick = (ev) => {
    ev.preventDefault();
    treePref[b.dataset.t] = b.getAttribute("aria-expanded") !== "true";
    saveTree(); renderSide(r);
  }));
  document.querySelectorAll("#nav a[data-view]").forEach((a) => {
    a.classList.toggle("active", a.dataset.view === r.view);
    a.href = `#/${r.org}/${a.dataset.view}`;
  });
}

// parts: plain labels, or {label, href} for a level you can open
function crumbs(parts) {
  $("#crumbs").innerHTML = parts.map((p, i) => {
    const label = typeof p === "string" ? p : p.label;
    return i === parts.length - 1 ? `<b>${esc(label)}</b>` : p.href ? `<a href="${p.href}">${esc(label)}</a>` : esc(label);
  }).join(" <span>/</span> ");
}

async function render() {
  hideTip();
  const r = route();
  // the full-screen report belongs to the Events page only
  if (r.view !== "events" || r.id === "new") state.expanded_report = false;
  if (!state.expanded_report) document.body.classList.remove("report-open");
  if (state.stmt && state.stmt !== r.id) state.stmt = null;
  if (r.org === "new-org") {
    if (STATIC || !(state.user.superuser || state.user.canCreate)) return go((state.orgs.find((o) => o.access) || {}).id, "overview");
    renderSide(r); $("#side").classList.remove("open"); crumbs(["New organization"]);
    return drawOrgForm($("#view"), null);
  }
  const first = state.orgs.find((o) => o.access && o.hasData) || state.orgs.find((o) => o.access);
  if (!r.org || !state.orgs.some((o) => o.id === r.org && o.access)) { if (first) go(first.id, "overview"); return; }
  if (r.view === "investors" && state.user.role === "investor") { go(r.org, "overview"); return; }
  renderSide(r);
  $("#side").classList.remove("open");
  const org = state.orgs.find((o) => o.id === r.org);
  const trail = []; let p = org; while (p) { trail.unshift(p.access ? { label: p.name, href: `#/${p.id}/overview` } : p.name); p = state.orgs.find((x) => x.id === p.parent); }
  const viewName = { overview: "Overview", events: "Events", investors: "Investors", chart: "Org chart" }[r.view] || "Overview";
  crumbs([...trail, viewName]);
  const view = $("#view");
  try {
    if (r.view === "capitalize" && org.canFound && !STATIC) { crumbs([...trail, "Initial capitalization"]); return drawOrgForm(view, org); }
    if (r.view === "chart") return await renderChart(view, r);
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
      <p><b>No events recorded${kids.length ? " at this level" : ""}.</b><br>${kids.length ? "Ownership is tracked in the sub-organizations above." : "Record the initial capitalization to begin."}</p>
      ${!kids.length && org.canFound && !STATIC ? `<a class="btn primary" href="#/${org.id}/capitalize">Enter the starting positions</a>` : ""}
    </div>`;
}

// ---------- org chart: every organization this user can see, as one diagram ----------
async function renderChart(view, r) {
  // only the selected organization's family: climb to the highest level above it this user may open,
  // then draw that branch (organizations the user can't open are left out)
  let top = state.orgs.find((o) => o.id === r.org);
  for (let p = state.orgs.find((x) => x.id === top.parent); p && p.access; p = state.orgs.find((x) => x.id === p.parent)) top = p;
  const inBranch = new Set();
  const collect = (o) => { if (!o.access) return; inBranch.add(o.id); state.orgs.filter((k) => k.parent === o.id).forEach(collect); };
  collect(top);
  const orgs = state.orgs.filter((o) => inBranch.has(o.id));
  const kidsOf = (id) => orgs.filter((o) => o.parent === id);
  const sums = {};
  await Promise.all(orgs.filter((o) => o.access && o.hasData).map(async (o) => {
    try { sums[o.id] = await api(`orgs/${o.id}/summary`); } catch { /* shown without figures */ }
  }));
  const NW = 232, NH = 104, GX = 26, GY = 58, PAD = 24;
  const width = {};
  const measure = (o) => {
    const k = kidsOf(o.id);
    width[o.id] = k.length ? Math.max(NW, k.reduce((a, c) => a + measure(c), 0) + GX * (k.length - 1)) : NW;
    return width[o.id];
  };
  const roots = [top];
  roots.forEach(measure);
  // each top-level group gets its own band, stacked down the page, so the chart stays narrow
  const pos = {};
  let depthMax = 0;
  const place = (o, x0, y0, d) => {
    pos[o.id] = { x: x0 + width[o.id] / 2 - NW / 2, y: y0 + d * (NH + GY) };
    depthMax = Math.max(depthMax, d);
    let x = x0;
    kidsOf(o.id).forEach((k) => { place(k, x, y0, d + 1); x += width[k.id] + GX; });
  };
  let y = 0;
  roots.forEach((o) => { depthMax = 0; place(o, 0, y, 0); y += (depthMax + 1) * (NH + GY) + GY * 0.4; });
  const W = Math.max(NW, ...roots.map((o) => width[o.id])) + PAD * 2, H = y - GY * 1.4 + PAD * 2;

  const kind = (o) => entityTag(o) ? (entityTag(o) === "Trust" ? "Trust" : "LLC partner") : o.kind || "";
  const meta = (o) => {
    const s = sums[o.id];
    if (!o.access) return "Shown for context";
    if (!s || !s.asOfEventId) {
      const n = kidsOf(o.id).length;
      return n ? `Holds ${n} ${n === 1 ? "organization" : "organizations"}` : "No records yet";
    }
    return `${s.activeMembers ?? "—"} ${s.activeMembers === 1 ? "member" : "members"} · ${fmt(s.capital, "usd0")}`;
  };
  const lines = orgs.filter((o) => o.parent && pos[o.parent] && pos[o.id]).map((o) => {
    const p = pos[o.parent], c = pos[o.id];
    const x1 = PAD + p.x + NW / 2, y1 = PAD + p.y + NH, x2 = PAD + c.x + NW / 2, y2 = PAD + c.y, ym = y1 + GY / 2;
    return `<path d="M${x1} ${y1} V${ym} H${x2} V${y2}"/>`;
  }).join("");
  const nodes = orgs.filter((o) => pos[o.id]).map((o) => {
    const p = pos[o.id], tag = entityTag(o);
    return `<a class="oc-node ${o.access ? "" : "locked"} ${o.id === r.org ? "here" : ""} ${tag ? "ent" : ""}" style="left:${PAD + p.x}px;top:${PAD + p.y}px;width:${NW}px;height:${NH}px"
      ${o.access ? `href="#/${o.id}/overview"` : ""} title="${esc(o.name)}">
      <span class="oc-kind">${esc(kind(o))}${sums[o.id]?.stakeIn ? ` · ${fmt(sums[o.id].stakeIn.pct, "pct")} of parent` : ""}${o.access ? "" : " · 🔒"}</span>
      <span class="oc-name">${esc(o.name)}</span>
      <span class="oc-meta">${meta(o)}</span></a>`;
  }).join("");
  const count = orgs.length;
  view.innerHTML = `
    <h1>Organization chart</h1>
    <p class="sub">${esc(top.name)}${count > 1 ? ` and the ${count - 1} ${count === 2 ? "organization" : "organizations"} under it` : ""} · click any box to open it</p>
    <div class="oc-tools">
      <span class="oc-key"><i class="k-org"></i>Partnership or organization</span>
      <span class="oc-key"><i class="k-ent"></i>LLC or trust partner</span>
      <label class="toggle"><input type="checkbox" id="ocFit" ${state.ocFit !== false ? "checked" : ""}> Fit to width</label>
    </div>
    <div class="card oc-wrap" id="ocWrap"><div class="oc-size" id="ocSize"><div class="oc-stage" id="ocStage" style="width:${W}px;height:${H}px">
      <svg class="oc-lines" width="${W}" height="${H}" aria-hidden="true">${lines}</svg>${nodes}</div></div></div>`;
  // scale down only when the chart is wider than the card; the sizer keeps the scroll area matched to the scaled chart
  const fit = () => {
    const wrap = $("#ocWrap"), size = $("#ocSize"), stage = $("#ocStage");
    if (!wrap) return;
    const k = state.ocFit !== false ? Math.min(1, (wrap.clientWidth - 2) / W) : 1;
    stage.style.transform = `scale(${k})`;
    size.style.width = `${W * k}px`;
    size.style.height = `${H * k}px`;
  };
  $("#ocFit").onchange = (e) => { state.ocFit = e.target.checked; fit(); };
  fit();
  addEventListener("resize", fit, { once: true });
}

// ---------- overview ----------
// where this organization sits: its kind, and the levels above it
function levelLine(id) {
  const o = state.orgs.find((x) => x.id === id) || {};
  const up = []; for (let p = state.orgs.find((x) => x.id === o.parent); p; p = state.orgs.find((x) => x.id === p.parent)) up.unshift(p);
  const kind = entityTag(o) ? (entityTag(o) === "Trust" ? "Trust" : "LLC") + " partner" : o.kind || "";
  return `<div class="level"><span class="lvl-kind">${esc(kind)}</span>${up.length ? `<span class="lvl-path">within ${up.map((p) => p.access ? `<a href="#/${p.id}/overview">${esc(p.name)}</a>` : esc(p.name)).join(" › ")}</span>` : `<span class="lvl-path">top level</span>`}</div>`;
}
// the partnerships nested directly under this one, with the share each holds here
function subCards(id, owners) {
  const kids = kidsOf(id);
  if (!kids.length) return "";
  return `<div class="card subs"><div class="card-h"><h2>Sub-partnerships</h2><span class="muted">${kids.length} nested directly under this ${entityTag(state.orgs.find((o) => o.id === id) || {}) ? "entity" : "partnership"}</span></div>
    <div class="sub-grid">${kids.map((k) => {
      const own = k.entityOf ? owners.find((x) => x.name === k.entityOf.member) : null;
      const below = subtreeSize(k.id);
      return `<a class="sub-card" ${k.access ? `href="#/${k.id}/overview"` : ""}>
        <div class="sc-top">${entityTag(k) ? `<span class="otag light">${entityTag(k)}</span>` : `<span class="otag light">${esc(k.kind)}</span>`}${below ? `<span class="muted">${below} more nested below</span>` : ""}</div>
        <div class="sc-name">${esc(k.name)}</div>
        <div class="sc-meta">${own ? `${fmt(own.pct, "pct")} of this partnership · ${fmt(own.shares, "num")} shares` : k.hasData ? "Ledger active" : "No events yet"}</div></a>`;
    }).join("")}</div></div>`;
}

async function renderOverview(view, r) {
  const s = await api(`orgs/${r.org}/summary`);
  if (!s.asOfEventId) {
    view.innerHTML = `<h1>${esc(state.orgs.find((o) => o.id === r.org)?.name || "")}</h1>
      <div class="card empty" style="margin-top:18px"><p><b>Nothing is finalized yet.</b><br>The initial capitalization is still a draft.</p>
      <a class="btn primary" href="#/${r.org}/events">Review the draft</a></div>`;
    return;
  }
  const inv = state.user.role === "investor";
  // an LLC or trust has no distributions of its own: it receives them from the partnership above
  const via = s.stakeIn && !s.distributions.length ? s.stakeIn : null;
  if (via) s.distributions = via.distributions;
  const last = s.distributions[s.distributions.length - 1] || {};
  const tiles = inv ? `
      <div class="card kpi hero"><div class="l">Your shares</div><div class="v">${fmt(s.me.shares, "num")}</div><div class="s">${fmt(s.me.pct, "pct")} of the partnership</div></div>
      <div class="card kpi"><div class="l">Your capital account</div><div class="v">${fmt(s.me.investment, "usd0")}</div><div class="s">as of ${esc(fmtSheetDate(s.asOf))}</div></div>
      <div class="card kpi"><div class="l">Lifetime distributions</div><div class="v">${fmt(s.me.lifetime, "usd0")}</div><div class="s">${s.distributions.filter((d) => d.mine).length} years paid</div></div>
      <div class="card kpi"><div class="l">${last.year || ""} distribution</div><div class="v">${fmt(last.mine, "usd0")}</div><div class="s">Partnership ROI ${fmt(last.roi, "pct")}</div></div>`
    : `
      <div class="card kpi hero"><div class="l">${via ? "Members' contributions" : "Committed capital"}</div><div class="v">${fmt(s.capital, "usd0")}</div><div class="s">${via ? "the ratios that split what it receives" : "held constant across every admission &amp; exit"}</div></div>
      <div class="card kpi"><div class="l">Shares outstanding</div><div class="v">${fmt(s.shares, "num")}</div><div class="s">$10,000 par</div></div>
      <div class="card kpi"><div class="l">Active members</div><div class="v">${s.activeMembers}</div><div class="s">as of ${esc(fmtSheetDate(s.asOf))}</div></div>
      ${via ? `
      <div class="card kpi"><div class="l">${last.year || ""} received</div><div class="v">${fmt(last.amount, "usd0")}</div><div class="s">from ${esc(via.orgName)}</div></div>
      <div class="card kpi"><div class="l">Received since ${s.distributions[0]?.year || ""}</div><div class="v">${fmt(s.distributions.reduce((a, d) => a + d.amount, 0), "usd0")}</div><div class="s">passed through to its members</div></div>` : `
      <div class="card kpi"><div class="l">${last.year || ""} distribution</div><div class="v">${fmt(last.amount, "usd0")}</div><div class="s">ROI ${fmt(last.roi, "pct")} · ${fmt(last.perShareMonth, "usd")}/share-month</div></div>
      <div class="card kpi"><div class="l">Distributed since ${s.distributions[0]?.year || ""}</div><div class="v">${fmt(s.lifetimeDistributed, "usd0")}</div><div class="s">${s.distributions.length} annual distributions</div></div>`}`;

  const right = inv ? `
    <div class="card"><div class="card-h"><h2>Your recent events</h2></div><div class="card-b list">
      ${s.recent.map((e) => `<a class="li" href="#/${r.org}/events/${e.id}"><div><div class="t">${esc(e.title)}</div><div class="d">${fmtIso(e.date)}</div></div><div class="r">${chip(e.type)}</div></a>`).join("")}
    </div></div>`
    : `
    <div class="card"><div class="card-h"><h2>Current ownership</h2><span class="muted">${esc(s.asOfTitle)}</span></div>
      <div class="card-b own">${ownershipBars(s.owners)}</div></div>`;

  view.innerHTML = `
    <h1>${inv ? "Welcome back, " + esc(shortName(s.me.name).split(" ")[0]) : esc(state.orgs.find((o) => o.id === r.org)?.name || "Partnership overview")}</h1>
    ${inv ? "" : levelLine(r.org)}
 ${s.stakeIn ? `<p class="stake">Partner in <a href="#/${s.stakeIn.org}/overview">${esc(s.stakeIn.orgName)}</a>: ${fmt(s.stakeIn.shares, "num")} shares · ${fmt(s.stakeIn.investment, "usd0")} capital · ${fmt(s.stakeIn.pct, "pct")} of the partnership, as of ${esc(fmtIso(s.stakeIn.asOf))}. Its members' split is recorded here.</p>` : ""}
    <p class="sub">${inv ? "Your position in " + esc(state.orgs.find((o) => o.id === r.org)?.name || "this partnership") : `${s.eventsRecorded} events recorded · latest: <a href="#/${r.org}/events/${s.asOfEventId}" style="color:var(--accent-ink)">${esc(s.asOfTitle)}</a>`}</p>
    <div class="kpis">${tiles}</div>
    ${inv ? "" : subCards(r.org, s.owners || [])}
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
    tip: via ? `<b>${d.year}</b>Received from ${esc(via.orgName)}: ${fmt(d.amount, "usd0")}`
             : `<b>${d.year} distribution</b>${inv ? `Your share: ${fmt(d.mine, "usd0")}<br>` : ""}Partnership: ${fmt(d.amount, "usd0")}<br>ROI ${fmt(d.roi, "pct")}`,
  })), (d) => go(via ? via.org : r.org, "events", d.id));
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
    // the full-height hit area sits on top of the bar so the whole column (bar included) responds
    s += `<g class="col"><path class="bar" d="M${x},${yy + h} V${yy + r} Q${x},${yy} ${x + r},${yy} H${x + w - r} Q${x + w},${yy} ${x + w},${yy + r} V${yy + h} Z"/>`;
    s += `<rect class="hit" data-i="${i}" x="${m.l + i * bw}" y="${m.t}" width="${bw}" height="${ih}"/></g>`;
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

// ---------- nested partners ----------
// members behind an LLC/trust partner arrive flattened in tree order; each knows its fraction of the
// top-level partner and who holds it directly ("via")
function nestInfo(top, members) {
  const frac = Object.fromEntries(members.map((m) => [m.key || m.memberId, m.fraction]));
  const name = Object.fromEntries(members.map((m) => [m.key || m.memberId, m.name]));
  return members.map((m) => {
    const parentFrac = m.via && m.via !== top.key && m.via !== top.memberId ? frac[m.via] : 1;
    return { ...m, ofParent: parentFrac ? m.fraction / parentFrac : 0, parentName: m.via && name[m.via] ? name[m.via] : top.name, gone: !m.fraction };
  });
}
const peopleCount = (members) => members.filter((m) => !(m.entity ?? m.isEntity) && m.fraction > 0).length;

// ---------- events ----------
const TYPES = ["All", "Distribution", "Admission", "Retirement", "Capital Call", "Scenario"];
// creating events needs the live server and an admin role; the review snapshot is read-only
// the review snapshot shows the form so it can be reviewed, but nothing can be calculated or saved there
const canDraft = () => ["org_admin", "platform_admin"].includes(state.user.role);
const canWrite = () => !STATIC && ["org_admin", "platform_admin"].includes(state.user.role);

async function post(path, body) {
  const r = await fetch("/api/" + path, { method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Demo-User": state.persona }, body: JSON.stringify(body || {}) });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) showLogin();
  if (!r.ok) throw Object.assign(new Error(j.error || "Request failed"), { status: r.status });
  return j;
}

async function renderEvents(view, r) {
  if (state.eventsOrg !== r.org || !state.events) { state.events = await api(`orgs/${r.org}/events`); state.eventsOrg = r.org; }
  const evs = state.events;
  if (!r.id) {
    const pick = evs.find((e) => e.status === "Draft") || [...evs].reverse().find((e) => e.status === "Final") || evs[0];
    if (pick) { history.replaceState(null, "", `#/${r.org}/events/${pick.id}`); r.id = pick.id; }
  }
  if (r.id === "new") return canDraft() ? drawEventPage(view, r) : go(r.org, "events");
  if (!$(".events", view)) {
    view.innerHTML = `<div class="events">
      <div class="card timeline">
        <div class="tl-filters">
          ${canDraft() ? `<a class="btn primary new-event" href="#/${r.org}/events/new">+ New event</a>` : ""}
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
  const ne = $(".new-event", view); if (ne) ne.href = `#/${r.org}/events/new`;
  drawTimeline(r);
  await drawReport(r);
}

// ---------- new event (its own page) ----------
const blankForm = () => ({ kind: "", date: "", scenario: false, joiners: [{ name: "", units: 1 }], devSells: true,
  leavers: [""], how: "", to: "all", buyer: "", newcomer: "", units: {}, cash: "", capital: "", callJoiners: [] });
const money = (t) => { const n = Number(String(t).replace(/[$,\s]/g, "")); return Number.isFinite(n) ? n : NaN; };
const posText = (u) => String(+Number(u || 0).toFixed(4));
// kinds of event that change who the partners are: dated on the 1st of a month only
const MOVES = ["admission", "retirement", "retire_admit"];
const KINDS = [
  ["admission", "Admit partners", "New partners buy in. Existing partners sell down so total capital stays the same.",
    "M8 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-6 8c0-3 2.7-5 6-5s6 2 6 5zM15 5h2v3h3v2h-3v3h-2v-3h-3V8h3z"],
  ["retirement", "Retire partners", "Partners are paid out at par. Their shares go to the remaining partners or to one of them.",
    "M8 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-6 8c0-3 2.7-5 6-5s6 2 6 5zM12 8h8v2h-8z"],
  ["retire_admit", "Retire and admit", "Partners leave and new partners or an entity come in on the same date, as one event.",
    "M6 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-5 8c0-3 2.2-5 5-5s5 2 5 5zM15 3l4 3-4 3V7h-4V5h4zm-1 8v2h4v2h-4v2l-4-3z"],
  ["restructure", "Change positions", "Resize one or more partners' positions. Everyone else adjusts in proportion.",
    "M3 5h9V2l5 4-5 4V7H3zm14 10H8v3l-5-4 5-4v3h9z"],
  ["distribution", "Pay a distribution", "Cash is paid to the current partners in proportion to their shares. Positions don't change.",
    "M2 5h16v10H2zm8 2.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z"],
  ["capital_call", "Capital call", "Partners contribute new capital in proportion to their positions. This raises the capital base.",
    "M3 17h14v-2H3zm6-4h2V7h3l-4-5-4 5h3z"],
];

async function drawEventPage(view, r) {
  const [inv, sum] = await Promise.all([api(`orgs/${r.org}/investors`), api(`orgs/${r.org}/summary`)]);
  const members = inv.filter((m) => m.status === "Active").sort((a, b) => a.name.localeCompare(b.name));
  const org = state.orgs.find((o) => o.id === r.org) || {};
  if (!members.length) {
    view.innerHTML = `<div class="card empty"><p><b>${esc(org.name || "This organization")} has no partners on record yet.</b><br>Events can be recorded once its initial capitalization is finalized.</p>
      <a class="btn" href="#/${r.org}/events">Back to events</a></div>`;
    return;
  }
  const total = members.reduce((a, m) => a + m.shares, 0);
  view.innerHTML = `<div class="ev-new">
    <div class="card" id="report"></div>
    <aside class="card roster">
      <h3>Partners today</h3>
      <div class="muted">${esc(org.name || "")}${sum.asOf ? ` · as of ${esc(fmtSheetDate(sum.asOf))}` : ""}</div>
      <div class="roster-kpi"><div><span>Capital</span><b>${fmt(sum.capital, "usd0")}</b></div><div><span>Shares</span><b>${fmt(total, "num")}</b></div></div>
      <table><tbody>${[...members].sort((a, b) => b.shares - a.shares).map((m) => `<tr><td>${esc(shortName(m.name))}</td><td>${fmt(m.shares, "num")}</td><td>${fmt(m.shares / total, "pct")}</td></tr>`).join("")}</tbody></table>
    </aside></div>`;
  drawEventForm(r, members);
}

function drawEventForm(r, members, error) {
  const box = $("#report");
  const latest = state.events.filter((e) => e.status === "Final" && e.date).map((e) => e.date).sort().pop() || "";
  const f = state.form || (state.form = blankForm());
  const again = (err) => drawEventForm(r, members, err);
  const opt = (sel, skip = []) => `<option value="">Choose a partner…</option>` + members.filter((m) => m.key === sel || !skip.includes(m.key))
    .map((m) => `<option value="${m.key}" ${m.key === sel ? "selected" : ""}>${esc(m.name)} — ${fmt(m.shares, "num")} shares</option>`).join("");
  const step = (n, t) => `<h2 class="step"><i>${n}</i>${t}</h2>`;

  const joinerRows = (sizes, ph = "Last, First, M.D.") => `
      <label class="fl">New partner(s)</label>
      <div id="joiners">${f.joiners.map((j, i) => `<div class="jrow">
        <input class="fi jn" data-i="${i}" placeholder="${ph}" value="${esc(j.name)}" required>
        ${sizes ? `<select class="fi ju" data-i="${i}" aria-label="Position size">
          <option value="1" ${+j.units === 1 ? "selected" : ""}>Full position</option>
          <option value="0.5" ${+j.units === 0.5 ? "selected" : ""}>Half position</option>
          <option value="0.3333333333" ${Math.abs(j.units - 1 / 3) < 0.001 ? "selected" : ""}>One-third position</option>
        </select>` : ""}
        ${f.joiners.length > 1 ? `<button type="button" class="btn x" data-list="joiners" data-i="${i}" aria-label="Remove">×</button>` : ""}</div>`).join("")}</div>
      <button type="button" class="btn add" data-add="joiners">+ Add another</button>`;
  const devToggle = () => `
      <label class="toggle fl2"><input type="checkbox" id="devSells" ${f.devSells ? "checked" : ""}> The developer sells down along with the physicians</label>
      <div class="hint">Checked: everyone sells down in proportion. Unchecked: only the physicians sell down.</div>`;
  const leaverRows = () => `
      <label class="fl">Retiring partner(s)</label>
      <div>${f.leavers.map((k, i) => `<div class="jrow">
        <select class="fi lv" data-i="${i}" required>${opt(k, f.leavers)}</select>
        ${f.leavers.length > 1 ? `<button type="button" class="btn x" data-list="leavers" data-i="${i}" aria-label="Remove">×</button>` : ""}</div>`).join("")}</div>
      <button type="button" class="btn add" data-add="leavers">+ Add another</button>
      <div class="hint">Each is paid their capital at par and keeps the share-months earned so far.</div>`;
  // one-for-one by default; uneven numbers (two out, one in) can only be a re-split
  const how = () => f.how || (f.joiners.length === f.leavers.length ? "takeover" : "resplit");

  const details = {
    admission: () => joinerRows(true) + devToggle(),
    retire_admit: () => `${leaverRows()}${joinerRows(how() === "resplit", "Last, First, M.D. or entity name")}
      <label class="fl">How do the shares move?</label>
      <div class="choices">
        <label class="toggle"><input type="radio" name="how" value="takeover" ${how() === "takeover" ? "checked" : ""}> <span>The new partners take over the retiring partners' shares exactly. Nobody else changes.</span></label>
        <label class="toggle"><input type="radio" name="how" value="resplit" ${how() === "resplit" ? "checked" : ""}> <span>Re-split. The retiring partners are paid out, the new partners buy in at their own position size, and everyone else adjusts.</span></label>
      </div>
      ${how() === "resplit" ? devToggle() : `<div class="hint">With equal numbers, each new partner takes the position of the retiring partner on the same row. A single new partner or entity takes them all.</div>`}`,
    retirement: () => `${leaverRows()}
      <label class="fl">Who takes the shares?</label>
      <div class="choices">
        <label class="toggle"><input type="radio" name="to" value="all" ${f.to === "all" ? "checked" : ""}> All remaining partners, in proportion to what they hold</label>
        <label class="toggle"><input type="radio" name="to" value="buyer" ${f.to === "buyer" ? "checked" : ""}> One current partner buys them</label>
        ${f.to === "buyer" ? `<select class="fi sub" id="buyer" required>${opt(f.buyer, f.leavers)}</select>` : ""}
      </div>`,
    restructure: () => `
      <label class="fl">Position sizes</label>
      <div class="pos-head"><span>Partner</span><span>Shares now</span><span>Position</span></div>
      ${members.map((m) => { const cur = posText(m.units), v = f.units[m.key] ?? cur; return `<div class="pos-row ${v !== cur ? "chg" : ""}">
        <span>${esc(m.name)}</span><span>${fmt(m.shares, "num")}</span>
        <input class="fi pu" data-k="${m.key}" data-cur="${cur}" inputmode="decimal" value="${esc(v)}" aria-label="Position for ${esc(m.name)}"></div>`; }).join("")}
      <div class="hint">1 = one full physician position. Change only the partners whose position is changing; total capital stays the same and everyone else adjusts in proportion.</div>`,
    distribution: () => `
      <label class="fl" for="cash">Cash to distribute</label>
      <input class="fi" id="cash" inputmode="decimal" placeholder="$0.00" value="${esc(f.cash)}" required>
      <div class="hint">Paid to partners holding shares on the effective date. Retired partners are not paid; their share-months stay on record for a sale.</div>`,
    capital_call: () => `
      <label class="fl" for="capital">Additional capital required</label>
      <input class="fi" id="capital" inputmode="decimal" placeholder="$0.00" value="${esc(f.capital)}" required>
      <div class="hint">Each partner contributes in proportion to their position and receives new shares at par.</div>
      <label class="fl">New partners joining with this call (optional)</label>
      <div>${f.callJoiners.map((j, i) => `<div class="jrow">
        <input class="fi cjn" data-i="${i}" placeholder="Last, First, M.D." value="${esc(j.name)}" required>
        <button type="button" class="btn x" data-list="callJoiners" data-i="${i}" aria-label="Remove">×</button></div>`).join("")}</div>
      <button type="button" class="btn add" data-add="callJoiners">+ Add a new partner</button>
      <div class="hint">A partner who joins here pays one physician's share of the call only, so holds a partial position afterwards.</div>`,
  };

  box.innerHTML = `
    <form class="ev-form" id="evForm">
      <div class="rep-meta"><a href="#/${r.org}/events">← Events</a><span>·</span><span>${STATIC ? "Review copy: you can try the form, but previewing and saving need the live app." : "Nothing is recorded until you finalize."}</span></div>
      <h1>New event</h1>
      ${step(1, "What happened?")}
      <div class="kinds">${KINDS.map(([k, t, d, icon]) => `<label class="kind ${f.kind === k ? "on" : ""}"><input type="radio" name="kind" value="${k}" ${f.kind === k ? "checked" : ""}>
        <svg viewBox="0 0 20 20"><path fill-rule="evenodd" d="${icon}"/></svg><b>${t}</b><span>${d}</span></label>`).join("")}</div>
      ${f.kind ? `
        ${step(2, "When?")}
        <label class="fl" for="evDate">Effective date</label>
        <input class="fi date" type="date" id="evDate" required value="${esc(f.date)}" ${latest ? `min="${latest}"` : ""}>
        <div class="hint">${MOVES.includes(f.kind) ? "<b>Admissions and retirements take effect on the 1st of a month.</b> " : ""}${latest ? `On or after the latest recorded event (${fmtIso(latest)}). ` : ""}${f.kind === "distribution" ? "" : "Share-months are counted from this date."}</div>
        ${step(3, "Details")}
        ${details[f.kind]()}
        <label class="toggle whatif"><input type="checkbox" id="scenario" ${f.scenario ? "checked" : ""}> <span><b>What-if only.</b> Save as a scenario for comparison; it never becomes part of the record.</span></label>
        <div class="login-err" id="evErr" role="alert">${esc(error || "")}</div>
        <div class="btns"><button class="btn primary" type="submit" id="evGo">Preview the result</button><a class="btn" href="#/${r.org}/events" id="evCancel">Cancel</a></div>`
      : `<div class="hint">Choose the kind of event to continue.</div>`}
    </form>`;

  const read = () => {
    const v = (id) => $("#" + id);
    if (v("evDate")) f.date = v("evDate").value;
    if (v("scenario")) f.scenario = v("scenario").checked;
    box.querySelectorAll(".jn").forEach((el) => (f.joiners[+el.dataset.i].name = el.value));
    box.querySelectorAll(".ju").forEach((el) => (f.joiners[+el.dataset.i].units = +el.value));
    box.querySelectorAll(".lv").forEach((el) => (f.leavers[+el.dataset.i] = el.value));
    box.querySelectorAll(".cjn").forEach((el) => (f.callJoiners[+el.dataset.i].name = el.value));
    box.querySelectorAll(".pu").forEach((el) => { if (el.value.trim() === el.dataset.cur) delete f.units[el.dataset.k]; else f.units[el.dataset.k] = el.value.trim(); });
    if (v("devSells")) f.devSells = v("devSells").checked;
    if (v("buyer")) f.buyer = v("buyer").value;
    if (v("newcomer")) f.newcomer = v("newcomer").value;
    const to = box.querySelector("input[name=to]:checked"); if (to) f.to = to.value;
    if (f.to === "new") f.to = "all";
    if (v("cash")) f.cash = v("cash").value;
    if (v("capital")) f.capital = v("capital").value;
  };
  const blank = { joiners: () => ({ name: "", units: 1 }), leavers: () => "", callJoiners: () => ({ name: "" }) };
  box.querySelectorAll("input[name=kind]").forEach((el) => (el.onchange = () => { read(); f.kind = el.value; again(); }));
  box.querySelectorAll("input[name=to], .lv").forEach((el) => (el.onchange = () => { read(); again(); }));
  box.querySelectorAll("input[name=how]").forEach((el) => (el.onchange = () => { read(); f.how = el.value; again(); }));
  box.querySelectorAll(".add").forEach((el) => (el.onclick = () => { read(); f[el.dataset.add].push(blank[el.dataset.add]()); again(); }));
  box.querySelectorAll(".x").forEach((el) => (el.onclick = () => { read(); f[el.dataset.list].splice(+el.dataset.i, 1); again(); }));
  box.querySelectorAll(".pu").forEach((el) => (el.oninput = () => el.closest(".pos-row").classList.toggle("chg", el.value.trim() !== el.dataset.cur)));
  const cancel = $("#evCancel"); if (cancel) cancel.onclick = () => { state.form = null; };

  $("#evForm").onsubmit = async (ev) => {
    ev.preventDefault(); read();
    if (STATIC) return again("This review copy is read-only. The result is calculated in the live app.");
    if (MOVES.includes(f.kind) && f.date && !f.date.endsWith("-01")) {
      const [y, mo] = f.date.split("-").map(Number), next = `${mo === 12 ? y + 1 : y}-${String(mo === 12 ? 1 : mo + 1).padStart(2, "0")}-01`;
      return again(`Admissions and retirements take effect on the first of a month. Use ${fmtIso(next)} instead of ${fmtIso(f.date)}.`);
    }
    const nameOf = (k) => shortName(members.find((m) => m.key === k)?.name || "");
    let body;
    if (f.kind === "admission") {
      const js = f.joiners.map((j) => ({ name: j.name.trim(), units: j.units })).filter((j) => j.name);
      body = { type: "admission", title: "Admit " + js.map((j) => shortName(j.name)).join(", "), inputs: { joiners: js, developer_sells_down: f.devSells } };
    } else if (f.kind === "retirement") {
      const ls = f.leavers.filter(Boolean), who = ls.map(nameOf).join(", ");
      if (new Set(ls).size !== ls.length) return again("The same partner is listed twice.");
      if (f.to === "all" && ls.length >= members.length) return again("Someone has to remain to take the shares. Choose a buyer, or use Retire and admit.");
      if (f.to === "buyer" && ls.includes(f.buyer)) return again("The buyer can't be one of the retiring partners.");
      body = { type: "retirement", title: "Retire " + who,
               inputs: { leavers: ls.map((id) => ({ memberId: id, ...(f.to === "buyer" ? { buyer: { memberId: f.buyer } } : {}) })) } };
    } else if (f.kind === "retire_admit") {
      const ls = f.leavers.filter(Boolean), js = f.joiners.map((j) => ({ name: j.name.trim(), units: j.units })).filter((j) => j.name);
      if (new Set(ls).size !== ls.length) return again("The same partner is listed twice.");
      let inputs;
      if (how() === "resplit") inputs = { leavers: ls.map((id) => ({ memberId: id })), joiners: js, developer_sells_down: f.devSells };
      else if (js.length === ls.length) inputs = { replacements: ls.map((id, i) => ({ leaver: { memberId: id }, joiner: { name: js[i].name } })) };
      else if (js.length === 1) inputs = { leavers: ls.map((id) => ({ memberId: id, buyer: { name: js[0].name } })) };
      else return again("For an exact takeover, list one new partner per retiring partner, or a single new partner or entity. Otherwise choose Re-split.");
      body = { type: "retire_admit", title: `Retire ${ls.map(nameOf).join(", ")}; admit ${js.map((j) => shortName(j.name)).join(", ")}`, inputs };
    } else if (f.kind === "restructure") {
      const ch = Object.entries(f.units).map(([k, t]) => ({ memberId: k, units: Number(t) }));
      if (!ch.length) return again("Change at least one partner's position.");
      if (ch.some((c) => !(c.units > 0))) return again("A position must be a number greater than zero. To remove a partner, record a retirement.");
      body = { type: "restructure", title: "Change positions: " + ch.map((c) => nameOf(c.memberId)).join(", "), inputs: { units: ch } };
    } else if (f.kind === "distribution") {
      const cash = money(f.cash);
      if (!(cash > 0)) return again("Enter the cash to distribute as a dollar amount.");
      body = { type: "distribution", title: `${(f.date || "").slice(0, 4)} Distributions`, inputs: { cash_to_distribute: cash } };
    } else {
      const cap = money(f.capital);
      if (!(cap > 0)) return again("Enter the additional capital as a dollar amount.");
      const js = f.callJoiners.map((j) => ({ name: j.name.trim(), units: 1 })).filter((j) => j.name);
      body = { type: "capital_call", title: `Capital call — ${usd0.format(cap)}`, inputs: { additional_capital: cap, joiners: js } };
    }
    body.date = f.date; body.scenario = f.scenario;
    if (f.scenario) body.title = "What if: " + body.title;
    const btn = $("#evGo"); btn.disabled = true; btn.textContent = "Calculating…";
    try {
      const out = await post(`orgs/${r.org}/events`, body);
      state.events = null;
      if (f.scenario) { state.form = null; state.filter.scenarios = true; }
      go(r.org, "events", out.id);
    } catch (e) { again(e.message); }
  };
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
  const list = state.events.filter((e) => (f.scenarios || e.status === "Final" || e.status === "Draft" || e.id === r.id) && typeMatch(e, f.type)
    && (!q || `${e.title} ${e.sheet} ${e.asOf}`.toLowerCase().includes(q)));
  const groups = {};
  [...list].reverse().forEach((e) => { const y = e.status === "Draft" ? "Drafts" : e.status === "Scenario" ? "Scenarios & analyses" : (e.date || "").slice(0, 4) || "Undated"; (groups[y] = groups[y] || []).push(e); });
  const rank = (k) => (k === "Drafts" ? 0 : k.startsWith("S") ? 2 : 1);
  const keys = Object.keys(groups).sort((a, b) => rank(a) - rank(b) || b.localeCompare(a));
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
  if (state.stmt === e.id) return drawStatements(e, r);
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
  const open = state.expanded || (state.expanded = {});
  const subRows = (row) => !row.members || !open[row.key] ? "" : nestInfo(row, row.members)
    .filter((m) => !(f.hideExited && m.gone))
    .map((m) => `<tr class="sub ${m.gone ? "exited" : ""}"><td class="l sticky"><span class="idx"></span><span class="nest" style="padding-left:${(m.depth - 1) * 16}px">↳ ${esc(m.name)}</span>
      <span class="of">${m.gone ? "left" : `${fmt(m.ofParent, "pct")} of ${esc(shortName(m.parentName))}`}</span></td>${cols.map((col) => td(col, m.values[col.id])).join("")}</tr>`).join("");
  const body = rows.map((row, i) => `<tr class="${isExited(row) ? "exited" : ""}${row.members ? " has-sub" : ""}"><td class="l sticky"><span class="idx">${i + 1}</span>${esc(row.name)}${row.members ? `
      <button class="lt" data-k="${esc(row.key)}" aria-expanded="${!!open[row.key]}">${open[row.key] ? "▾" : "▸"} ${peopleCount(row.members)} people</button>` : ""}</td>${cols.map((col) => td(col, row.values[col.id])).join("")}</tr>${subRows(row)}`).join("");
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
        <div class="rep-meta">${chip(e.type, e.status)}<span>As of ${esc(e.asOf || "—")}</span>${e.sheet && e.sheet !== e.title ? `<span>·</span><span>Source tab “${esc(e.sheet)}”</span>` : ""}${e.status !== "Final" ? `<span>·</span><b>${esc(e.status)}</b>` : ""}</div>
        <h1>${esc(e.title)}</h1>
      </div>
      <div class="btns">
        ${state.expanded_report ? `<button class="btn x-close" id="unexpand" aria-label="Close the expanded view" title="Close (Esc)">×</button>`
          : `<button class="btn" id="expand" title="Open the numbers full-screen"><svg viewBox="0 0 20 20"><path d="M3 3h6v2H5v4H3zm8 0h6v6h-2V5h-4zM3 11h2v4h4v2H3zm12 0h2v6h-6v-2h4z"/></svg>Expand</button>`}
        <button class="btn" id="stmts"><svg viewBox="0 0 20 20"><path d="M5 2h8l3 3v13H5zm2 6v2h7V8zm0 4v2h7v-2z"/></svg>Statements</button>
        <button class="btn" id="csv"><svg viewBox="0 0 20 20"><path d="M9 3h2v8l3-3 1.4 1.4L10 14.8 4.6 9.4 6 8l3 3zM4 16h12v2H4z"/></svg>CSV</button>
        <button class="btn" onclick="print()"><svg viewBox="0 0 20 20"><path d="M5 2h10v4H5zm-2 5h14a1 1 0 0 1 1 1v6h-3v4H5v-4H2V8a1 1 0 0 1 1-1zm4 7v2h6v-2z"/></svg>PDF</button>
      </div>
    </div>
    ${e.status === "Draft" ? `<div class="draft-bar">
      <div><b>Draft — not part of the official record yet.</b>
        <span class="${e.check && e.check.ok ? "ok" : "bad"}">${!(e.check && e.check.ok) ? "✗ Total shares would change — this draft can't be finalized."
          : e.check.new_epoch ? `✓ New capital base: ${fmt(e.check.capital, "usd0")} · ${fmt(e.check.shares, "num")} shares.`
          : e.rawType === "distribution" ? `✓ ${fmt(e.totals.ds, "usd")} paid out; positions are unchanged.` : "✓ Total capital and shares are unchanged."}</span>
        Review each partner's before and after below.</div>
      ${canWrite() ? `<div class="btns"><button class="btn primary" id="fin" ${e.check && e.check.ok ? "" : "disabled"}>Finalize</button><button class="btn" id="edit">Change inputs</button><button class="btn" id="disc">Discard</button></div>` : ""}
      <div class="login-err" id="draftErr" role="alert"></div></div>` : ""}
    ${e.status === "Scenario" && e.inputs && canWrite() ? `<div class="draft-bar">
      <div><b>What-if scenario — not part of the official record.</b> It shows what this event would do to the partnership as it stood when the scenario was saved.</div>
      <div class="btns"><button class="btn" id="disc">Delete scenario</button></div>
      <div class="login-err" id="draftErr" role="alert"></div></div>` : ""}
    ${e.scoped ? `<div class="lock-note" style="margin:8px 22px 0"><svg viewBox="0 0 20 20"><path d="M10 1l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V4z"/></svg>Showing your line and partnership totals only. Other members' positions are not sent to your browser.</div>` : ""}
    ${e.fromEvent ? `<div class="flow-from">${esc(state.orgs.find((o) => o.id === r.org)?.name || "")}'s share of <a href="#/${e.fromEvent.org}/events/${e.fromEvent.id}">${esc(e.fromEvent.orgName)}'s ${esc((e.date || "").slice(0, 4))} distribution</a>, split among its members.</div>` : ""}
    ${e.flowsTo && e.flowsTo.length ? `<div class="flow"><h3>Where the cash went</h3>
      <div class="fl-row top"><b>${esc(state.orgs.find((o) => o.id === r.org)?.name || "")}</b><span>${fmt(e.totals.ds, "usd")}</span><em>to ${e.rows.filter((x) => x.values.ds).length} partners</em></div>
      ${e.flowsTo.map((x) => `<div class="fl-row" style="padding-left:${x.depth * 22}px"><span class="tw">└</span><a href="#/${x.org}/events/${x.eventId}">${esc(x.orgName)}</a><span>${fmt(x.amount, "usd")}</span><em>to ${x.members} members</em></div>`).join("")}
      <div class="hint">Each LLC and trust records the same distribution in its own books, split by its members' ratios. Every level adds up to the cent.</div></div>` : ""}
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

  $("#stmts").onclick = () => { state.stmt = e.id; drawReport(r); };
  // full-screen view of the numbers; × or Esc returns to the normal layout
  const setExpanded = (on) => {
    state.expanded_report = on;
    $("#report").classList.toggle("expanded", on);
    document.body.classList.toggle("report-open", on);
    drawReport(r);
  };
  $("#report").classList.toggle("expanded", !!state.expanded_report);
  document.body.classList.toggle("report-open", !!state.expanded_report);
  const ex = $("#expand"); if (ex) ex.onclick = () => setExpanded(true);
  const ux = $("#unexpand"); if (ux) { ux.onclick = () => setExpanded(false); ux.focus(); }
  document.onkeydown = (ev) => { if (ev.key === "Escape" && state.expanded_report && $("#report")) setExpanded(false); };
  $("#report").querySelectorAll(".lt").forEach((b) => (b.onclick = () => { open[b.dataset.k] = !open[b.dataset.k]; drawReport(r); }));
  const fin = $("#fin");
  if (fin) fin.onclick = async () => {
    if (!fin.dataset.armed) { fin.dataset.armed = 1; fin.textContent = "Confirm — this becomes permanent"; return; }
    fin.disabled = true;
    try { await post(`orgs/${r.org}/events/${e.id}/finalize`); state.events = null; state.form = null; state.capForm = null; state.orgs = await api("orgs"); render(); }
    catch (err) { $("#draftErr").textContent = err.message; fin.disabled = false; }
  };
  const drop = async (reopen) => {
    if (e.rawType === "capitalization") {
      try {
        if (reopen) state.capForm = { date: e.date, rows: ((e.inputs && e.inputs.members) || []).map((m) => ({ name: m.name, amount: String(m.amount), dev: !!m.isDeveloper })) };
        await post(`orgs/${r.org}/events/${e.id}/discard`); state.events = null; state.orgs = await api("orgs");
        location.hash = reopen ? `#/${r.org}/capitalize` : `#/${r.org}/overview`;
      } catch (err) { $("#draftErr").textContent = err.message; }
      return;
    }
    try { await post(`orgs/${r.org}/events/${e.id}/discard`); state.events = null; if (!reopen) state.form = null; go(r.org, "events", reopen ? "new" : null); }
    catch (err) { $("#draftErr").textContent = err.message; }
  };
  const ed = $("#edit"); if (ed) ed.onclick = () => drop(true);
  const dc = $("#disc"); if (dc) dc.onclick = () => drop(false);
  const hx = $("#hx"); if (hx) hx.onchange = () => { f.hideExited = hx.checked; drawReport(r); };
  const ac = $("#ac"); if (ac) ac.onchange = () => { f.allCols = ac.checked; drawReport(r); };
  const chm = $("#chm"); if (chm) chm.onclick = () => { $("#chl").innerHTML = ch.map((x) => `<li><b>${esc(shortName(x.name))}</b> — ${esc(x.note)}</li>`).join(""); chm.remove(); };
  $("#csv").onclick = () => downloadCsv(e, cols, rows);
}

// ---------- new organization + initial capitalization (superuser, or the customer who owns it) ----------
const blankCap = () => ({ name: "", kind: "partnership", parent: "", par: "10,000", date: "", rows: [{ name: "", amount: "", dev: false }, { name: "", amount: "", dev: false }, { name: "", amount: "", dev: false }] });

function drawOrgForm(view, org, error) {
  const f = state.capForm = { ...blankCap(), ...(state.capForm || {}) };
  if (!f.rows || !f.rows.length) f.rows = blankCap().rows;
  const par = org ? null : money(f.par);
  // a customer can nest a new organization only under one they own
  const parents = state.orgs.filter((o) => o.access && (state.user.superuser || o.canFound));
  view.innerHTML = `
    <form class="card ev-form org-form" id="orgForm">
      <div class="rep-meta"><span class="chip"><i></i>${org ? "Initial capitalization" : "New organization"}</span><span>Nothing is recorded as final until you review and finalize.</span></div>
      <h1>${org ? esc(org.name) : "Create an organization"}</h1>
      ${org && org.entityOf ? `<p class="hint">${esc(org.name)} is a partner in ${esc(state.orgs.find((o) => o.id === org.entityOf.org)?.name || "")}. Enter what each member put into it. Their ratios decide how its distributions, payouts and share-months pass through to them.</p>` : ""}
      ${org ? "" : `
        <label class="fl" for="oName">Organization name</label>
        <input class="fi" id="oName" required maxlength="120" placeholder="e.g. Riverside Building Partners, LLC" value="${esc(f.name)}">
        <div class="frow">
          <div><label class="fl" for="oKind">Type</label>
            <select class="fi" id="oKind">${[["partnership", "Partnership"], ["practice", "Practice"], ["holding", "Holding company"], ["sub_entity", "Sub-entity"]].map(([v, l]) => `<option value="${v}" ${f.kind === v ? "selected" : ""}>${l}</option>`).join("")}</select></div>
          <div><label class="fl" for="oParent">Part of (optional)</label>
            <select class="fi" id="oParent"><option value="">— a top-level organization —</option>${parents.map((o) => `<option value="${o.id}" ${f.parent === o.id ? "selected" : ""}>${esc(o.name)}</option>`).join("")}</select></div>
          <div><label class="fl" for="oPar">Par value per share</label>
            <input class="fi" id="oPar" inputmode="decimal" value="${esc(f.par)}" required></div>
        </div>`}

      <h2 class="fsec">Initial capitalization</h2>
      <label class="fl" for="oDate">Date funded</label>
      <input class="fi" type="date" id="oDate" required value="${esc(f.date)}">
      <div class="hint">Each investor's share-months start on this date.</div>

      <label class="fl">Investors and the amount each put in</label>
      <div class="cap-head"><span>Name</span><span>Amount invested</span><span>Developer</span><span></span></div>
      <div id="capRows">${f.rows.map((row, i) => `<div class="cap-row">
        <input class="fi cn" data-i="${i}" placeholder="Last, First, M.D." value="${esc(row.name)}" aria-label="Investor name">
        <input class="fi ca" data-i="${i}" inputmode="decimal" placeholder="$0" value="${esc(row.amount)}" aria-label="Amount invested">
        <label class="toggle" title="The developer holds a multiple of a physician's position"><input type="checkbox" class="cd" data-i="${i}" ${row.dev ? "checked" : ""}> Developer</label>
        <button type="button" class="btn cx" data-i="${i}" aria-label="Remove investor" ${f.rows.length > 1 ? "" : "disabled"}>×</button></div>`).join("")}</div>
      <div class="cap-actions"><button type="button" class="btn" id="capAdd">+ Add investor</button><button type="button" class="btn" id="capAdd5">+ Add 5 rows</button></div>
      <div class="cap-total" id="capTotal" aria-live="polite"></div>

      <div class="login-err" id="orgErr" role="alert">${esc(error || "")}</div>
      <div class="btns"><button class="btn primary" type="submit" id="orgGo">${org ? "Preview the capitalization" : "Create and preview"}</button>
        <a class="btn" href="#/${org ? org.id + "/overview" : ""}">Cancel</a></div>
    </form>`;

  const read = () => {
    if (!org) { f.name = $("#oName").value; f.kind = $("#oKind").value; f.parent = $("#oParent").value; f.par = $("#oPar").value; }
    f.date = $("#oDate").value;
    view.querySelectorAll(".cn").forEach((el) => (f.rows[+el.dataset.i].name = el.value));
    view.querySelectorAll(".ca").forEach((el) => (f.rows[+el.dataset.i].amount = el.value));
    view.querySelectorAll(".cd").forEach((el) => (f.rows[+el.dataset.i].dev = el.checked));
  };
  // a running tally of what has been typed; the official figures come back from the server's preview
  const tally = () => {
    read();
    const filled = f.rows.filter((x) => x.name.trim() && money(x.amount) > 0);
    const total = filled.reduce((a, x) => a + money(x.amount), 0);
    $("#capTotal").textContent = filled.length ? `${filled.length} investor${filled.length === 1 ? "" : "s"} entered · ${usd2.format(total)} total` : "";
  };
  view.querySelectorAll(".cn, .ca, .cd").forEach((el) => (el.oninput = tally));
  const add = (n) => { read(); for (let i = 0; i < n; i++) f.rows.push({ name: "", amount: "", dev: false }); drawOrgForm(view, org); };
  $("#capAdd").onclick = () => add(1);
  $("#capAdd5").onclick = () => add(5);
  view.querySelectorAll(".cx").forEach((el) => (el.onclick = () => { read(); f.rows.splice(+el.dataset.i, 1); drawOrgForm(view, org); }));
  tally();

  $("#orgForm").onsubmit = async (ev) => {
    ev.preventDefault(); read();
    const rows = f.rows.filter((x) => x.name.trim() || String(x.amount).trim());
    const bad = rows.find((x) => !x.name.trim() || !(money(x.amount) > 0));
    if (!rows.length) return drawOrgForm(view, org, "Enter at least one investor.");
    if (bad) return drawOrgForm(view, org, `Each investor needs a name and an amount${bad.name.trim() ? ` (check ${bad.name.trim()})` : ""}.`);
    if (!org && !(money(f.par) > 0)) return drawOrgForm(view, org, "Enter the par value per share.");
    const btn = $("#orgGo"); btn.disabled = true; btn.textContent = "Working…";
    let slug = org && org.id;
    try {
      if (!slug) {
        slug = (await post("orgs", { name: f.name.trim(), kind: f.kind, parent: f.parent || null, par: money(f.par) })).id;
        state.orgs = await api("orgs");
      }
      const out = await post(`orgs/${slug}/events`, { type: "capitalization", title: "Initial Capitalization", date: f.date,
        inputs: { members: rows.map((x) => ({ name: x.name.trim(), amount: money(x.amount), isDeveloper: x.dev })) } });
      state.orgs = await api("orgs"); state.events = null;
      go(slug, "events", out.id);
    } catch (e) {
      // the organization may already exist at this point: carry on in "capitalize" mode so nothing is created twice
      if (slug && !org) { state.capErr = e.message; location.hash = `#/${slug}/capitalize`; return; }
      drawOrgForm(view, org, e.message);
    }
  };
  if (state.capErr) { $("#orgErr").textContent = state.capErr; state.capErr = null; }
}

// ---------- per-partner statements (one printable page each) ----------
function drawStatements(e, r) {
  const org = state.orgs.find((o) => o.id === r.org);
  const has = (id) => e.columns.some((c) => c.id === id);
  const rows = e.rows.flatMap((row) => [row, ...(row.members ? nestInfo(row, row.members)
      .filter((m) => !m.entity && !m.gone).map((m) => ({ ...m, through: row.name })) : [])])
    .filter((row) => ["ps", "qs", "as", "ds"].some((id) => row.values[id]));
  const line = (label, value, strong) => (value === null || value === undefined || value === "" ? "" :
    `<tr class="${strong ? "strong" : ""}"><td>${label}</td><td>${value}</td></tr>`);
  const one = (row) => {
    const v = row.values, pre = v.ps || 0, post = v.qs ?? pre, delta = has("qs") ? post - pre : 0;
    const par = e.kpis.totalShares ? e.kpis.totalInvestment / e.kpis.totalShares : 10000;
    const moved = Math.abs(delta) > 0.00005;
    const verb = v.as ? "Capital contributed" : post === 0 && pre > 0 ? "Shares redeemed" : delta > 0 ? "Shares purchased" : "Shares sold";
    return `<section class="stmt">
      <header><div class="brandline">Fair<b>Share</b></div><div class="stmt-org">${esc(org ? org.name : "")}</div></header>
      <h2>Statement of account</h2>
      <div class="stmt-who">${esc(row.name)}</div>
      ${row.through ? `<div class="stmt-ev">Held through ${esc(row.through)}: ${fmt(row.fraction, "pct")} of its position${row.parentName !== row.through ? `, as ${fmt(row.ofParent, "pct")} of ${esc(row.parentName)}` : ""}</div>` : ""}
      <div class="stmt-ev">${esc(e.title)} · effective ${esc(fmtIso(e.date))}${e.status !== "Final" ? ` · <b>${esc(e.status.toUpperCase())} — not final</b>` : ""}</div>
      <table>
        ${has("ps") ? line("Shares before", fmt(pre, "num")) + line("Capital account before", fmt(v.pi ?? pre * par, "usd")) : ""}
        ${moved ? line(verb, `${fmt(Math.abs(delta), "num")} shares`) + line(delta > 0 ? "Amount you pay" : "Amount you receive", fmt(Math.abs(v.ai ?? delta * par), "usd"), true) : ""}
        ${has("qs") ? line("Shares after", fmt(post, "num"), true) + line("Capital account after", fmt(v.qi ?? post * par, "usd")) : ""}
        ${line("Ownership of the partnership", v.pc != null ? fmt(v.pc, "pct") : null)}
        ${v.ds ? line("Distribution paid to you", fmt(v.ds, "usd"), true) : ""}
        ${line("Loan guaranty", v.lg != null ? fmt(v.lg, "pct") : null)}
        ${line("Indemnity", v.in != null ? fmt(v.in, "pct") : null)}
        ${line("Share-months to date", v.sm != null ? fmt(v.sm, "num") : null)}
      </table>
      <footer>Shares are bought and sold at $10,000 par. Share-months accrue from your admission and determine your share of proceeds if the facility is sold.</footer>
    </section>`;
  };
  $("#report").innerHTML = `
    <div class="stmt-tools"><button class="btn" id="stBack">← Back to the event</button>
      <span class="muted">${rows.length} statement${rows.length === 1 ? "" : "s"} · one page each</span>
      <button class="btn primary" onclick="print()">Print / save as PDF</button></div>
    <div class="stmts">${rows.map(one).join("")}</div>`;
  $("#stBack").onclick = () => { state.stmt = null; drawReport(r); };
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
        <td><span class="avatar">${esc(initials(x.name))}</span>${esc(x.name)}${x.entityOrg ? ` <a class="lt" href="#/${x.entityOrg}/overview" onclick="event.stopPropagation()">${peopleCount(x.members || [])} people ›</a>` : ""}</td>
        <td>${esc(x.since ? fmtSheetDate(x.since) : "—")}</td>
        <td><span class="pill ${x.status.toLowerCase()}">${x.status}</span></td>
        <td class="r">${x.shares ? fmt(x.shares, "num") : "—"}</td>
        <td class="r">${x.investment ? fmt(x.investment, "usd0") : "—"}</td>
        <td class="r">${fmt(x.lifetime, "usd0")}</td>
        <td class="r">${x.events}</td></tr>${x.members ? nestInfo(x, x.members).map((m) => `<tr class="sub ${m.gone ? "exited" : ""}">
        <td><span class="nest" style="padding-left:${(m.depth - 1) * 16 + 34}px">↳ ${esc(m.name)}</span> <span class="of">${m.gone ? "left" : `${fmt(m.ofParent, "pct")} of ${esc(shortName(m.parentName))}`}</span></td>
        <td>—</td><td><span class="pill ${m.gone ? "exited" : "active"}">${m.gone ? "Exited" : "Active"}</span></td>
        <td class="r">${m.shares ? fmt(m.shares, "num") : "—"}</td><td class="r">${m.investment ? fmt(m.investment, "usd0") : "—"}</td>
        <td class="r">${fmt(m.lifetime, "usd0")}</td><td class="r muted" title="Share-months to date">${m.shareMonths != null ? fmt(m.shareMonths, "num") + " sm" : ""}</td></tr>`).join("") : ""}`).join("")}</tbody></table>
    </div>`;
  view.querySelectorAll("tr[data-k]").forEach((tr) => (tr.onclick = () => go(r.org, "investors", tr.dataset.k)));
  state.invList = list;
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
  const entry = (state.invList || []).find((x) => x.key === key) || {};
  if (entry.entityOrg) dr.querySelector(".sub").insertAdjacentHTML("afterend",
    `<p><a class="btn" href="#/${entry.entityOrg}/overview">Open ${esc(shortName(d.name))}'s members ›</a></p>`);
  else if (state.orgs.find((o) => o.id === r.org)?.canFound && !STATIC && entry.status === "Active") {
    dr.querySelector(".sub").insertAdjacentHTML("afterend", `<p><button class="btn" id="mkEntity">This partner is an LLC or trust: record its members</button></p>
      <div class="login-err" id="entErr" role="alert"></div>`);
    dr.querySelector("#mkEntity").onclick = async () => {
      try {
        const out = await post(`orgs/${r.org}/investors/${encodeURIComponent(key)}/entity`);
        state.orgs = await api("orgs"); state.capForm = null; close(); location.hash = `#/${out.id}/capitalize`;
      } catch (err) { dr.querySelector("#entErr").textContent = err.message; }
    };
  }
  dr.querySelector(".x").onclick = close;
  document.body.append(bg, dr);
  barChart($("#invChart"), d.distributions.map((x) => ({ x: String(x.year), y: x.amount, tip: `<b>${x.year}</b>${fmt(x.amount, "usd0")}` })));
}

$("#menuBtn").onclick = () => $("#side").classList.toggle("open");
addEventListener("hashchange", () => { if (state.user && !$("#shell").hidden) render(); });
let rt; addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => { if (route().view === "overview") render(); }, 200); });
boot();
