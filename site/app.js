/* Dependency Check: app logic. No server, no storage, no tracking.
   All DNS answers are untrusted input: rendered with textContent only, never innerHTML. */
"use strict";

(function () {
  const $ = (s) => document.querySelector(s);
  const state = {
    domain: "",
    deps: [],          // {id, name, cat, evidence:[], source:'dns'|'manual'|'custom', impact, fallback, admins, flags:[]}
    dns: {},           // raw findings: {nsProviders:[], ns:[], dmarc: null|string, spf: null|string}
    globals: {},
    cost: "2"
  };
  let idSeq = 0;

  /* ---------- tiny DOM helper (text only) ---------- */
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      n.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
    }
    return n;
  }
  function toast(msg) {
    const t = el("div", { class: "toast", role: "status", text: msg });
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3200);
  }

  /* ---------- DNS over HTTPS ---------- */
  const TYPES = { A: 1, CNAME: 5, NS: 2, MX: 15, TXT: 16 };
  async function doh(name, type) {
    const urls = [
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`
    ];
    for (const u of urls) {
      try {
        const r = await fetch(u, { headers: { accept: "application/dns-json" }, referrerPolicy: "no-referrer", credentials: "omit" });
        if (!r.ok) continue;
        const j = await r.json();
        return (j.Answer || [])
          .filter((a) => a.type === TYPES[type] || (type === "CNAME" && a.type === 5))
          .map((a) => String(a.data));
      } catch (e) { /* try next resolver */ }
    }
    throw new Error("DNS lookup failed");
  }
  // Answers for a name, including CNAME hops (resolvers return the chain on A queries)
  async function chain(name) {
    const urls = [
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`,
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=A`
    ];
    for (const u of urls) {
      try {
        const r = await fetch(u, { headers: { accept: "application/dns-json" }, referrerPolicy: "no-referrer", credentials: "omit" });
        if (!r.ok) continue;
        const j = await r.json();
        return (j.Answer || []).filter((a) => a.type === 5).map((a) => String(a.data));
      } catch (e) {}
    }
    return [];
  }
  const txtValue = (s) => s.replace(/^"|"$/g, "").replace(/"\s+"/g, "");

  function match(table, value) {
    for (const row of table) if (row[0].test(value)) return row;
    return null;
  }

  function cleanDomain(raw) {
    let d = String(raw || "").trim().toLowerCase();
    d = d.replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").replace(/^www\./, "").replace(/\.$/, "");
    if (!/^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d)) return null;
    return d;
  }

  /* ---------- dependency bookkeeping ---------- */
  function addDep(name, cat, evidence, source) {
    const key = name.toLowerCase();
    let d = state.deps.find((x) => x.name.toLowerCase() === key);
    if (d) {
      if (evidence && !d.evidence.includes(evidence)) d.evidence.push(evidence);
      // promote to the most important category seen
      if ((DC.CATS[cat] || {}).impact > (DC.CATS[d.cat] || {}).impact) d.cat = cat;
      return d;
    }
    const c = DC.CATS[cat] || DC.CATS.other;
    d = {
      id: "d" + (++idSeq), name, cat, evidence: evidence ? [evidence] : [], source,
      impact: c.impact, fallback: "none", admins: "unknown", flags: []
    };
    state.deps.push(d);
    return d;
  }

  async function scan(domain) {
    state.domain = domain;
    state.deps = state.deps.filter((d) => d.source !== "dns");
    state.dns = {};
    const [ns, mx, txt, dmarc, www, apex] = await Promise.all([
      doh(domain, "NS").catch(() => []),
      doh(domain, "MX").catch(() => []),
      doh(domain, "TXT").catch(() => []),
      doh("_dmarc." + domain, "TXT").catch(() => []),
      chain("www." + domain),
      chain(domain)
    ]);
    if (!ns.length && !mx.length && !txt.length) throw new Error("No DNS records found");

    // DNS hosting
    const nsProviders = [...new Set(ns.map((n) => (match(DC.NS, n) || [, "Unrecognized DNS host"])[1]))];
    state.dns.ns = ns;
    state.dns.nsProviders = nsProviders;
    if (ns.length) {
      const name = nsProviders.length === 1 ? nsProviders[0] : nsProviders.join(" + ");
      const d = addDep(name, "dns", "NS " + ns.join(", "), "dns");
      if (nsProviders.length === 1) d.flags.push("Single DNS provider: if it has a bad day, your email and website go with it.");
    }

    // Email
    let identityFound = false;
    for (const rec of mx) {
      const host = rec.split(/\s+/).pop();
      const m = match(DC.MX, host);
      if (m) {
        addDep(m[1], m[2], "MX " + host, "dns");
        if (m[2] === "identity") identityFound = true;
      }
    }
    if (mx.length && !state.deps.some((d) => d.evidence.some((e) => e.startsWith("MX ")))) {
      addDep("Email host (unrecognized)", "email", "MX " + mx.join(", "), "dns");
    }

    // TXT: SPF + verification tokens
    const txts = txt.map(txtValue);
    const spf = txts.find((t) => /^v=spf1/i.test(t)) || null;
    state.dns.spf = spf;
    if (spf) {
      const incs = [...spf.matchAll(/(?:include:|redirect=)([^\s]+)/gi)].map((m) => m[1]);
      for (const inc of incs) {
        const m = match(DC.SPF, inc);
        if (m) addDep(m[1], m[2], "SPF include:" + inc, "dns");
      }
    }
    for (const t of txts) {
      const m = match(DC.TXT, t);
      if (!m) continue;
      // Google/Microsoft verification alone = they use that ecosystem; fold into identity provider names
      let name = m[1];
      if (name === "Google" && state.deps.some((d) => d.name === "Google Workspace")) name = "Google Workspace";
      addDep(name, m[2], "TXT " + t.split("=")[0], "dns");
    }
    // Microsoft 365 bought through GoDaddy: tenant named NETORGFT####.onmicrosoft.com.
    // GoDaddy then controls the email tenant as well as DNS, and the secureserver SPF include is the same service.
    const netorg = txts.find((t) => /^NETORGFT\d+\.onmicrosoft\.com$/i.test(t));
    if (netorg) {
      state.deps = state.deps.filter((d) => !(d.name === "GoDaddy Email" && d.source === "dns" && d.evidence.every((e) => /secureserver/i.test(e))));
      const m = addDep("Microsoft 365", "identity", "TXT " + netorg, "dns");
      m.name = "Microsoft 365 (bought through GoDaddy)";
      m.flags.push("Bought through GoDaddy, so your GoDaddy login controls your email admin as well as your DNS. That one account is a single key to most of the business.");
    }

    // Google site verification without Workspace mail is usually Search Console, not critical
    const g = state.deps.find((d) => d.name === "Google" && d.source === "dns");
    if (g) { g.name = "Google (Search Console / services)"; g.cat = "saas"; g.impact = 0; }

    // DMARC
    const dm = dmarc.map(txtValue).find((t) => /^v=DMARC1/i.test(t)) || null;
    state.dns.dmarc = dm;

    // Website host
    const hops = [...www, ...apex];
    let web = null;
    for (const h of hops) { const m = match(DC.WEB, h); if (m) { web = m[1]; break; } }
    if (web) addDep(web, "web", "CNAME " + hops[0], "dns");

    // Identity note
    for (const d of state.deps) if (d.cat === "identity") {
      d.flags.push("This is likely your sign-in system too. Locked out of it means locked out of everything tied to it.");
    }
    state.dns.identity = identityFound;
  }

  /* ---------- render: step 1 ---------- */
  function renderDeps() {
    const box = $("#deps");
    box.replaceChildren();
    if (!state.deps.length) {
      box.appendChild(el("p", { class: "empty", text: "Nothing yet. Add the services your business uses below." }));
    }
    for (const d of state.deps) {
      const c = DC.CATS[d.cat] || DC.CATS.other;
      box.appendChild(el("div", { class: "dep" },
        el("div", null,
          el("div", { class: "cat", text: c.label + (d.source === "dns" ? " · found in DNS" : "") }),
          el("div", { class: "name", text: d.name }),
          d.evidence.length ? el("div", { class: "ev", text: d.evidence.join("  ·  ") }) : null,
          ...d.flags.map((f) => el("div", { class: "flag", text: f }))
        ),
        el("button", { class: "icon-btn", type: "button", "aria-label": "Remove " + d.name, onclick: () => {
          state.deps = state.deps.filter((x) => x !== d);
          syncChips(); renderDeps(); renderQuestions();
        } }, "Remove")
      ));
    }
  }

  function renderManual() {
    const box = $("#manual");
    box.replaceChildren();
    DC.MANUAL.forEach((m, i) => {
      const cb = el("input", { type: "checkbox", "data-i": String(i) });
      const chip = el("label", { class: "chip" }, cb, m.name);
      cb.addEventListener("change", () => {
        if (cb.checked) addDep(m.name, m.cat, null, "manual");
        else state.deps = state.deps.filter((d) => !(d.source === "manual" && d.name === m.name));
        chip.classList.toggle("on", cb.checked);
        renderDeps(); renderQuestions();
      });
      box.appendChild(chip);
    });
  }
  function syncChips() {
    document.querySelectorAll("#manual input").forEach((cb) => {
      const m = DC.MANUAL[+cb.dataset.i];
      cb.checked = state.deps.some((d) => d.source === "manual" && d.name === m.name);
      cb.parentElement.classList.toggle("on", cb.checked);
    });
  }

  /* ---------- render: step 2 ---------- */
  function select(options, value, onchange, id) {
    const s = el("select", { id });
    for (const o of options) {
      const opt = el("option", { value: String(o.v), text: o.label });
      if (String(o.v) === String(value)) opt.selected = true;
      s.appendChild(opt);
    }
    s.addEventListener("change", () => onchange(s.value));
    return s;
  }
  function renderQuestions() {
    const box = $("#questions");
    box.replaceChildren();
    const has = state.deps.length > 0;
    $("#step2").hidden = !has;
    $("#step3").hidden = !has;
    if (!has) return;
    const sorted = [...state.deps].sort((a, b) => b.impact - a.impact);
    for (const d of sorted) {
      const c = DC.CATS[d.cat] || DC.CATS.other;
      box.appendChild(el("div", { class: "q-card" },
        el("h3", null, d.name, el("span", { class: "cat", text: c.label })),
        c.note ? el("p", { class: "muted small", text: c.note }) : null,
        el("div", { class: "q-grid" },
          el("div", { class: "q" }, el("label", { for: d.id + "-i", text: "If it's down all day" }),
            select(DC.IMPACT, d.impact, (v) => { d.impact = +v; }, d.id + "-i")),
          el("div", { class: "q" }, el("label", { for: d.id + "-f", text: "Backup way to keep working" }),
            select(DC.FALLBACK, d.fallback, (v) => { d.fallback = v; }, d.id + "-f")),
          el("div", { class: "q" }, el("label", { for: d.id + "-a", text: "Who can get in as admin" }),
            select(DC.ADMINS, d.admins, (v) => { d.admins = v; }, d.id + "-a"))
        )
      ));
    }
  }

  /* ---------- render: step 3 ---------- */
  function renderGlobals() {
    const box = $("#globals");
    box.replaceChildren();
    box.appendChild(el("div", { class: "g-row" },
      el("div", null,
        el("div", { class: "q-text", text: "Roughly what does one full day of being unable to operate cost you?" }),
        el("div", { class: "q-help", text: "Lost sales, idle staff, missed deadlines. A gut estimate is fine." })),
      select(DC.COSTS, state.cost, (v) => { state.cost = v; }, "g-cost")
    ));
    for (const g of DC.GLOBALS) {
      box.appendChild(el("div", { class: "g-row" },
        el("div", null,
          el("div", { class: "q-text", text: g.text }),
          g.help ? el("div", { class: "q-help", text: g.help }) : null),
        select(DC.YESNO, state.globals[g.id] || "", (v) => { state.globals[g.id] = v; }, "g-" + g.id)
      ));
    }
  }

  /* ---------- scoring ---------- */
  const W = [0, 2, 5, 9]; // impact weight
  const fb = (v) => (DC.FALLBACK.find((x) => x.v === v) || { f: 1 }).f;
  const ad = (v) => (DC.ADMINS.find((x) => x.v === v) || { f: 1 }).f;
  const gap = (id) => { const v = state.globals[id]; return v === "yes" ? 0 : v === "unsure" ? 0.8 : 1; };
  const level = (s) => (s >= 60 ? "high" : s >= 35 ? "medium" : "low");

  function buildFindings() {
    const F = [];
    const push = (f) => { if (f.score >= 8) F.push(f); };
    const maxImpact = Math.max(0, ...state.deps.map((d) => d.impact));
    const identity = state.deps.filter((d) => d.cat === "identity");
    const idImpact = Math.max(0, ...identity.map((d) => d.impact));
    const crit = state.deps.filter((d) => d.impact >= 2);

    // Per-dependency gaps. DNS is covered by the registrar + single-provider findings below.
    // Minor (impact 1) tools without a tested fallback are rolled into one combined item.
    const minor = [];
    for (const d of state.deps) {
      if (d.cat === "dns") continue;
      const c = DC.CATS[d.cat] || DC.CATS.other;
      const s1 = Math.round(W[d.impact] * fb(d.fallback) * 9);
      if (d.impact === 1 && d.fallback !== "tested") minor.push(d);
      if (d.impact >= 2) push({
        title: `Make a plan for when ${d.name} is down`,
        area: c.label,
        why: `You said an outage would mean "${DC.IMPACT.find((x) => x.v === d.impact).label.toLowerCase()}", and ${d.fallback === "tested" ? "your fallback is tested" : d.fallback === "untested" ? "the fallback has never been tested" : "there's no fallback today"}.`,
        fix: fallbackFix(d),
        cost: d.cat === "isp" ? "mid" : "free",
        score: s1
      });
      const s2 = Math.round(W[d.impact] * ad(d.admins) * 6);
      if (d.impact >= 2) push({
        title: `Add a second admin to ${d.name}`,
        area: c.label,
        why: "If the only person who can manage it leaves, gets sick or loses their phone, nobody can fix, reset or recover it.",
        fix: "Give a second trusted person admin rights, turn on 2-step login for both, and keep the recovery codes in a sealed envelope or the company password manager.",
        cost: "free",
        score: s2
      });
    }
    if (minor.length) push({
      title: `Write a one-line fallback for ${minor.length} smaller ${minor.length === 1 ? "tool" : "tools"}`,
      area: "Planning",
      why: `${minor.map((d) => d.name).join(", ")}: annoying to lose for a day, not fatal, and no fallback today.`,
      fix: "For each one, write down the status page URL, the vendor support number, and how you'd get through a day without it. Add it to the offline 'who to call' sheet.",
      cost: "free",
      score: 12 + minor.length * 2
    });

    // DNS single provider
    if ((state.dns.nsProviders || []).length === 1) push({
      title: "Your DNS is a single point of failure for email and the website",
      area: "DNS hosting",
      why: `All of your nameservers are run by ${state.dns.nsProviders[0]}. Outages are rare but take email and web down together.`,
      fix: "Export a copy of your DNS zone and keep it offline so you can rebuild it anywhere in an hour. If the website or email is revenue-critical, add a secondary DNS provider.",
      cost: "low",
      score: Math.round(18 + W[maxImpact] * 1.5)
    });

    // Business-wide
    const G = (id, f) => { const g = gap(id); if (g > 0) push(Object.assign(f, { score: Math.round(f.base * g) })); };
    G("registrar", {
      title: "Lock down your domain registrar account", area: "Domain",
      why: "Whoever controls the registrar controls your email and website. Account takeovers there are a common way businesses lose their domain for days.",
      fix: "Turn on 2-step login (an authenticator app, not SMS), add a second admin, enable registrar lock, and make sure the account email isn't on the same domain it controls.",
      cost: "free", base: 72
    });
    G("autorenew", {
      title: "Turn on domain auto-renew with a current card", area: "Domain",
      why: "An expired domain takes email and the website offline at the same time, and the renewal reminder often goes to someone who left.",
      fix: "Enable auto-renew, renew for several years, update the payment card, and send renewal notices to a shared inbox.",
      cost: "free", base: 48
    });
    G("breakglass", {
      title: "Create an emergency admin account for email and sign-in", area: "Email + sign-in",
      why: identity.length ? `${identity.map((d) => d.name).join(" / ")} is your master key. If the normal admin is locked out, everything behind it is stuck.` : "Your email and sign-in system is the master key. If the normal admin is locked out, everything behind it is stuck.",
      fix: "Create one cloud-only admin account that isn't anyone's daily login. Protect it with a hardware key or long password, store the credentials offline, and test it twice a year.",
      cost: "free", base: identity.length ? 40 + W[idImpact] * 4 : 45
    });
    G("backups", {
      title: "Get a backup an outage or attacker can't touch", area: "Backups",
      why: "Ransomware and bad syncs delete backups that sit on the same network or account. An untested backup fails when you need it.",
      fix: "Keep an offline or immutable copy of critical data (cloud backup with immutability, or a rotated drive kept offsite) and do a test restore every quarter.",
      cost: "mid", base: 88
    });
    G("saasbackup", {
      title: "Back up cloud email and files separately", area: "Backups",
      why: "Microsoft and Google keep the service running. Getting back deleted, overwritten or encrypted data is mostly your responsibility.",
      fix: "Add a third-party backup for Microsoft 365 / Google Workspace mailboxes and drives, usually a few dollars per user per month.",
      cost: "low", base: 50
    });
    G("oob", {
      title: "Set up a backup way to reach your team", area: "Communications",
      why: "When email or chat is down, or compromised, you still need to tell people what's happening and what to do.",
      fix: "Create a Signal or WhatsApp group (or a text tree) with personal numbers, and use it only for emergencies.",
      cost: "free", base: 42
    });
    G("offline", {
      title: "Keep an offline 'who to call' sheet", area: "Communications",
      why: "Vendor support numbers, account IDs and contacts are usually stored in the system that's down.",
      fix: "One page: each critical vendor, support number, account ID, who's admin, and your IT contact. Print it and keep a copy on two phones.",
      cost: "free", base: 36
    });
    G("isp", {
      title: "Add backup internet", area: "Internet service",
      why: "Almost everything above runs over one internet line. A cut cable stops the whole office.",
      fix: "A cellular failover router or a business hotspot with a data plan. Test it by unplugging the main line for ten minutes.",
      cost: "mid", base: maxImpact >= 3 ? 58 : 32
    });
    G("drill", {
      title: "Run a 30-minute 'X is down' tabletop", area: "Planning",
      why: "Plans that have never been walked through fail on the first missing detail: a password, a phone number, who decides.",
      fix: "Pick the top dependency on this report, assume it's down at 9am Monday, and walk through it with your team. Write down what you didn't know.",
      cost: "free", base: 34
    });

    // Email spoofing (security, from DNS)
    if (state.domain && state.dns && !state.dns.dmarc) push({
      title: "Publish a DMARC record so nobody can send email as you", area: "Email",
      why: "Your domain has no DMARC policy, so criminals can more easily send invoices and 'urgent' requests that look like they came from you.",
      fix: "Add a DMARC record starting at p=none to monitor, then move to quarantine/reject once your legitimate senders are aligned.",
      cost: "free", score: 38
    });
    if (state.domain && state.dns && state.dns.dmarc && /p=none/i.test(state.dns.dmarc)) push({
      title: "Move DMARC from monitor to enforce", area: "Email",
      why: "Your DMARC policy is p=none: it reports spoofing but doesn't stop it.",
      fix: "Review DMARC reports, make sure every legitimate sender passes, then move to p=quarantine and later p=reject.",
      cost: "free", score: 22
    });

    // Rank by risk reduced per dollar
    for (const f of F) {
      f.level = level(f.score);
      f.priority = f.score / DC.COST[f.cost].w;
    }
    F.sort((a, b) => b.priority - a.priority);
    return F;
  }

  function fallbackFix(d) {
    switch (d.cat) {
      case "identity": return "Write down how the team keeps working for a day without it: phones for urgent contact, offline copies of today's key files, and break-glass admin access to restore it. Then test it once.";
      case "email": return "Agree on a backup channel for customer contact (phone, a secondary mailbox) and keep a list of key customer contacts outside email.";
      case "dns": return "Keep an offline export of your DNS zone and know how you'd move it to another provider. Store the registrar login with the break-glass credentials.";
      case "payments": return "Set up a second way to take payment (a backup processor, card reader or invoice link) and test it on a real transaction.";
      case "isp": return "Add cellular failover or a business hotspot, and know which devices you'll move to it first.";
      case "lob": return "Ask the vendor for their outage process and status page. Keep a daily export or printout of tomorrow's schedule and customer list so work can continue on paper.";
      case "phone": return "Set call forwarding to mobile phones as an outage fallback and keep the forwarding steps on the offline sheet.";
      case "files": return "Make sure critical files sync to at least one laptop for offline use, and keep a separate backup.";
      case "security": return "Ask your vendor how bad updates are staged and rolled back, and keep local admin recovery steps for when an agent breaks machines at boot.";
      case "payroll": return "Know the deadline by which payroll must run, and the vendor's manual or emergency process if the system is down that day.";
      case "it": return "Make sure you, not only the provider, hold admin credentials to your own systems, and keep a backup contact for emergencies.";
      case "passwords": return "Make sure the emergency kit and recovery codes for the password manager are stored offline, and that two people can recover the account.";
      case "field": return "Keep a few devices set up to work offline (downloaded forms, maps and job details), and have a second carrier's hotspot for crews in weak-signal areas.";
      case "dispatch": return "Print or export the next day's schedule and job details every evening so crews can still roll if the system is down in the morning.";
      case "portal": return "Know the portal's phone or email fallback for urgent submissions, and keep copies of anything you'd need to resubmit.";
      case "specialty": return "Know how licenses are activated (and whether they work offline), keep installers and license keys somewhere safe, and back up project files outside the app.";
      default: return `Write down how you'd work for a day without ${d.name}, who to call, and where its status page is. Test the plan once.`;
    }
  }

  /* ---------- render: report ---------- */
  let lastFindings = [];
  function renderReport() {
    const F = buildFindings();
    lastFindings = F;
    const costTxt = DC.COSTS.find((c) => c.v === state.cost).text;
    const today = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

    $("#report-title").textContent = state.domain ? `Dependency Check: ${state.domain}` : "Dependency Check";
    $("#report-meta").textContent = `Generated ${today} · ${state.deps.length} dependencies · ${F.length} recommendations`;

    const stops = state.deps.filter((d) => d.impact === 3);
    const unprotected = stops.filter((d) => d.fallback !== "tested");
    $("#owner-lede").textContent =
      `A full day down costs you roughly ${costTxt}. ` +
      (unprotected.length
        ? `${unprotected.length} ${unprotected.length === 1 ? "thing would" : "things would"} stop the business with no tested fallback: ${unprotected.map((d) => d.name).join(", ")}. `
        : "Nothing you rely on would stop the business without a tested fallback. ") +
      "These are the five best uses of your next dollar or hour, ranked by risk reduced per dollar.";

    const ol = $("#owner-list");
    ol.replaceChildren();
    const top = F.slice(0, 5);
    if (!top.length) ol.appendChild(el("li", null, el("div", null, el("div", { class: "t", text: "No significant gaps found from your answers." })), el("div")));
    for (const f of top) {
      const c = DC.COST[f.cost];
      ol.appendChild(el("li", null,
        el("div", null, el("div", { class: "t", text: f.title }), el("div", { class: "w", text: f.why })),
        el("div", { class: "cost" }, c.label, el("small", { text: c.note }))
      ));
    }

    const stats = $("#stats");
    stats.replaceChildren(
      stat(String(state.deps.length), "Outside services you depend on"),
      stat(String(stops.length), "Would stop the business if down"),
      stat(String(F.filter((f) => f.cost === "free").length), "Fixes that cost nothing but time")
    );

    const cl = $("#checklist");
    cl.replaceChildren();
    F.forEach((f, i) => {
      const cb = el("input", { type: "checkbox", "aria-label": "Mark done: " + f.title });
      const item = el("div", { class: "item" }, cb,
        el("div", null,
          el("div", { class: "top" },
            el("span", { class: "t", text: `${i + 1}. ${f.title}` }),
            el("span", { class: "pill " + f.level, text: f.level + " risk" }),
            el("span", { class: "pill", text: DC.COST[f.cost].label + " · " + DC.COST[f.cost].note }),
            el("span", { class: "pill", text: f.area })),
          el("div", { class: "why", text: f.why }),
          el("div", { class: "fix" }, el("b", { text: "Fix: " }), f.fix)
        ));
      cb.addEventListener("change", () => { item.classList.toggle("done", cb.checked); f.done = cb.checked; });
      cl.appendChild(item);
    });

    const map = $("#map");
    map.replaceChildren();
    const ranked = [...state.deps].sort((a, b) => (W[b.impact] * fb(b.fallback)) - (W[a.impact] * fb(a.fallback)));
    for (const d of ranked) {
      const exposure = Math.max(4, Math.round((W[d.impact] * fb(d.fallback)) / 9 * 100));
      map.appendChild(el("div", { class: "map-row" },
        el("div", { class: "label" }, d.name, el("small", { text: (DC.CATS[d.cat] || DC.CATS.other).label })),
        el("div", { class: "bar", title: "Exposure " + exposure + "%" }, el("span", { style: null }))
      ));
      // width set via CSSOM (allowed under style-src 'self'; inline style attributes are not)
      map.lastChild.querySelector(".bar > span").style.width = exposure + "%";
    }

    // Reach-out link: pre-filled email the user reviews in their own mail app
    const subj = "Dependency Check" + (state.domain ? ": " + state.domain : "");
    const body = "Hi Windsor Security,\n\nI ran Dependency Check" + (state.domain ? " on " + state.domain : "") +
      " and would like to talk through the results.\n\nTop items from my report:\n" +
      F.slice(0, 3).map((f, i) => `${i + 1}. ${f.title}`).join("\n") + "\n\nThanks,\n";
    $("#reach-out").href = "mailto:hello@windsorsec.com?subject=" + encodeURIComponent(subj) + "&body=" + encodeURIComponent(body);

    $("#report").hidden = false;
    $("#report").scrollIntoView({ behavior: "smooth" });
  }
  function stat(n, l) { return el("div", { class: "stat" }, el("div", { class: "n", text: n }), el("div", { class: "l", text: l })); }

  /* ---------- exports ---------- */
  function download(name, mime, text) {
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    const a = el("a", { href: url, download: name });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  const csvCell = (v) => {
    let s = String(v == null ? "" : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // block spreadsheet formula injection
    return '"' + s.replace(/"/g, '""') + '"';
  };
  const slug = () => (state.domain || "business").replace(/[^a-z0-9.-]/gi, "");

  function exportCSV() {
    const rows = [["Priority", "Done", "Recommendation", "Area", "Risk", "Cost", "Why", "Fix"]];
    lastFindings.forEach((f, i) => rows.push([i + 1, f.done ? "yes" : "", f.title, f.area, f.level, DC.COST[f.cost].label + " (" + DC.COST[f.cost].note + ")", f.why, f.fix]));
    rows.push([]);
    rows.push(["Dependency", "", "Category", "Impact if down", "Fallback", "Admins", "Evidence", ""]);
    for (const d of state.deps) rows.push([d.name, "", (DC.CATS[d.cat] || DC.CATS.other).label,
      DC.IMPACT.find((x) => x.v === d.impact).label, DC.FALLBACK.find((x) => x.v === d.fallback).label,
      DC.ADMINS.find((x) => x.v === d.admins).label, d.evidence.join("; "), ""]);
    download(`dependency-checklist-${slug()}.csv`, "text/csv", rows.map((r) => r.map(csvCell).join(",")).join("\r\n"));
  }

  function exportMD() {
    const md = (s) => String(s).replace(/([\\`*_[\]<>|])/g, "\\$1");
    const L = [];
    L.push(`# Dependency Check${state.domain ? ": " + md(state.domain) : ""}`, "");
    L.push(`_${$("#report-meta").textContent}_`, "");
    L.push("## For the owner: where your next IT dollar goes", "", md($("#owner-lede").textContent), "");
    lastFindings.slice(0, 5).forEach((f, i) => L.push(`${i + 1}. **${md(f.title)}** (${DC.COST[f.cost].label}, ${DC.COST[f.cost].note}): ${md(f.why)}`));
    L.push("", "## For your IT person: full checklist", "");
    lastFindings.forEach((f, i) => {
      L.push(`- [${f.done ? "x" : " "}] **${i + 1}. ${md(f.title)}** · ${f.level} risk · ${DC.COST[f.cost].label} · ${md(f.area)}`);
      L.push(`  - Why: ${md(f.why)}`);
      L.push(`  - Fix: ${md(f.fix)}`);
    });
    L.push("", "## Dependencies", "", "| Dependency | Category | If down | Fallback | Admins |", "|---|---|---|---|---|");
    for (const d of state.deps) L.push(`| ${md(d.name)} | ${(DC.CATS[d.cat] || DC.CATS.other).label} | ${DC.IMPACT.find((x) => x.v === d.impact).label} | ${DC.FALLBACK.find((x) => x.v === d.fallback).label} | ${DC.ADMINS.find((x) => x.v === d.admins).label} |`);
    L.push("", "---", "Generated with Dependency Check by Windsor Security, https://deps.windsorsec.com. Self-assessment, not an audit.");
    download(`dependency-report-${slug()}.md`, "text/markdown", L.join("\n"));
  }

  /* ---------- wiring ---------- */
  function showStep1(summary) {
    $("#check").hidden = false;
    $("#scan-summary").textContent = summary;
    renderDeps(); renderQuestions(); renderGlobals();
    $("#check").scrollIntoView({ behavior: "smooth" });
  }

  $("#scan-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = cleanDomain($("#domain").value);
    if (!d) { toast("That doesn't look like a domain. Try something like yourbusiness.com."); return; }
    const btn = $("#scan-btn");
    btn.disabled = true; btn.textContent = "Reading DNS…";
    $("#report").hidden = true;
    try {
      await scan(d);
      const n = state.deps.filter((x) => x.source === "dns").length;
      showStep1(`Found ${n} ${n === 1 ? "service" : "services"} in the public DNS for ${d}. Remove anything that's wrong, then add what DNS can't see.`);
    } catch (err) {
      toast(`Couldn't read DNS for ${d}. Check the spelling, or skip the scan and add things by hand.`);
    } finally {
      btn.disabled = false; btn.textContent = "Scan my domain";
    }
  });
  $("#skip-scan").addEventListener("click", () => {
    showStep1("No scan. Add the services your business uses below.");
  });
  $("#custom-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("#custom-name").value.trim().slice(0, 80);
    if (!v) return;
    addDep(v, "other", null, "custom");
    $("#custom-name").value = "";
    renderDeps(); renderQuestions();
  });
  $("#build-report").addEventListener("click", () => {
    if (!state.deps.length) { toast("Add at least one dependency first."); return; }
    renderReport();
  });
  $("#dl-csv").addEventListener("click", exportCSV);
  $("#dl-md").addEventListener("click", exportMD);
  $("#print").addEventListener("click", () => window.print());
  $("#year").textContent = String(new Date().getFullYear());

  /* nav: products dropdown + mobile menu (mirrors windsorsec.com) */
  const pBtn = $("#products-btn"), pPanel = $("#products-panel");
  pBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const open = pPanel.hidden;
    pPanel.hidden = !open; pBtn.setAttribute("aria-expanded", String(open));
  });
  document.addEventListener("mousedown", (e) => {
    if (!pPanel.hidden && !$("#products").contains(e.target)) { pPanel.hidden = true; pBtn.setAttribute("aria-expanded", "false"); }
  });
  const mBtn = $("#menu-btn"), mMenu = $("#mobile-menu");
  mBtn.addEventListener("click", () => {
    const open = mMenu.hidden;
    mMenu.hidden = !open; mBtn.setAttribute("aria-expanded", String(open));
  });

  renderManual();
})();
