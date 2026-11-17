# Dependency Check

**Find the one outage that takes your business down.** Live at [deps.windsorsec.com](https://deps.windsorsec.com).

A free, open-source self-assessment for small businesses. It maps the outside services a business depends on, finds the single points of failure, and ranks where the next IT dollar should go. It produces:

- **A one-page owner summary:** the five best uses of the next dollar or hour, ranked by risk reduced per dollar.
- **A full IT checklist:** every recommendation with why it matters, the fix, a risk level and a rough cost. Exports to CSV, Markdown or print/PDF.
- **A dependency map** showing which services expose the business most.

## How it works

1. **Discover.** Reads the domain's public DNS through DNS-over-HTTPS (Cloudflare, with Google as a fallback):
   - `NS` shows who hosts DNS, and whether it's a single provider.
   - `MX` shows the email and sign-in provider (Microsoft 365, Google Workspace, …).
   - SPF `include:` entries show services that send mail as the domain (CRM, marketing, support, payroll).
   - Apex `TXT` verification tokens show SaaS tools that have verified the domain (Atlassian, DocuSign, Slack, Stripe, …).
   - The `CNAME` chain of `www` shows the website host.
   - `_dmarc` shows whether the domain can be spoofed.
2. **Weigh.** For each dependency, the user answers three questions: what happens if it's down for a workday, whether there's a fallback, and how many people can administer it. Nine business-wide questions cover the safety nets: registrar security, auto-renew, break-glass admin, offline backups, SaaS backup, out-of-band comms, offline contact sheet, backup internet and tabletop drills.
3. **Rank.** Each gap gets a risk score (0–100). Fixes are sorted by `score ÷ cost weight`, so cheap, high-impact work rises to the top.

### Scoring

| Input | Values |
|---|---|
| Impact weight | Business stops 9 · Major slowdown 5 · Annoying 2 · Barely notice 0 |
| Fallback factor | None 1.0 · Untested 0.55 · Tested 0.15 |
| Admin factor | Not sure 1.0 · One person 0.85 · Two+ with recovery codes 0.15 |
| Cost weight | Free 1.0 · $ 1.35 · $$ 1.9 · $$$ 2.6 |

- Per-dependency "no fallback" score = `impact × fallback × 9`
- Per-dependency "single admin" score = `impact × admin × 6` (only for major-slowdown and above)
- Business-wide gaps have a fixed base score, scaled by Yes 0 · Not sure 0.8 · No 1.0

All rules live in [`site/app.js`](site/app.js) (`buildFindings`). All fingerprints and questions live in [`site/data.js`](site/data.js). Pull requests that add provider fingerprints are welcome.

## Privacy

- No server, no accounts, no analytics, no cookies, no storage.
- The only network requests are DNS lookups for the domain you type, sent to `cloudflare-dns.com` (or `dns.google` as a fallback). Your answers never leave the page.
- A strict Content Security Policy limits scripts to this site and network requests to those two resolvers.

## Limits

This is a structured self-assessment plus a passive read of public DNS. It doesn't scan networks, probe hosts or log in to anything, and it isn't an audit. Services that don't touch DNS (payroll, POS, line-of-business apps, your ISP) are added by hand.

## Development

Static files in `site/`, no build step. Serve locally with:

```sh
python3 -m http.server -d site 8080
```

Pushing to `main` deploys to GitHub Pages through `.github/workflows/pages.yml`.

## Why

In 2026 CISA discontinued several free assessment services, including the External Dependencies Management assessment. This project is an open, free take on the part that matters most to small teams.

---

MIT licensed. Built by [Windsor Security](https://windsorsec.com).
