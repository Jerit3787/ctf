---
title:  "GMI CTF 2026 - Middle Management (Web)"
date:   2026-06-23 14:00:00 +0800
categories: [CTF Writeup, Web Exploitation]
tags: [GMI CTF 2026]
---

> This challenge was created by me for GMI CTF 2026 under the Web category. It is built around a real-world bug — **CVE-2025-29927**, the Next.js middleware authorization bypass — so the writeup doubles as a little tour of that CVE.
{: .prompt-info}

Hello again! After the heavier client-side and SQLi chains, this one is a nice palate cleanser — a single-step challenge that teaches one very important lesson: **middleware is not an authentication boundary.** It's based on a real Next.js CVE that made the rounds in 2025, and once you see the trick it's basically a one-liner with `curl`.

## Challenge Description

> Name: Middle Management
>
> Category: Web
>
> Difficulty: Easy
>
> Northwind Labs just rolled out their slick new internal operations dashboard. After a long sprint the team pushed it live, declared it production-ready, and moved straight on to the next thing on the roadmap. Everything looks buttoned-up from the outside. Take a look around.

## Step 1 — Recon

Poking at the app, we find two relevant routes:

- `GET /` → a public landing page that points at a staff-only `/admin` console.
- `GET /admin` → a **307 redirect** straight back to `/`.

So there's clearly something behind `/admin` we're not allowed to see. Where does that redirect come from? It's issued by `middleware.js`, whose `matcher` covers `/admin` and `/admin/*`. The middleware checks a `staff_session` cookie and bounces anyone without the right value.

Here's the important detail: the admin page itself (`app/admin/page.js`) does **no** auth of its own. It simply trusts that the middleware already vetted the request before it got there. That assumption — "if you reached this handler, middleware must have approved you" — is the whole vulnerability.

> Whenever you see authorization living *only* in middleware/a proxy/an edge function, and the underlying route does nothing to re-check it, your antenna should go up. The route is one bypassed middleware away from being wide open.
{: .prompt-info }

## Step 2 — The bug (CVE-2025-29927)

Next.js has an internal header it uses to stop middleware from recursing into itself:

```
x-middleware-subrequest: <middleware module name>
```

The idea is innocent enough: when the framework makes an internal subrequest, it tags it with this header so the same middleware doesn't run again and loop forever. The problem (CVE-2025-29927) is that the server **trusts this header even when it comes from the client**. Nothing strips it from inbound requests, so an attacker can simply *send it themselves*. If the header marks the current middleware as "already running," the framework **skips executing it entirely** — and in this app, that middleware is the only thing standing between us and `/admin`.

This affects vulnerable Next.js versions (here `next@14.2.24`; patched in 14.2.25 / 13.5.9 / 15.2.3 / 12.3.5).

## Step 3 — Build the payload

The middleware module is `middleware.js` at the project root, so its module name is simply `middleware`. Newer 14.x builds added a recursion-depth guard, so we repeat the name a few times to get past that limit (this also satisfies the simpler `includes()` check used in earlier builds):

```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

## Step 4 — Exploit

That's it — one request:

```bash
curl -s http://TARGET:3000/admin \
  -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
```

Without the header, the response is `307 → /`. With it, the middleware never runs, `/admin` renders, and the flag is sitting right there in the HTML. The automated version is `solve/solve.py`:

```bash
python3 solve/solve.py http://127.0.0.1:3000
```

→ **Flag** → `HYNX{m1ddl3w4r3_1snt_4n_4uth_b0undary}`

The flag spells out the lesson nicely: *middleware isn't an auth boundary.*

## Fix notes (for the curious)

- Upgrade Next.js to a patched release (≥ 14.2.25 for the 14.x line).
- Don't treat middleware as the *sole* authorization boundary — enforce authentication/authorization in the route/handler (or a server-side data layer) too, so a skipped middleware doesn't equal a skipped auth check.
- At the edge/proxy, strip the `x-middleware-subrequest` header from inbound client requests.

## Conclusion

Short and sweet, but a genuinely valuable one to internalise: defence-in-depth exists precisely so that one bypassed control doesn't hand over the whole app. Northwind Labs put all their trust in a single middleware check, and CVE-2025-29927 let us walk right around it. Keep your auth as close to the data as possible, and never let "they couldn't have reached this code without passing the gate" be the only thing protecting your gate. Till the next one, ciao!
