# HackerOne Product Security Analyst — Complete Interview Prep
**Interview: Monday, 5 October 2026 | Prep window: 3 days**

---

## 0. The one-line reframe (read this first)

You do **not** need bug bounty experience to pass this. The job is **triage**: taking a vulnerability report someone else wrote, deciding if it's real, reproducing it, scoring its severity correctly, and writing a crisp verdict. Your ~1.5 years of hands-on manual VAPT (finding and validating 200+ vulns) *is* exactly this skill — you already validate findings and write reports at CyRAACS. Your job in the interview is to **reframe your pentest experience as triage experience**, be fluent in OWASP mechanics + impact + mitigation, and nail the live triage challenge.

The candidate who failed did so at the **challenge/triage round** despite knowing the theory. So weight your 3 days toward *practising triage out loud*, not re-reading XSS definitions you already know.

---

## 1. The role — what it actually is

**Team:** Technical Services (the triage team that sits between hackers and customers).

**What you'll do day to day:**
- Read vulnerability reports submitted by external researchers ("hackers")
- Decide **validity** (is it real / in-scope / impactful?)
- **Reproduce** it independently in a test environment
- Assign **severity** (via CVSS)
- Write a **technical summary**: impact, steps to reproduce, remediation
- Communicate with hackers (ask for missing info, politely reject invalid reports) and keep customers informed

**Pune role specifics (from the actual posting):**
- Location: Pune, work from office, 4–5 days a week
- **Shifts / weekend coverage**, with regular US business-hours overlap
- Compensation: **₹2.5M – ₹2.6M (25–26 LPA) + equity**
- Interview process (stated on the posting): **Technical Round → Challenge Round → Hiring Manager Round**

**Customers include:** Anthropic, Crypto.com, General Motors, Goldman Sachs, Lufthansa, Uber, UK Ministry of Defence, US DoD.

**Why "Product Security Analyst" not "Triage Analyst":** it's the more senior-sounding of two related titles HackerOne uses (Triage Analyst also exists, and there's now a "Team Lead, Triage"). "Product security" = you protect the security posture of customers' *products*, even though you validate rather than pentest them. Fair to ask what distinguishes the two internally.

---

## 2. Minimum qualifications & how you map

| They want | You have | How to say it |
|---|---|---|
| 3+ yrs security testing / ethical hacking (web & mobile) | ~1.5 yrs AppSec + ~1 yr backend | Lead with "close to two years of hands-on manual VAPT across web, API, and Android." Don't volunteer the gap; if pushed, emphasise depth (200+ validated vulns) and code-level understanding. |
| OWASP Top 10 | Daily work | Strong — be fluent in mechanics + impact + fix |
| Burp Suite | Daily work | Strong |
| CVSS familiarity | Used it | **Shore this up** — Section 5 |
| Excellent English communication | — | The job is 50% communication. Structured, calm, clear. |
| Bug bounty / VDP (preferred) | Don't have it | Compensate with triage-workflow fluency (Section 4) |
| Weekend shifts, on-site Pune | — | Confirm clearly you're OK with this; they screen hard |

---

## 3. Core technical questions — WITH answers
*(Candidates report being drilled on: XSS, CSRF, SQLi, IDOR, SSRF, CORS, plus API and business-logic scenarios. One recent review: "explain the technical mechanics, risks, and mitigation for OWASP Top 10, specifically XSS, SQLi, SSRF, and API-specific flaws, alongside business-logic scenarios." For each vuln know: **what → how you verify/exploit → impact → mitigation**. That four-part structure IS triage.)*

### 3.1 XSS (Cross-Site Scripting)
**What:** Injecting attacker script that runs in another user's browser in the site's context.
**Types:** Reflected (payload echoed from request), Stored/Persistent (saved server-side, served to all viewers — highest impact), DOM-based (client-side only; JS writes attacker data into a sink like `innerHTML`/`eval`).
**Impact:** Session/cookie theft, account takeover, keylogging, CSRF-token theft, phishing redirects, actions as the victim.
**Mitigation:** Context-aware output encoding, CSP, `HttpOnly` cookies, input validation, auto-escaping frameworks, DOMPurify for rich HTML.
**Triage angle:** Self-XSS (hits only the attacker) = usually low/informative. Stored on an authenticated high-traffic page = high. Identify reflected vs stored vs DOM.

### 3.2 CSRF
**What:** Forcing an authenticated victim's browser to send a state-changing request they didn't intend, abusing auto-attached cookies.
**Conditions:** State-changing action + cookie-only auth + predictable params + no anti-CSRF token / no SameSite.
**Impact:** Change email/password, transfer funds, change settings as the victim.
**Mitigation:** Anti-CSRF tokens (synchroniser pattern), `SameSite=Lax/Strict`, verify Origin/Referer, re-auth for sensitive actions.
**Triage angle:** CSRF on logout/non-sensitive pref = low. CSRF on password/email change = high. If a validated token exists → likely N/A.

### 3.3 SQL Injection
**What:** Untrusted input concatenated into a SQL query, altering query logic.
**Types:** In-band (union/error-based), blind (boolean/time-based), out-of-band.
**Impact:** Dump/modify DB, auth bypass, sometimes RCE/file read.
**Mitigation:** Parameterised queries/prepared statements, ORM with binding, least-privilege DB user, input validation, WAF as defence-in-depth (not a fix).
**Triage angle:** Reproduce with a safe proof (boolean/time differential, `version()`), never dump real customer data. Confirmed on prod = critical/high.

### 3.4 IDOR / Broken Access Control
**What:** An object reference the server doesn't authorise against the current user.
**Impact:** Read/modify other users' data; horizontal or vertical escalation.
**Mitigation:** Server-side object-level authorisation on every request; unguessable refs as defence-in-depth only; centralised access checks.
**Triage angle:** #1 bug-bounty class. Verify with **two accounts**: can A reach B's object? PII/financial = high/critical; your own non-sensitive object = none.

### 3.5 SSRF
**What:** Making the server send attacker-controlled requests (internal services, cloud metadata).
**Impact:** Reach internal services, read cloud metadata (`169.254.169.254` → steal creds, the Capital One breach), internal port-scan, sometimes RCE.
**Mitigation:** Outbound allowlist, block link-local/internal ranges, disable unused URL schemes, enforce IMDSv2, segmentation.
**Triage angle:** Blind SSRF (callback only) < SSRF returning internal data or cloud creds (critical).

### 3.6 CORS misconfiguration
**What:** Overly permissive CORS lets a malicious origin read responses.
**Danger combo:** `Access-Control-Allow-Origin` reflects arbitrary origin **AND** `Access-Control-Allow-Credentials: true` → attacker site reads authenticated responses.
**Preflight:** For non-simple requests (custom headers, PUT/DELETE, certain content types) the browser first sends `OPTIONS`; the server's CORS headers decide if the real request proceeds.
**Mitigation:** Strict origin allowlist; never reflect arbitrary origin with credentials true; no `*` for authenticated endpoints.
**Triage angle:** Origin reflection + credentials true + sensitive data = valid/high. ACAO `*`, no credentials, no sensitive data = often low/informative.

### 3.7 API-specific (OWASP API Top 10 — know the names)
BOLA / API-IDOR (#1), Broken Authentication (weak JWT, no login/OTP rate limit), BFLA (admin funcs as regular user), Mass Assignment (`isAdmin=true`), Excessive Data Exposure (API returns more than UI shows), SSRF, security misconfig, no rate limiting.

### 3.8 JWT / OAuth (modern auth)
- **JWT:** `alg:none`, weak-secret brute force, `kid` injection, unverified signature, `exp` not checked. Fix: verify signature server-side, strong alg, validate claims.
- **OAuth:** `redirect_uri` manipulation, stolen `code`, CSRF on callback (missing `state`), token leak via Referer. Fix: strict redirect-uri allowlist, verify `state`, PKCE.

### 3.9 Quick-fire others
XXE, open redirect, clickjacking, file upload → RCE, path traversal, race conditions (you have real experience — mention it), host header injection, subdomain takeover, insecure deserialization, rate-limiting/brute force.

---

## 4. HackerOne-specific knowledge (your bug-bounty substitute)

Knowing HackerOne's own triage workflow signals you understand the job without bounty experience. **Learn these report states cold.**

**Open states:**
- **New** — pending validation (just submitted)
- **Pending Program Review** — H1 triage validated it; awaiting the customer's team
- **Triaged** — validated, reproducible, escalated to customer for remediation ("this is a real bug")
- **Needs More Info (NMI)** — waiting on the hacker for repro/detail; auto-closes as informative after 30 days

**Closed states:**
- **Resolved** — fixed (hacker reputation +, bounty may apply)
- **Duplicate** — already reported/known (attribute to the original)
- **Informative** — valid-ish but no real security impact / no action (reputation 0)
- **Not Applicable (N/A)** — invalid, out of scope, or no impact (hacker reputation −5)
- **Spam** — junk

**Report ID colour cues** (nice detail to drop): Triaged = orange, Needs More Info = light blue, Duplicate = brown, Informative = grey, N/A = red.

**Your triage decision tree (memorise the flow):**
1. **In scope?** (program policy) → if not, N/A
2. **Enough info to reproduce?** → if not, **Needs More Info** (ask precisely)
3. **Already reported?** → **Duplicate**
4. **Reproducible AND has impact?** → **Triaged**; set severity
5. **Reproducible but no real security impact?** → **Informative**
6. **Not reproducible / not a vuln?** → **N/A**

**Severity tooling:** HackerOne uses **CVSS 3.0 (custom), 3.1, and 4.0** calculators; programs pick which (and may use a non-CVSS method stated in their policy). Buckets: None / Low / Medium / High / Critical. Programs can set **severity caps** per asset. Hai Triage (their AI) does a first pass — humans validate.

**Golden rule of triage communication:** respectful to hackers even when rejecting — they're the community. Explain *why* clearly, ask precisely for what's missing, never be dismissive. Ties to their values **"Default to Disclosure"** and **"Win Together."**

---

## 5. CVSS — the part to actually drill

You'll likely be handed a vuln and asked to produce a vector + score. Learn the **8 base metrics** and reason them out loud.

**CVSS 3.1 Base metrics**

*Exploitability:*
- **AV — Attack Vector:** Network (N) > Adjacent (A) > Local (L) > Physical (P)
- **AC — Attack Complexity:** Low (L) / High (H)
- **PR — Privileges Required:** None (N) / Low (L) / High (H)
- **UI — User Interaction:** None (N) / Required (R)

*Scope:*
- **S — Scope:** Unchanged (U) / Changed (C) — "Changed" if impact crosses beyond the vulnerable component's security authority (sandbox escape; stored XSS hitting other users). Pushes score up a lot.

*Impact (CIA):*
- **C / I / A — Confidentiality / Integrity / Availability:** None / Low / High each

**Score bands:** 0.0 None · 0.1–3.9 Low · 4.0–6.9 Medium · 7.0–8.9 High · 9.0–10.0 Critical

**Worked examples (say the vector, then the band):**
- **Unauthenticated SQLi dumping DB:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **9.8 Critical**
- **Stored XSS, authenticated, hits other users:** `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` → ~5.4–6.x **Medium** (S:C because it crosses into others' context; push C/I up → High if it enables ATO)
- **Reflected XSS needing a click:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` → ~6.1 **Medium**
- **IDOR reading others' PII, low-priv account:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → ~6.5 **Medium** (High if write too)
- **SSRF → cloud metadata → cred theft:** push C:H, often S:C → **High/Critical**
- **CSRF changing email (ATO path):** `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` → ~8.0 **High**

**How to talk CVSS in the challenge:** narrate each metric and *why*. "Attack vector network — exploitable over the internet. Privileges required low — needs a basic account. UI none. Scope unchanged — stays within the app's authority. Confidentiality high — exposes other users' PII; integrity/availability none. That's ~6.5, Medium." The **reasoning** scores higher than the exact decimal.

**Practice tool:** FIRST.org CVSS 3.1 calculator (first.org/cvss/calculator/3.1) and the 4.0 one. Do ~10 vulns end-to-end before Monday.

---

## 6. The Challenge / live triage round — how to NOT fail it

This is where the earlier candidate was rejected despite good theory (one review felt the grader wanted a *specific, structured* answer, not just correct facts). **Use this exact out-loud framework every time:**

1. **Restate the claim.** "The researcher claims a stored XSS in the profile-name field."
2. **Check scope & policy.** "First I'd confirm the asset is in scope per the program policy."
3. **Assess info completeness.** "Report has URL, payload, steps — enough to reproduce. If repro steps were missing I'd move it to Needs More Info and ask specifically for X."
4. **Reproduce (describe how).** "Two test accounts: inject as user A, load the page as user B in a clean session to confirm it fires in another user's context."
5. **Determine validity & impact.** "Confirmed — fires for other users, so valid stored XSS, not self-XSS."
6. **Score severity (CVSS, narrated).** Walk the metrics (Section 5).
7. **State verdict + next state.** "I'd mark it **Triaged**, severity Medium (6.1), escalate to the customer."
8. **Write the summary** (template below).
9. **Communicate.** "Thank the researcher; if anything's missing, ask precisely."

**Triage summary template (memorise):**
```
Summary:   [one line — what & where]
Validity:  Valid / Needs More Info / N/A / Duplicate / Informative — [reason]
Steps to Reproduce:
  1. ...
  2. ...
Impact:    [what an attacker achieves + who is affected]
Severity:  [CVSS vector] → [score] ([band])
Remediation: [specific, actionable fix]
```

**Decisiveness wins.** Always: clear verdict + concrete reason + severity with reasoning. Say "I'd mark it X because Y" — commit. Avoid bare "it depends" without saying what it depends on.

**Traps in the given reports:**
- **Self-XSS** sold as XSS → low/informative unless chained
- **Missing repro steps** → Needs More Info, not instant reject
- **Out-of-scope asset** → N/A even if technically a bug
- **Obvious dupe** → Duplicate
- **Theoretical, no demonstrated impact** → Informative
- **Hacker over-inflated severity** → re-score down, with reasoning
- **Missing-security-header-only** (no CSP/HSTS, no exploit) → usually Informative/Low

---

## 7. Situational / behavioural — WITH answers
*(Weighted heavily: the job is repetitive, communication-heavy, shift-based. These are real reported questions.)*

**"If you get the same kind of report repeatedly, how do you stay motivated / avoid boredom?"** *(asked verbatim, multiple times)*
> "Consistency is the point — a customer trusts that every report gets the same rigorous validation whether it's my first XSS of the day or my fiftieth. I keep sharp by raising my own bar: clearer summary, tighter repro, cleaner CVSS reasoning. And volume is where patterns show up — recurring root causes across reports are genuinely interesting and worth flagging to improve a program. If fatigue hits, I rotate tasks, take short resets, and lean on the team."

**"How do you handle burnout / high-pressure situations and stay effective in a team?"**
> "I manage energy, not just time — batch similar work, protect focus for harder reproductions, and flag early if I'm overloaded rather than let quality slip. Under pressure, like a critical vuln on a major customer, I slow down just enough to be methodical: reproduce carefully, score accurately, communicate clearly. Panic causes mistakes; a calm checklist doesn't."

**"How would you approach triaging a real-world vulnerability report?"**
> Walk the Section 6 framework out loud — that *is* the answer.

**"A hacker disagrees with your N/A decision and is upset. What do you do?"**
> "Stay respectful and factual. Explain precisely why — which policy, scope, or missing-impact point drove it — referencing the program's rules, not making it personal. If they bring new evidence that changes the picture, I'd happily reopen; being right matters more than being consistent. The researcher community is the heart of HackerOne, so the tone stays collaborative even in disagreement."

**"A report has a working PoC but you can't reproduce it. Now what?"**
> "I don't jump to N/A. I recheck my environment — different account, role, browser, region, timing, any preconditions they mentioned. If I still can't, I move it to Needs More Info and ask for specific missing details: exact account state, headers, a video, timing. I only close it after a genuine good-faith attempt and clear communication."

**"Why HackerOne?"**
> "It's where I get exposure to real vulnerabilities across some of the best programs in the world — Anthropic, GM, Goldman, DoD — working alongside top researchers. I come from finding and validating bugs hands-on; this role lets me sharpen that validation and communication at scale, and learn from the global hacker community in a way no single in-house role could."

**"Why move from your current role / from development?"**
> "My move from backend engineering into AppSec gave me both sides: how software is built securely and how it breaks. This is the natural next step — pure signal, validating real findings all day, which deepens exactly the skill I want to master, with broader exposure than a single-company scope."

**"Tell me about yourself."**
> 45 sec: name, ~2 years hands-on manual VAPT across web/API/Android at CyRAACS, 200+ validated vulns, backend engineering background giving code-level context, CEH v13 + CNSP, a Springer research paper, and you're drawn to triage because validating and clearly communicating findings is what you're best at.

**"Comfortable with weekend shifts / US-hours overlap, on-site Pune?"**
> Be clear and affirmative if yes: "Yes — I understand the role needs weekend coverage and office presence, and I'm fully on board." They screen this hard; don't be vague.

**"Where do you see yourself in 5 years?"**
> "Growing into a senior triage/AppSec specialist — deeper technical mastery, mentoring newer analysts, contributing to how the team scales triage quality. I want the judgement that comes from seeing thousands of real-world reports."

**"What do you think HackerOne is lacking / how could we improve?"** *(a real closing question)*
> Tactful, constructive: "From outside I'd hold any opinion lightly — but one thing the whole industry is racing on is balancing AI-assisted triage with human judgement: keeping speed without losing accuracy or the researcher relationship. I'd be curious how the team is thinking about that." (Ties to their AI-First direction / Hai Triage.)

**"What culture do you thrive in?"**
> "Collaborative, high-trust, feedback-driven — people share knowledge openly and quality is a shared standard. Maps to your 'Win Together' value."

---

## 8. HackerOne values (weave in naturally)
- **Customer Obsessed** — prioritise customer outcomes
- **Default to Disclosure** — transparency and integrity
- **Win Together** — empowerment, inclusion, accountability
- **AI-First** — they push AI-assisted triage (Hai Triage). Being comfortable *using AI to work faster while keeping human judgement* is a plus.

---

## 9. Smart questions to ask them (pick 2–3)
- "What distinguishes the Product Security Analyst role from the Triage Analyst role internally?"
- "What's the day-to-day report mix — which vulnerability classes and kinds of programs would I mostly handle?"
- "How is the team using AI / Hai Triage today, and how does that change the analyst's role?"
- "What does success look like in the first 3–6 months?"
- "What's the growth path — senior analyst, specialisation, team lead?"

*(Handle salary/shifts with the recruiter, not as your curiosity question.)*

---

## 10. Your 3-day study plan

**Day 1 (Fri) — Theory fluency**
- Drill Section 3: for every vuln, say *what → verify → impact → fix* out loud, no notes.
- Read HackerOne docs: Report States, Severity, CVSS pages (docs.hackerone.com).
- Memorise the Section 4 decision tree + report states.

**Day 2 (Sat) — CVSS + triage reps**
- FIRST.org CVSS 3.1 calculator: score 10 vulns, narrate each vector.
- Read 10–15 **disclosed reports on hackerone.com/hacktivity** — for each, predict: valid? state? severity? Then compare to the real outcome. **Highest-value exercise; your bug-bounty substitute.**
- Run the Section 6 framework out loud on 5 of them.

**Day 3 (Sun) — Mock + behavioural + polish**
- Full out-loud mock: someone hands you a report; triage end-to-end with the framework + template.
- Rehearse every Section 7 answer in your own words (know the beats, don't memorise verbatim).
- Re-read HackerOne values; prep your 2–3 questions.
- Logistics: quiet space, stable internet, Burp ready if they screen-share, water, calm.

---

## 11. Night-before checklist
- [ ] Explain XSS/CSRF/SQLi/IDOR/SSRF/CORS with impact + fix, cold
- [ ] Produce a CVSS vector + band for any vuln, narrated
- [ ] Know all report states + when each applies
- [ ] Triage framework + summary template memorised
- [ ] Behavioural answers rehearsed (boredom, burnout, hacker disagreement, why H1)
- [ ] 2–3 questions ready
- [ ] Confirmed OK with weekend shifts / on-site, stated clearly
- [ ] Logistics sorted

---

### Final note
Your real edge: you genuinely validate vulnerabilities for a living, and you read code. Most triage candidates only know theory. Lead with **structure and decisiveness** in the challenge round — verdict, reason, severity — and you clear the exact bar that tripped the last candidate. Good luck Monday.
