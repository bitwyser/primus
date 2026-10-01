# 100 PwC AppSec / VAPT / Pentesting Interview Questions

Compiled from Glassdoor PwC interview reports, Naukri/AmbitionBox/Code360 candidate
experiences, and the recurring technical question banks used across Big-4 and industry
AppSec/pentest interviews (GitHub security-interview-question repos, InfoSec training
sites, Teal/Interview Baba, Practical DevSecOps). Section 1 contains questions **actually
reported by candidates who interviewed at PwC**; the rest are the standard technical
question set that shows up in PwC AppSec/VAPT/Cyber Security rounds for your exact
profile (Web, API, Android, SDLC, Threat Modelling, SAST/DAST, Cloud, HTTP/S, Auth).

---

## 1. Questions Actually Reported in PwC Interviews (Glassdoor / Naukri / Code360)

1. Walk us through how attacks like XSS, SQL injection, and file upload vulnerabilities happen, and how an attacker would bypass basic filters for each. *(PwC — Junior Penetration Tester, Glassdoor)*
2. How would you lead a junior tester through a full penetration test? Describe the process end to end. *(PwC — Junior Penetration Tester, Glassdoor)*
3. Describe CORS and how you would mitigate a CORS misconfiguration. *(PwC — Junior Penetration Tester, Glassdoor, Italy office)*
4. Tell us about a time in a previous role where you hit a difficult technical problem and how you overcame it. *(PwC — Cyber Security round, Glassdoor)*
5. Talk about a time you showed curiosity that led to a positive outcome on a project. *(PwC — Cyber Security video-interview round, Glassdoor)*
6. Walk through a recent finding from a security assessment/hackathon you worked on — what was it and how did you validate it? *(PwC India Launchpad/Hackathon program, Code360 candidate reports)*
7. Core CS fundamentals round: DSA, OOP concepts, DBMS, Operating Systems, Linux, and SQL basics before the security-specific questions. *(PwC AC India / Launchpad, Naukri Code360)*
8. Resume deep-dive: be ready to explain every project and technology on your resume in detail — this is a heavily used PwC technical-round format. *(PwC Interview process, InterviewBit/Btree Systems reports)*
9. Case-study / scenario round: "how would you handle X situation with a client" — common in PwC's video-interview and case-based rounds. *(PwC Cyber Security round, Glassdoor)*
10. Why PwC, and why cybersecurity/advisory over industry-side security roles? *(Standard PwC HR round question asked across all technical tracks)*

---

## 2. Web Application Security & OWASP Top 10

11. Walk through your top 3 favourite OWASP Top 10 vulnerabilities and explain why you picked them.
12. What is SQL Injection, and what are the different types (in-band, blind boolean, blind time-based, out-of-band)? How do you prevent it?
13. Explain XSS — Reflected, Stored, and DOM-based — with a real example of each.
14. What is CSRF? How is it different from XSS, and what controls actually stop it (SameSite cookies, CSRF tokens, double-submit cookie)?
15. Explain SOP (Same-Origin Policy), CORS, and CSP from a security standpoint, and how they interact.
16. What is SSRF? How can an attacker escalate an SSRF finding into cloud credential theft (e.g., via the 169.254.169.254 metadata endpoint)?
17. What's the difference between IDOR and BOLA — are they the same thing?
18. How would you identify and exploit an XXE (XML External Entity) vulnerability?
19. Explain insecure deserialization and why it's dangerous in Java/.NET/PHP applications.
20. How do you test for and prevent open redirect vulnerabilities?
21. What is clickjacking, and how do X-Frame-Options / CSP frame-ancestors prevent it?
22. Explain HTTP request smuggling and why it's hard to detect with a single proxy.
23. What security headers would you expect to see on a hardened web app (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, etc.), and what does each protect against?
24. How would you test a file-upload feature for security issues, and how would you bypass a weak extension/MIME-type filter?
25. What is a race condition vulnerability in web apps, and how would you test for one (e.g., in a coupon-redemption or wallet-top-up flow)?

---

## 3. VAPT / Penetration Testing Methodology & Tools

26. What's the difference between Vulnerability Assessment and Penetration Testing?
27. Walk through your standard VAPT methodology end to end — scoping, recon, scanning, exploitation, post-exploitation, reporting, retesting.
28. Which industry methodologies/standards do you align testing to (OWASP WSTG/ASVS, PTES, NIST SP 800-115, OSSTMM)?
29. What's the difference between black-box, grey-box, and white-box testing, and when would you recommend each to a client?
30. Which tools do you use day to day, and what's each one for (Burp Suite, Nmap, Nessus/Nikto, Metasploit, sqlmap, ffuf/gobuster)?
31. How do you handle false positives from an automated scanner during a VAPT engagement?
32. Describe how you'd perform post-exploitation and lateral movement once you've got an initial foothold, while staying within scope.
33. How do you write a vulnerability report that both a developer and a CISO/board member would find useful?
34. How do you assign a CVSS score to a finding, and where do business context and CVSS score sometimes disagree?
35. Tell me about the last vulnerability you found — what was it, how did you find it, and what was the business impact?
36. How would you scope and safely test a production environment without disrupting business operations?
37. What's your process for retesting a fixed vulnerability, and what do you check beyond "does the original PoC still work"?
38. How do you keep yourself updated on new vulnerability classes, CVEs, and attacker techniques?

---

## 4. API Security (REST / GraphQL)

39. Why is API security treated as a distinct discipline from general web security now?
40. Walk through the OWASP API Security Top 10 (2023) and give a one-line description of each.
41. What is Broken Object Level Authorization (BOLA/IDOR), and why does it remain the #1 API vulnerability year after year?
42. What is mass assignment, and why do modern frameworks make it easy to introduce accidentally?
43. What's the difference between Broken Object Level Authorization (API1) and Broken Function Level Authorization (API5)?
44. How should rate limiting for an API differ from rate limiting a login form?
45. What is a Shadow API, and how do organisations end up with them?
46. How would you test a REST API for authorization flaws when you only have a Swagger/Postman collection?
47. What GraphQL-specific attack would you look for that has no direct REST equivalent (hint: nested/aliased queries)?
48. How would you approach unsafe consumption of third-party APIs (API10) during a review?
49. What security responsibilities belong at the API gateway versus inside each individual microservice?
50. How would you test an API for SSRF via a "fetch this URL"/webhook/import feature?

---

## 5. Authentication & Authorization — JWT, OAuth2, SAML, SSO

51. Explain the difference between authentication and authorization, and why interviewers always test whether you can separate the two.
52. What should a security review specifically check about JWT usage (algorithm confirmation, `exp`, revocation, payload contents, storage location)?
53. Explain the `alg: none` JWT attack and the RS256-to-HS256 key-confusion attack — how do both work, and how do you prevent them?
54. Where should a JWT be stored client-side — localStorage, sessionStorage, or an httpOnly cookie — and what are the trade-offs?
55. Walk through the OAuth 2.0 Authorization Code flow (with PKCE) end to end. Why is PKCE needed for public/mobile clients?
56. What's the difference between OAuth2 and OpenID Connect (OIDC)? Why do people confuse "logging in with Google" with OAuth when it's actually OIDC?
57. Explain how SAML SSO works — what is the difference between an SP-initiated and an IdP-initiated flow?
58. What is a SAML signature-wrapping attack, and why is XML signature validation so tricky to get right?
59. Explain the difference between SAML and OAuth/OIDC, and when you'd recommend one over the other to a client.
60. What is token replay, and how do nonce, `aud` claim validation, and short expiry protect against it?
61. How would you design secure session management for a web app (cookie flags: Secure, HttpOnly, SameSite; session fixation prevention; idle/absolute timeout)?
62. Explain multi-factor authentication bypass techniques you've seen in real assessments (e.g., response manipulation, missing MFA on API endpoints, OTP brute-force).
63. How do you test for privilege escalation — both vertical (user to admin) and horizontal (user to user)?

---

## 6. Android / Mobile Application Security

64. What's your general methodology for testing an Android application (static + dynamic)?
65. How would you set up Burp Suite / a proxy to intercept traffic from an Android app on a real device or emulator?
66. What is certificate pinning, and how do you bypass it during a pentest (Frida, Objection, patching the APK)?
67. What are the key files/artefacts you look at when statically analysing an APK (AndroidManifest.xml, decompiled smali/Java via jadx, shared preferences, local DBs)?
68. How does Android's permission model work, and what would you flag as an over-privileged app?
69. What insecure data storage issues are common in Android apps (plaintext SharedPreferences, unencrypted SQLite, logs, backups)?
70. How would you test for insecure inter-process communication — exported Activities, Broadcast Receivers, Content Providers, and intent hijacking?
71. What is root/jailbreak detection, and how would you bypass it to continue dynamic testing?

---

## 7. Cloud Security

72. What are the top cloud misconfigurations you'd check for in an AWS/Azure/GCP environment (public S3 buckets, open security groups, over-permissive IAM roles)?
73. How does SSRF become critical specifically in a cloud environment (instance metadata service, IMDSv1 vs IMDSv2)?
74. Explain the shared responsibility model — where does the cloud provider's responsibility end and the customer's begin?
75. How would you review IAM policies for least privilege, and what's a common over-permissioning mistake you see?
76. What's the difference between a security group and a NACL in AWS, and why does it matter for a pentest?
77. How would you approach threat modelling for a cloud-native/microservices application differently than a monolith?
78. What's mTLS, and why is it not sufficient on its own for service-to-service authorization in a service mesh?
79. How would you secure secrets (API keys, DB credentials) in a CI/CD pipeline and cloud-native application (vault solutions vs hardcoded/env vars)?

---

## 8. SDLC, Threat Modelling, SAST/DAST/SCA

80. At which phases of the SDLC should security activities be embedded, and what goes into each phase?
81. What's the difference between SAST, DAST, IAST, and SCA — and where does each fit in a CI/CD pipeline?
82. What's the difference between SAST and SCA specifically, since they're often confused?
83. Explain the STRIDE threat modelling methodology with one example of each threat category.
84. How do DREAD and MITRE ATT&CK differ from STRIDE, and when would you use each?
85. Walk through how you'd threat-model a new banking web application — what assets, trust boundaries, and data flows would you focus on first?
86. How would you integrate threat modelling into an Agile/sprint-based development process without slowing teams down?
87. How do you prioritise findings from a SAST scan full of noise/false positives for a development team?
88. Describe your approach to a manual secure code review — what do you look for first, and manual vs automated: which do you trust more, and why?
89. Identify the issue: a login endpoint hashes passwords using plain MD5 with no salt before storing them — what's wrong and what's the fix?
90. Identify the issue: an endpoint updates a user's email directly from `$_POST` with no CSRF token on a state-changing POST request — what's the vulnerability and the fix?
91. How would you evaluate and reduce the risk of vulnerable third-party/open-source dependencies flagged by an SCA tool?
92. What metrics would you track to prove an SDL/AppSec program is actually working?

---

## 9. HTTP/S, Networking & Cryptography Fundamentals

93. Walk through what happens end to end when you type a URL into a browser and hit Enter (DNS, TCP handshake, TLS handshake, HTTP request/response, rendering).
94. Explain the TCP three-way handshake and why it matters for understanding attacks like SYN floods.
95. How does TLS/SSL actually secure data in transit — client/server hello, key exchange, symmetric vs asymmetric use, and what is Perfect Forward Secrecy?
96. What is a weak cipher suite, and how would you identify one using `openssl` or testssl.sh during an assessment?
97. Explain the practical difference between encryption, hashing, salting, encoding, and obfuscation — a lot of candidates mix these up.
98. Why can a website secured with HTTPS still get hacked? What does TLS not protect against?
99. How would you design a secure password-storage and password-reset mechanism from scratch (hashing algorithm choice, salting, reset-token expiry/one-time-use)?
100. How would you defend a login/signup/forgot-password flow against brute-force and credential-stuffing attacks (CAPTCHA, rate limiting, account lockout, MFA, anomaly monitoring)?

---

## How to use this list
- Section 1 is what to over-prepare — these are the exact reported PwC questions.
- Sections 2–9 map directly to your profile (AppSec, VAPT, Web, API, Android, SDLC,
  Threat Modelling, SAST/DAST, Cloud, HTTP/S, Auth) and are the standard bank used
  by PwC's cyber/AppSec technical panel, since PwC's technical round is largely
  fundamentals + resume-project deep dive rather than PwC-proprietary trivia.
- For every "explain X" question, be ready with a live example from your own
  work at CyRAACS or Credility — interviewers consistently follow up theoretical
  answers with "have you actually found/fixed this yourself?"

### Sources
- Glassdoor: PwC Cyber Security & Junior Penetration Tester interview question reports
- Naukri Code360: PwC AC India / Launchpad candidate interview experiences
- GitHub: jassics/security-interview-questions (AppSec & API Security question banks)
- GitHub: InfoSecWarrior/Penetration-Testing-Interview-Questions
- Practical DevSecOps, InfoSecTrain, ThinkCloudly, Interview Baba, Teal — VAPT/threat modelling/mobile-API question banks
