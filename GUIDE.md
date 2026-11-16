# K-FarmSupport prototype: how to run it and explain it

## 1. Run it (5 minutes)
1. Install Python 3.10+ from python.org.
2. Put these files in one folder: `app.py`, `core.py`, `checks.py`, `requirements.txt`.
3. Open a terminal in that folder and run:
   ```
   pip install -r requirements.txt
   streamlit run app.py
   ```
4. Your browser opens the app. To stop it, press Ctrl+C in the terminal.
5. Evidence without the browser: `python checks.py` prints every test result as text. Screenshot it for your report.

## 2. What the files are
| File | What it does |
|---|---|
| `core.py` | The "backend": login, applications, admin actions, audit log. Every security control is here, with a comment on its line. |
| `checks.py` | 11 attack tests. Each one runs against the vulnerable and the secure build and records the result. |
| `app.py` | The Streamlit screens. It only calls `core.py`, so security is enforced on the "server", not in the buttons. |

The sidebar switch changes one flag, `secure=True/False`, in `core.py`. Same app, controls on or off.

## 3. Five-minute demo script
1. **Say:** "This is K-FarmSupport, an educational prototype with fictional data. The same code runs in two builds."
2. Pick **Vulnerable build**. Log in as `kim / kim-pass-1`. Open "Try attacks as this farmer" and open application ID 2. It shows lee's farm. **Say:** "Kim read another farmer's record. That is T06, information disclosure."
3. Click "Open admin dashboard" and "Approve application 1". Both work. **Say:** "Elevation of privilege and tampering, T07 and T04."
4. Log out. Log in with username `' OR '1'='1` and the same text as the password. You get in as admin. **Say:** "SQL injection, because the build joins strings into the SQL."
5. Switch to **Secure build**. Repeat steps 2 to 4. Each one is refused with a 403 or a wrong-password message.
6. Log in as `admin / Admin#2026` and show the **Audit log**. It records the denied attempts with who and when.
7. Open **2. Security tests** and click **Run all attacks**. **Say:** "11 of 11 attacks worked on the vulnerable build and 0 of 11 on the secure build."

## 4. Map to the course checklist
| Criterion | Where to show it |
|---|---|
| Problem, users, scope | Your Week 1 and 2 notes; the app has two roles, farmer and admin |
| Architecture, DFD, trust boundaries | Your DFD: browser (`app.py`), service layer (`core.py`), database (SQLite), audit log table |
| STRIDE and OSI | `checks.py` test IDs match your threat IDs (T02, T04 to T09, T11) |
| Risk scoring | Your Week 2 risk table. The tests show the top risks are real |
| Controls and traceability | Comments in `core.py` map to the mitigation table, and each control has a test |
| Safe testing, evidence, residual risk | Security tests tab and `python checks.py`; the limits are in section 6 |
| Clarity, teamwork, references | Each member explains one file |

## 5. How to explain each control (one line each)
- **Parameterized queries:** user text is passed as data, never as SQL code, so `' OR '1'='1` does nothing.
- **Password hashing:** the database stores a salted hash, so a stolen database does not reveal passwords.
- **Lockout:** 5 wrong logins in a minute locks the account, which stops guessing.
- **Random expiring sessions:** the token is a long random value held on the server, so it cannot be invented.
- **Owner check:** the server compares the record's owner to the logged-in user. The browser's word is never trusted.
- **Role check:** admin functions refuse anyone who is not an admin.
- **Output encoding:** `<script>` is shown as text and never runs.
- **Rate limiting:** after 10 submissions a minute, the rest get a 429.
- **Audit log:** every sensitive action is written with who and when, so an admin cannot deny it.

## 6. Be honest about limits (professors respect this)
- It is a prototype with fictional data. There is no real government link and no payments.
- HTTPS is a deployment setting. This local demo runs on plain HTTP, so the network-sniffing threat (T10) is not tested here. You can say it would be handled by TLS on the host.
- Fake accounts (T03) are only partly covered by input validation. Backups (T12) are not covered.
- The tests are written by us against our own code. They show the controls work for these cases, not that the app is unbreakable.
- The audit log is in memory, and sessions and data reset when the app restarts. A real build would use a protected database.

## 7. Questions the professor may ask
- **"Why two builds?"** To get a baseline and a retest, which is what the brief asks for.
- **"Is the vulnerable build dangerous?"** It only runs on your own computer with fictional data, which is the authorized lab setup the brief requires.
- **"What would you add next?"** MFA, HTTPS deployment, a persistent hashed audit log, and more tests such as session expiry.
- **"How do the tests prove anything?"** Each test calls the real function with attacker-style input and checks whether the action succeeded. You can read the code in `checks.py`.
