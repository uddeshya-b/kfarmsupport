"""Runs each attack against BOTH builds using the real code in core.py.
attack_worked=True means the app was exposed."""
import base64
from core import Core

def _kim(c): return c.login("kim", "kim-pass-1")

def t_idor(c):
    return c.get_app(_kim(c), 2)[2]
def t_admin(c):
    return len(c.all_apps(_kim(c)))
def t_tamper(c):
    k = _kim(c); c.set_status(k, 1, "Approved"); return "A1 became Approved"
def t_sqli(c):
    return c.login("' OR '1'='1", "' OR '1'='1") and "logged in without a password"
def t_brute(c):
    for i, p in enumerate(["0000", "1111", "password", "qwerty", "abcd", "kim-pass-1"], 1):
        try:
            c.login("kim", p); return f"guess {i} got in"
        except PermissionError:
            pass
    raise PermissionError("locked out before guess 6")
def t_xss(c):
    k = _kim(c); c.create_app(k, "Test farm", "<script>steal()</script>")
    out = c.render_note(c.my_apps(k)[-1][3])
    if "<script>" in out: return "raw script reaches the page"
    raise ValueError("encoded as " + out)
def t_forge(c):
    return len(c.all_apps(base64.b64encode(b"admin").decode()))
def t_audit(c):
    c.set_status(c.login("admin", "Admin#2026"), 2, "Approved")
    log = c.audit(c.login("admin", "Admin#2026"))
    if any("set application 2" in r[2] for r in log): raise ValueError("entry saved with actor and time")
    return "no log: admin can deny it"
def t_store(c):
    p = c.db.execute("SELECT password FROM users WHERE username='kim'").fetchone()[0]
    if p == "kim-pass-1": return "passwords stored as plain text"
    raise ValueError("stored as salted hash")
def t_flood(c):
    k = _kim(c); ok = 0
    for _ in range(50):
        try: c.create_app(k, "Flood farm", "x"); ok += 1
        except PermissionError: pass
    if ok == 50: return "all 50 accepted"
    raise PermissionError(f"{ok} accepted, {50 - ok} blocked")
def t_input(c):
    c.register("bad name;--", "x"); return "junk username and weak password accepted"

TESTS = [("T06", "Farmer reads another farmer's form", t_idor), ("T07", "Farmer opens admin page", t_admin),
         ("T04", "Farmer approves own application", t_tamper), ("T05", "SQL text in login box", t_sqli),
         ("T02", "Password guessing (6 tries)", t_brute), ("T05", "Script saved in a note (XSS)", t_xss),
         ("T09", "Forged session token", t_forge), ("T08", "Admin denies a change (audit log)", t_audit),
         ("T01", "Password storage", t_store), ("T11", "50 requests in a second", t_flood),
         ("T03", "Junk or weak sign-up input", t_input)]

def run_all():
    rows = []
    for tid, name, fn in TESTS:
        r = {"Threat": tid, "Test": name}
        for label, sec in (("Vulnerable build", False), ("Secure build", True)):
            try:
                r[label] = ("ATTACK WORKED: " + str(fn(Core(sec)))); r[label + "_ok"] = False
            except Exception as e:
                r[label] = "Blocked: " + str(e); r[label + "_ok"] = True
        rows.append(r)
    return rows

if __name__ == "__main__":
    for r in run_all():
        print(f"{r['Threat']} {r['Test']}\n   vulnerable: {r['Vulnerable build']}\n   secure:     {r['Secure build']}")
