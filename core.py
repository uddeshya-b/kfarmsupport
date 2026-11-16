"""K-FarmSupport service layer. Fictional data only.
secure=True  -> real controls ON.   secure=False -> deliberately weak (for the before/after demo)."""
import sqlite3, hashlib, hmac, secrets, time, html, re, base64

STATUSES = ("Pending", "Approved", "Rejected")


class Core:
    def __init__(self, secure=True):
        self.secure = secure
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.sessions, self.fails, self.hits = {}, {}, {}
        self.db.executescript("""
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE apps(id INTEGER PRIMARY KEY, owner TEXT, farm TEXT, note TEXT, status TEXT);
        CREATE TABLE audit(id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, action TEXT);""")
        for u, p, r in [("admin", "Admin#2026", "admin"), ("kim", "kim-pass-1", "farmer"), ("lee", "lee-pass-1", "farmer")]:
            self.db.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)", (u, self._store(p), r))
        self.db.execute("INSERT INTO apps(owner,farm,note,status) VALUES('kim','Pear orchard','Needs irrigation help','Pending')")
        self.db.execute("INSERT INTO apps(owner,farm,note,status) VALUES('lee','Rice paddy','Storm damage','Pending')")

    # ---- helpers
    def _store(self, pw):  # control: salted password hashing
        if not self.secure:
            return pw
        salt = secrets.token_hex(8)
        return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()

    def _ok_pw(self, stored, pw):
        if not self.secure:
            return stored == pw
        salt, h = stored.split("$")
        return hmac.compare_digest(h, hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex())

    def _log(self, actor, action):  # control: audit log (secure build only)
        if self.secure:
            self.db.execute("INSERT INTO audit(ts,actor,action) VALUES(?,?,?)",
                            (time.strftime("%H:%M:%S"), actor, action))

    def _allow(self, key, limit, window):  # control: rate limit
        if not self.secure:
            return True
        now = time.time()
        h = [t for t in self.hits.get(key, []) if now - t < window]
        if len(h) >= limit:
            self.hits[key] = h
            return False
        self.hits[key] = h + [now]
        return True

    def who(self, token):
        if self.secure:  # control: random server-side sessions with expiry
            s = self.sessions.get(token)
            if s and s["exp"] > time.time():
                return s
            self.sessions.pop(token, None)
            return None
        try:  # weak build: token is just the encoded username
            u = base64.b64decode(token).decode()
            r = self.db.execute("SELECT username, role FROM users WHERE username=?", (u,)).fetchone()
            return {"user": r[0], "role": r[1]} if r else None
        except Exception:
            return None

    def _need(self, token):
        s = self.who(token)
        if not s:
            raise PermissionError("401: please log in")
        return s

    # ---- accounts
    def register(self, u, p):
        if self.secure and (not re.fullmatch(r"[a-z0-9_]{3,20}", u) or len(p) < 8):  # control: input validation
            raise ValueError("Username: 3-20 chars a-z 0-9 _. Password: 8+ chars.")
        try:
            self.db.execute("INSERT INTO users(username,password,role) VALUES(?,?,'farmer')", (u, self._store(p)))
        except sqlite3.IntegrityError:
            raise ValueError("Username already taken")
        self._log(u, "registered")

    def login(self, u, p):
        if not self.secure:  # weak: SQL built by string joining, no lockout
            try:
                r = self.db.execute(f"SELECT username, role FROM users WHERE username='{u}' AND password='{p}'").fetchone()
            except sqlite3.Error:
                r = None
            if not r:
                raise PermissionError("Wrong username or password")
            return base64.b64encode(r[0].encode()).decode()
        if not self._allow("login:" + u, 5, 60):  # control: lockout after 5 tries / minute
            self._log(u, "login blocked (too many tries)")
            raise PermissionError("Too many attempts. Try again in a minute.")
        r = self.db.execute("SELECT password, role FROM users WHERE username=?", (u,)).fetchone()  # control: parameterized query
        if not r or not self._ok_pw(r[0], p):
            self._log(u, "failed login")
            raise PermissionError("Wrong username or password")
        t = secrets.token_urlsafe(32)
        self.sessions[t] = {"user": u, "role": r[1], "exp": time.time() + 900}
        self._log(u, "login ok")
        return t

    def logout(self, token):
        s = self.sessions.pop(token, None)
        if s:
            self._log(s["user"], "logout")

    # ---- applications
    def create_app(self, token, farm, note):
        s = self._need(token)
        if not self._allow("create:" + s["user"], 10, 60):
            raise PermissionError("429: too many requests")
        if self.secure and (not re.fullmatch(r"[A-Za-z0-9 .,'-]{2,60}", farm) or len(note) > 200):
            raise ValueError("Farm name: 2-60 letters/numbers. Note: max 200 chars.")
        self.db.execute("INSERT INTO apps(owner,farm,note,status) VALUES(?,?,?,'Pending')", (s["user"], farm, note))
        self._log(s["user"], "created application")

    def get_app(self, token, app_id):
        s = self._need(token)
        r = self.db.execute("SELECT id,owner,farm,note,status FROM apps WHERE id=?", (app_id,)).fetchone()
        if not r:
            raise LookupError("404: not found")
        if self.secure and r[1] != s["user"] and s["role"] != "admin":  # control: object-level authorization
            self._log(s["user"], f"DENIED read of application {app_id}")
            raise PermissionError("403: not your application")
        return r

    def my_apps(self, token):
        s = self._need(token)
        return self.db.execute("SELECT id,owner,farm,note,status FROM apps WHERE owner=?", (s["user"],)).fetchall()

    def all_apps(self, token):
        s = self._need(token)
        if self.secure and s["role"] != "admin":  # control: server-side role check
            self._log(s["user"], "DENIED admin page")
            raise PermissionError("403: admin only")
        return self.db.execute("SELECT id,owner,farm,note,status FROM apps").fetchall()

    def set_status(self, token, app_id, status):
        s = self._need(token)
        if self.secure and (s["role"] != "admin" or status not in STATUSES):
            self._log(s["user"], f"DENIED status change on {app_id}")
            raise PermissionError("403: admin only")
        self.db.execute("UPDATE apps SET status=? WHERE id=?", (status, app_id))
        self._log(s["user"], f"set application {app_id} to {status}")

    def audit(self, token):
        s = self._need(token)
        if s["role"] != "admin":
            raise PermissionError("403: admin only")
        return self.db.execute("SELECT ts,actor,action FROM audit").fetchall()

    def render_note(self, text):  # control: output encoding
        return html.escape(text) if self.secure else text
