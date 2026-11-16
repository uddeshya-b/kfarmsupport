import pandas as pd
import streamlit as st
from core import Core
from checks import run_all

st.set_page_config(page_title="K-FarmSupport", page_icon="🌾", layout="wide")
st.title("🌾 K-FarmSupport prototype")
st.caption("Educational prototype. Fictional farmers and applications only. Not a government service.")

build = st.sidebar.radio("Build", ["Secure build", "Vulnerable build (demo only)"])
secure = build == "Secure build"
if st.session_state.get("secure") != secure:
    st.session_state.update(secure=secure, core=Core(secure), token=None)
core, token = st.session_state.core, st.session_state.token
st.sidebar.markdown("**Demo logins**\n\nadmin / Admin#2026\n\nkim / kim-pass-1\n\nlee / lee-pass-1")
(st.sidebar.success if secure else st.sidebar.error)("Controls ON" if secure else "Controls OFF: deliberately weak")

def show(rows):
    df = pd.DataFrame(rows, columns=["ID", "Owner", "Farm", "Note", "Status"])
    df["Note"] = df["Note"].map(core.render_note)
    st.markdown(df.to_html(escape=False, index=False), unsafe_allow_html=True)

ERR = object()

def attempt(fn, *a):
    try:
        return fn(*a)
    except Exception as e:
        st.error(str(e))
        return ERR

tab_app, tab_sec, tab_info = st.tabs(["1. The app", "2. Security tests", "3. How it works"])

with tab_app:
    s = core.who(token) if token else None
    if not s:
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Log in")
            u = st.text_input("Username", key="lu")
            p = st.text_input("Password", type="password", key="lp")
            if st.button("Log in"):
                t = attempt(core.login, u, p)
                if t is not ERR:
                    st.session_state.token = t
                    st.rerun()
        with c2:
            st.subheader("Register as a farmer")
            ru = st.text_input("New username", key="ru")
            rp = st.text_input("New password", type="password", key="rp")
            if st.button("Register"):
                if attempt(core.register, ru, rp) is not ERR:
                    st.success("Registered. You can log in now.")
    else:
        st.success(f"Logged in as {s['user']} ({s['role']})")
        if st.button("Log out"):
            core.logout(token)
            st.session_state.token = None
            st.rerun()
        if s["role"] == "farmer":
            st.subheader("Submit an application")
            farm = st.text_input("Farm name")
            note = st.text_area("Note", max_chars=500)
            if st.button("Submit"):
                if attempt(core.create_app, token, farm, note) is not ERR:
                    st.rerun()
            st.subheader("My applications")
            show(core.my_apps(token))
            with st.expander("Try attacks as this farmer (live demo)"):
                aid = st.number_input("Open application ID", 1, 99, 2)
                if st.button("Open it"):
                    r = attempt(core.get_app, token, int(aid))
                    if r is not ERR: show([r])
                if st.button("Open admin dashboard"):
                    r = attempt(core.all_apps, token)
                    if r is not ERR: show(r)
                if st.button("Approve application 1"):
                    if attempt(core.set_status, token, 1, "Approved") is not ERR:
                        st.warning("Request went through (see audit log in secure build).")
        else:
            st.subheader("All applications")
            show(core.all_apps(token))
            aid = st.number_input("Application ID", 1, 99, 1)
            stt = st.selectbox("New status", ["Pending", "Approved", "Rejected"])
            if st.button("Update status"):
                if attempt(core.set_status, token, int(aid), stt) is not ERR:
                    st.rerun()
            st.subheader("Audit log")
            log = core.audit(token)
            st.dataframe(pd.DataFrame(log, columns=["Time", "Who", "What"]) if log else pd.DataFrame(columns=["Time", "Who", "What"]), hide_index=True)
            if not secure:
                st.caption("The vulnerable build keeps no audit log.")

with tab_sec:
    st.write("Each attack runs against the real code in both builds. A fresh app is used per test.")
    if st.button("Run all attacks"):
        rows = run_all()
        v = sum(not r["Vulnerable build_ok"] for r in rows)
        x = sum(not r["Secure build_ok"] for r in rows)
        a, b = st.columns(2)
        a.metric("Attacks that worked: vulnerable build", f"{v} / {len(rows)}")
        b.metric("Attacks that worked: secure build", f"{x} / {len(rows)}")
        st.dataframe(pd.DataFrame(rows)[["Threat", "Test", "Vulnerable build", "Secure build"]], hide_index=True, use_container_width=True)

with tab_info:
    st.markdown("""
**Controls in the secure build** (all in `core.py`, one comment per control):
password hashing, parameterized SQL, lockout after 5 wrong logins, random expiring session tokens,
owner check on every record, admin-only role checks, input validation, output encoding,
rate limiting, and an audit log.

**Not covered here:** HTTPS (a deployment setting), real government systems, payments, backups.
""")
