#!/usr/bin/env python3
"""Null Proxy: admin panel + supervisor for mtprotoproxy.
- Fake-TLS, multi-user (persistent usage, quota, expiry), TCP endpoints managed from the panel
- Multi-sponsor: one mtprotoproxy per distinct AD_TAG, routed by TCP entry port
- Real health probe: a valid Fake-TLS ClientHello must be answered by the proxy (not just an open port)
- SOCKS5 (user/pass, shared users + usage) on any TCP, chosen per TCP
- "Railway" tab: every Railway TCP proxy (whole account / project), all probed in parallel, live
"""
import asyncio, hashlib, hmac, http.server, ipaddress, json, os, re, secrets, signal, socket, socketserver, subprocess
import threading, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
from http import cookies
from pathlib import Path
try: import segno
except ImportError: segno = None

E = os.environ.get
APP_DIR, HERE = E("MTP_DIR", "/app"), os.path.dirname(os.path.abspath(__file__))
BASE = int(E("PORT_MTG", "3128")); MAXEP = max(1, min(1000, int(E("MAX_ENDPOINTS", "100"))))
ENTRY = list(range(BASE, BASE + MAXEP))
IN0, MET0, MAXSP = int(E("INTERNAL_PORT", "4443")), 8888, 8        # instance slot i -> ports IN0+i / MET0+i
WEB = int(E("PANEL_PORT") or E("PORT") or 8080)
if WEB in ENTRY or IN0 <= WEB <= IN0 + MAXSP or MET0 <= WEB <= MET0 + MAXSP: WEB = 8080
RW_API = E("RAILWAY_API_URL", "https://backboard.railway.com/graphql/v2")
RW_ENV, RW_SVC, RW_PRJ = E("RAILWAY_ENVIRONMENT_ID", ""), E("RAILWAY_SERVICE_ID", ""), E("RAILWAY_PROJECT_ID", "")
SEED = RW_SVC + RW_PRJ + RW_ENV + "nullproxy"
HEX32, NAME_RE = re.compile(r"^[0-9a-f]{32}$"), re.compile(r"^[A-Za-z0-9_\-]{1,32}$")
DOMAIN_RE, DATE_RE = re.compile(r"^[A-Za-z0-9.\-]{3,253}$"), re.compile(r"^\d{4}-\d{2}-\d{2}$")
lock, START = threading.RLock(), time.time()
hexonly = lambda s: re.sub(r"[^0-9a-f]", "", str(s).lower())

def data_dir():
    for d in (E("DATA_DIR"), "/data"):
        if d and os.path.isdir(d) and os.access(d, os.W_OK): return d, True
    os.makedirs("/tmp/nullproxy", exist_ok=True); return "/tmp/nullproxy", False
DATA_DIR, PERSISTENT = data_dir()
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

EVENTS = []
def event(msg, kind="info"):
    EVENTS.append({"ts": int(time.time()), "kind": kind, "msg": msg}); del EVENTS[:-200]; print(f"[panel] {msg}")

# ---------------- settings ----------------
def default_secret():
    s = E("MTG_SECRET", "").lower()
    if s.startswith("ee") and HEX32.match(s[2:34]): return s[2:34]
    r = hexonly(E("MTG_RANDOM", ""))[:32]
    return r if len(r) == 32 else hashlib.sha256(SEED.encode()).hexdigest()[:32]

def new_user(secret=None, note=""):
    return {"secret": secret or secrets.token_hex(16), "max_conns": 0, "quota_gb": 0, "expires": "", "note": note,
            "enabled": True, "reason": "", "created": int(time.time()), "socks_pass": secrets.token_hex(8)}

def load_settings():
    s = {}
    try: s = json.loads(Path(SETTINGS_FILE).read_text())
    except FileNotFoundError: pass
    except Exception as e: print("settings read error:", e)
    first, old = "sponsors" not in s, hexonly(s.pop("ad_tag", "") or E("AD_TAG", ""))   # v3 single AD_TAG -> sponsor "main"
    for k, v in {"tls_domain": E("FAKE_TLS_DOMAIN", "www.cloudflare.com"), "usage": {}, "railway_token": E("RAILWAY_TOKEN_PANEL", ""),
                 "manual_endpoints": [], "aliases": {}, "primary": "", "admin": {}, "sponsors": {}, "port_sponsor": {}, "port_kind": {},
                 "default_sponsor": "", "users": {"null": new_user(default_secret(), "کاربر اصلی")}}.items(): s.setdefault(k, v)
    if first and len(old) == 32: s["sponsors"]["main"], s["default_sponsor"] = old, "main"
    for u in s["users"].values():
        for k, v in new_user(u.get("secret")).items(): u.setdefault(k, v)
    return s

S = load_settings()
def save():
    tmp = SETTINGS_FILE + ".tmp"; Path(tmp).write_text(json.dumps(S, ensure_ascii=False, indent=1)); os.replace(tmp, SETTINGS_FILE)

kind_of = lambda port: "socks" if S["port_kind"].get(str(port)) == "socks" else "mtproto"
def sponsor_of(port):
    n = S["port_sponsor"].get(str(port)) or S["default_sponsor"]
    return (n, S["sponsors"][n]) if n in S["sponsors"] else ("", "")

# ---------------- auth ----------------
pw_hash = lambda pw, salt: hashlib.sha256((salt + pw).encode()).hexdigest()
env_password = lambda: E("ADMIN_PASSWORD") or hashlib.sha256((SEED + "admin").encode()).hexdigest()[:12]
def check_password(pw):
    a = S["admin"]
    return hmac.compare_digest(pw_hash(pw, a["salt"]), a["hash"]) if a.get("hash") else hmac.compare_digest(pw.encode(), env_password().encode())
def session_token():
    return hmac.new(hashlib.sha256((SEED + "session").encode()).digest(), (S["admin"].get("hash") or env_password()).encode(), "sha256").hexdigest()

# ---------------- mtprotoproxy instances (one per distinct AD_TAG) ----------------
active_users = lambda: {n: u for n, u in S["users"].items() if u.get("enabled", True)}
ROUTE = {p: IN0 for p in ENTRY}          # entry port -> internal instance port
LOG = []

def port_free(port):
    t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: t.bind(("127.0.0.1", port)); return True
    except OSError: return False
    finally: t.close()

class Inst:
    def __init__(s, tag, slot): s.tag, s.slot, s.p, s.t0 = tag, slot, None, 0
    port = property(lambda s: IN0 + s.slot); mport = property(lambda s: MET0 + s.slot)
    cfg = property(lambda s: os.path.join(APP_DIR, f"config_{s.slot}.py"))
    running = lambda s: bool(s.p and s.p.poll() is None)
    def write(s):
        au = active_users() or {"_off": {"secret": secrets.token_hex(16)}}
        L = [f"PORT = {s.port}", 'LISTEN_ADDR_IPV4 = "127.0.0.1"', "USERS = " + json.dumps({n: u["secret"] for n, u in au.items()}),
             'MODES = {"classic": False, "secure": False, "tls": True}', f"TLS_DOMAIN = {json.dumps(S['tls_domain'])}",
             f"METRICS_PORT = {s.mport}", 'METRICS_LISTEN_ADDR_IPV4 = "127.0.0.1"', 'METRICS_WHITELIST = ["127.0.0.1", "::1"]']
        if s.tag: L.append(f"AD_TAG = {json.dumps(s.tag)}")
        mc = {n: int(u["max_conns"]) for n, u in au.items() if int(u.get("max_conns") or 0) > 0}
        if mc: L.append("USER_MAX_TCP_CONNS = " + json.dumps(mc))
        Path(s.cfg).write_text("\n".join(L) + "\n")
    def start(s):
        if s.running(): return
        s.write()
        for _ in range(20):
            if port_free(s.port): break
            time.sleep(.5)
        s.p = subprocess.Popen(["python3", "mtprotoproxy.py", s.cfg], cwd=APP_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        s.t0 = time.time(); threading.Thread(target=s.pump, args=(s.p,), daemon=True).start()
    def pump(s, p):
        for line in p.stdout:
            line = line.rstrip()
            if line and not any(x in line for x in ("secret=", "tg://", "t.me/")):
                print(f"[mtproto{s.slot}]", line); LOG.append(f"{time.strftime('%H:%M:%S')} #{s.slot} {line}"); del LOG[:-100]
    def stop(s):
        if s.running():
            s.p.terminate()
            try: s.p.wait(8)
            except subprocess.TimeoutExpired: s.p.kill()
    def reload(s):                      # apply user changes without dropping connections
        s.write()
        if not s.running(): return s.start()
        try: s.p.send_signal(signal.SIGUSR2)
        except Exception: s.stop(); s.start()

class Fleet:
    def __init__(s): s.inst, s.want, s.restarts = {}, True, 0
    up = lambda s: (bool(s.inst) or any(kind_of(p) == "socks" for p in ENTRY)) and all(i.running() for i in s.inst.values())
    def uptime(s): return int(time.time() - min((i.t0 for i in s.inst.values() if i.running()), default=time.time()))
    def sync(s, restart=False):
        """Make instances match the sponsor plan (one per distinct tag), then refresh routing."""
        with lock:
            need = {sponsor_of(p)[1] for p in ENTRY if kind_of(p) != "socks"}
            for t in [t for t in s.inst if t not in need]: s.inst.pop(t).stop()
            for t in need - set(s.inst): s.inst[t] = Inst(t, min(set(range(MAXSP + 1)) - {i.slot for i in s.inst.values()}))
            for i in s.inst.values():
                if restart: i.stop(); i.start()
                else: i.reload()
            ROUTE.update({p: s.inst[sponsor_of(p)[1]].port for p in ENTRY if kind_of(p) != "socks"}); s.restarts += restart
    def watchdog(s):
        while True:
            time.sleep(3)
            with lock:
                for i in list(s.inst.values()):
                    if s.want and not i.running():
                        event("پروکسی متوقف شد، دوباره روشن شد", "warn"); s.restarts += 1
                        try: i.start()
                        except Exception as e: print("start failed:", e)
FLEET = Fleet()

# ---------------- entry-port forwarders (per-endpoint stats) ----------------
FWD = {p: dict(curr=0, total=0, bytes=0, last=0, good=0, last_good=0, pending=0, pts=0) for p in ENTRY}
FWD_ERR = {}
def nodelay(w):
    s = w.get_extra_info("socket")
    if s: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

async def _pipe(r, w, st, c):
    try:
        while d := await r.read(65536): st["bytes"] += len(d); c[0] += len(d); w.write(d); await w.drain()
    except Exception: pass
    finally:
        try: w.close()
        except Exception: pass

# ---------------- SOCKS5 (username/password, CONNECT) ----------------
SOCKS_BYTES, SOCKS_CONNS = {}, {}
ALLOW_PRIVATE = E("SOCKS_ALLOW_PRIVATE", "") == "1"
def _blocked(ip):
    """Never let a SOCKS user reach this container, Railway's private network or other internal addresses."""
    try:
        a = ipaddress.ip_address(str(ip).split("%")[0]); a = getattr(a, "ipv4_mapped", None) or a
        return not ALLOW_PRIVATE and (not a.is_global or a.is_multicast)
    except ValueError: return True

async def _spipe(r, w, st, c, user):
    try:
        while d := await r.read(65536):
            if not S["users"].get(user, {}).get("enabled", True): break
            n = len(d); st["bytes"] += n; c[0] += n; SOCKS_BYTES[user] = SOCKS_BYTES.get(user, 0) + n; w.write(d); await w.drain()
    except Exception: pass
    finally:
        try: w.close()
        except Exception: pass

async def socks_session(r, w, st, c):
    rd = lambda n: asyncio.wait_for(r.readexactly(n), 15)
    rep = lambda code: b"\x05" + bytes([code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    ver, n = await rd(2)
    if ver != 5: return
    if 2 not in await rd(n): w.write(b"\x05\xff"); await w.drain(); return
    w.write(b"\x05\x02")
    if (await rd(1))[0] != 1: return
    user = (await rd((await rd(1))[0])).decode("utf-8", "ignore"); pw = (await rd((await rd(1))[0])).decode("utf-8", "ignore")
    u = S["users"].get(user)
    ok = bool(u and u.get("enabled", True) and hmac.compare_digest(pw.encode(), str(u.get("socks_pass", "")).encode()))
    w.write(b"\x01\x00" if ok else b"\x01\x01"); await w.drain()
    if not ok: return
    _, cmd, _, at = await rd(4)
    if at == 1: host = socket.inet_ntoa(await rd(4))
    elif at == 3: host = (await rd((await rd(1))[0])).decode("utf-8", "ignore")
    elif at == 4: host = socket.inet_ntop(socket.AF_INET6, await rd(16))
    else: w.write(rep(8)); return
    port = int.from_bytes(await rd(2), "big")
    if cmd != 1: w.write(rep(7)); return
    mx = int(u.get("max_conns") or 0)
    if mx and SOCKS_CONNS.get(user, 0) >= mx: w.write(rep(2)); return
    try: infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM), 10)
    except Exception: w.write(rep(4)); return
    ip = next((i[4][0] for i in infos if not _blocked(i[4][0])), None)      # connect to the checked IP itself (no DNS rebinding)
    if not ip: w.write(rep(2)); return
    try: r2, w2 = await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
    except asyncio.TimeoutError: w.write(rep(6)); return
    except OSError: w.write(rep(5)); return
    nodelay(w2); w.write(rep(0)); await w.drain(); SOCKS_CONNS[user] = SOCKS_CONNS.get(user, 0) + 1
    try: await asyncio.gather(_spipe(r, w2, st, c, user), _spipe(r2, w, st, c, user))
    finally: SOCKS_CONNS[user] -= 1; w2.close()

async def _handle(reader, writer, port):
    st, t0, c = FWD[port], time.time(), [0]
    if st["pending"] and t0 - st["pts"] > 15: st["pending"] = 0
    probe = st["pending"] > 0                        # health probes must not count as real users
    if probe: st["pending"] -= 1
    else: st["curr"] += 1; st["total"] += 1; st["last"] = t0
    try:
        nodelay(writer)
        if kind_of(port) == "socks":
            try: await socks_session(reader, writer, st, c)
            finally: writer.close()
        else:
            r2, w2 = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", ROUTE[port]), 5); nodelay(w2)
            await asyncio.gather(_pipe(reader, w2, st, c), _pipe(r2, writer, st, c))
    except Exception: writer.close()
    finally:
        if not probe:
            st["curr"] -= 1
            if c[0] > 20000 or time.time() - t0 > 15: st["good"] += 1; st["last_good"] = time.time()

def run_forwarders():
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    for p in ENTRY:
        try: loop.run_until_complete(asyncio.start_server(lambda r, w, p=p: _handle(r, w, p), "0.0.0.0", p, backlog=1024))
        except OSError as e: FWD_ERR[p] = str(e); print(f"!! cannot listen on {p}: {e}")
    loop.run_forever()

# ---------------- Railway API ----------------
RW = {"mode": None, "ts": 0, "list": [], "err": ""}
def rw(query, variables=None):
    tok = S.get("railway_token")
    if not tok: raise RuntimeError("توکن Railway تنظیم نشده")
    body, last = json.dumps({"query": query, "variables": variables or {}}).encode(), None
    for m in [RW["mode"]] if RW["mode"] else ["bearer", "project"]:
        h = {"Content-Type": "application/json", "User-Agent": "nullproxy-panel", **({"Authorization": "Bearer " + tok} if m == "bearer" else {"Project-Access-Token": tok})}
        try: res = json.loads(urllib.request.urlopen(urllib.request.Request(RW_API, body, h), timeout=15).read())
        except Exception as e: last = f"اتصال به Railway: {e}"; continue
        if res.get("errors"):
            last = res["errors"][0].get("message", "خطای Railway")
            if "auth" in last.lower(): continue
            raise RuntimeError(last)
        RW["mode"] = m; return res.get("data") or {}
    RW["mode"] = None; raise RuntimeError(last or "خطای Railway")

def rw_list(force=False):
    if not S.get("railway_token"): return []
    if force or time.time() - RW["ts"] > 30:
        try: RW.update(ts=time.time(), err="", list=rw("query($e:String!,$s:String!){tcpProxies(environmentId:$e,serviceId:$s){id domain proxyPort applicationPort}}", {"e": RW_ENV, "s": RW_SVC}).get("tcpProxies") or [])
        except Exception as e: RW.update(ts=time.time(), err=str(e))
    return RW["list"]

def rw_create(app_port):
    d = rw("mutation($i:TCPProxyCreateInput!){tcpProxyCreate(input:$i){id domain proxyPort applicationPort}}",
           {"i": {"environmentId": RW_ENV, "serviceId": RW_SVC, "applicationPort": app_port}}); RW["ts"] = 0; return d["tcpProxyCreate"]
def rw_delete(pid): rw("mutation($id:String!){tcpProxyDelete(id:$id)}", {"id": pid}); RW["ts"] = 0

RWQ = "query($e:String!,$s:String!){tcpProxies(environmentId:$e,serviceId:$s){id domain proxyPort applicationPort}}"
RWF = "id name environments{edges{node{id name}}} services{edges{node{id name}}}"
RWALL = {"ts": 0, "list": [], "err": "", "scope": "none", "busy": False}
def rw_projects():
    """Whole account when the token allows it, otherwise the current project, otherwise just this service."""
    norm = lambda p: {"id": p["id"], "name": p.get("name") or "", "envs": [x["node"] for x in p["environments"]["edges"]],
                      "svcs": [x["node"] for x in p["services"]["edges"]]}
    ps, scope = [], "service"
    try:
        ps = [norm(x["node"]) for x in rw("query{me{projects{edges{node{" + RWF + "}}}}}")["me"]["projects"]["edges"]]; scope = "account"
    except Exception: pass
    if RW_PRJ and not any(p["id"] == RW_PRJ for p in ps):       # team projects are not under `me`
        try:
            ps.append(norm(rw("query($p:String!){project(id:$p){" + RWF + "}}", {"p": RW_PRJ})["project"])); scope = scope if scope == "account" else "project"
        except Exception: pass
    if not ps and RW_ENV and RW_SVC: ps = [{"id": RW_PRJ, "name": "", "envs": [{"id": RW_ENV, "name": ""}], "svcs": [{"id": RW_SVC, "name": ""}]}]
    return ps, scope

def _rw_all_fetch():
    RWALL["busy"] = True
    try:
        ps, scope = rw_projects(); jobs = [(p, e, s) for p in ps for e in p["envs"] for s in p["svcs"]]; errs = []
        def one(j):
            p, e, sv = j
            try:
                return [{"key": f"{t['domain']}:{t['proxyPort']}", "id": t["id"], "domain": t["domain"], "port": int(t["proxyPort"]), "app_port": int(t.get("applicationPort") or 0),
                         "project": p["name"], "env": e["name"], "service": sv["name"]}
                        for t in (rw(RWQ, {"e": e["id"], "s": sv["id"]}).get("tcpProxies") or []) if t.get("domain") and t.get("proxyPort")]
            except Exception as ex: errs.append(str(ex)); return []
        with ThreadPoolExecutor(max_workers=8) as ex: res = list(ex.map(one, jobs))
        out, seen = [], set()
        for r in (x for g in res for x in g):
            if r["key"] not in seen: seen.add(r["key"]); out.append(r)
        RWALL.update(ts=time.time(), list=out, scope=scope, err=errs[0] if errs and not out else "")
    except Exception as ex: RWALL.update(ts=time.time(), err=str(ex))
    finally: RWALL["busy"] = False

def rw_all(force=False):
    """Every TCP proxy Railway shows for this token. Cached; a stale list is refreshed in the background so checks never wait on it."""
    if not S.get("railway_token"): return []
    if RWALL["busy"] and (force or not RWALL["ts"]):
        for _ in range(60):
            if not RWALL["busy"]: break
            time.sleep(.5)
    elif force or not RWALL["ts"]: _rw_all_fetch()
    elif time.time() - RWALL["ts"] > 30 and not RWALL["busy"]: threading.Thread(target=_rw_all_fetch, daemon=True).start()
    return RWALL["list"]

# ---------------- endpoints + health ----------------
CHECKS = {}   # key -> {mode: ok|tcp|down, ms, ts, hist}
def endpoints():
    out, seen = [], set()
    def add(domain, port, app, source, eid):
        key = f"{domain}:{port}"
        if not domain or not port or key in seen: return
        seen.add(key); app = int(app or BASE); st = FWD.get(app, {}); ck = CHECKS.get(key, {}); sp = sponsor_of(app) if kind_of(app) != "socks" else ("", "")
        out.append({"key": key, "id": eid, "domain": domain, "port": int(port), "app_port": app, "source": source,
                    "alias": S["aliases"].get(key, ""), "kind": kind_of(app), "primary": False, "bad_port": app not in ENTRY,
                    "curr": st.get("curr", 0), "total": st.get("total", 0), "bytes": st.get("bytes", 0), "good": st.get("good", 0),
                    "last_good": int(st.get("last_good", 0)), "sponsor": sp[0], "sponsor_set": S["port_sponsor"].get(str(app), ""),
                    "check": {"mode": ck.get("mode"), "ms": ck.get("ms"), "ts": ck.get("ts"), "hist": ck.get("hist", [])}})
    for p in rw_list(): add(p.get("domain"), p.get("proxyPort"), p.get("applicationPort"), "railway", p.get("id"))
    if not S.get("railway_token") or RW["err"]: add(E("RAILWAY_TCP_PROXY_DOMAIN"), E("RAILWAY_TCP_PROXY_PORT"), BASE, "env", "env")
    for m in S["manual_endpoints"]: add(m.get("domain"), m.get("port"), m.get("app_port"), "manual", m.get("id"))
    prim = next((e for e in out if e["key"] == S["primary"]), None) or (out[0] if out else None)
    if prim: prim["primary"] = True
    return out

ep_host = lambda e: e["alias"] or e["domain"]
link_secret = lambda raw: "ee" + raw + S["tls_domain"].encode().hex()
def link_obj(e, n, u):
    h = ep_host(e)
    if e["kind"] == "socks":
        nm = urllib.parse.quote(n)
        return {"key": e["key"], "host": h, "port": e["port"], "kind": "socks", "link": f"https://t.me/socks?server={h}&port={e['port']}&user={nm}&pass={u['socks_pass']}",
                "url": f"socks5://{nm}:{u['socks_pass']}@{h}:{e['port']}"}
    return {"key": e["key"], "host": h, "port": e["port"], "kind": "mtproto", "link": make_link(e, u["secret"])}
make_link = lambda e, raw: f"https://t.me/proxy?server={ep_host(e)}&port={e['port']}&secret={link_secret(raw)}"

def tls_probe(host, port, secret_hex, timeout=6):
    """Send a valid Fake-TLS ClientHello; a working proxy answers with a TLS ServerHello (0x16 0x03 0x03).
    Returns (mode, ms): ok = proxy answered | tcp = port open but no valid answer | down = cannot connect."""
    t0 = time.time()
    try: s = socket.create_connection((host, port), timeout=timeout)
    except OSError: return "down", None
    try:
        s.settimeout(timeout)
        h = bytearray(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + bytes(32) + b"\x20" + os.urandom(32)); h += os.urandom(517 - len(h))
        d = hmac.new(bytes.fromhex(secret_hex), bytes(h), "sha256").digest()
        h[11:43] = d[:28] + bytes(a ^ b for a, b in zip(d[28:], int(time.time()).to_bytes(4, "little")))
        s.sendall(h); ok = s.recv(3) == b"\x16\x03\x03"
        return ("ok" if ok else "tcp"), int((time.time() - t0) * 1000)
    except OSError: return "tcp", None
    finally: s.close()

def record(key, mode, ms):
    """Store the latest probe result. The history keeps one point per >=20s (or on any status change), so fast checks don't flush it."""
    now, ck = time.time(), CHECKS.setdefault(key, {"hist": [], "hts": 0, "hm": None})
    ck.update(mode=mode, ms=ms, ts=int(now))
    if now - ck.get("hts", 0) >= 20 or ck.get("hm") != mode:
        ck["hist"] = (ck["hist"] + [ms if mode == "ok" else -1])[-40:]; ck["hts"], ck["hm"] = now, mode

def socks_probe(host, port, user, pw, timeout=6):
    """Real SOCKS5 handshake + login. ok = the proxy accepted our credentials | tcp = port open but no valid answer | down = cannot connect."""
    t0 = time.time()
    try: s = socket.create_connection((host, port), timeout=timeout)
    except OSError: return "down", None
    try:
        s.settimeout(timeout); s.sendall(b"\x05\x01\x02")
        if s.recv(2) != b"\x05\x02": return "tcp", None
        a, b = user.encode(), pw.encode(); s.sendall(b"\x01" + bytes([len(a)]) + a + bytes([len(b)]) + b)
        return ("ok" if s.recv(2) == b"\x01\x00" else "tcp"), int((time.time() - t0) * 1000)
    except OSError: return "tcp", None
    finally: s.close()

def check_endpoint(e, timeout=6):
    un, u = next(iter(active_users().items()), (None, None))
    f = FWD.get(e["app_port"])
    if f: f["pending"] = min(3, f["pending"] + 1); f["pts"] = time.time()
    if e.get("kind") == "socks": mode, ms = socks_probe(ep_host(e), e["port"], un or "x", (u or {}).get("socks_pass") or "x", timeout)
    else: mode, ms = tls_probe(ep_host(e), e["port"], (u or {}).get("secret") or secrets.token_hex(16), timeout)
    if mode == "down" and f: f["pending"] = max(0, f["pending"] - 1)      # the probe never reached us
    record(e["key"], mode, ms)

def check_many(eps, timeout=6):
    """Probe every endpoint at the same time (one thread each), so the whole round takes as long as the slowest one."""
    def one(e):
        try: check_endpoint(e, timeout)
        except Exception as ex: print("check:", ex)
    if eps:
        with ThreadPoolExecutor(max_workers=min(128, len(eps))) as ex: list(ex.map(one, eps))

CHECK_EVERY = max(2.0, float(E("CHECK_INTERVAL", "5")))
def checker():
    time.sleep(3)
    while True:
        t0 = time.time()
        try: check_many(endpoints())
        except Exception as ex: print("checker:", ex)
        time.sleep(max(1.0, CHECK_EVERY - (time.time() - t0)))

def free_entry_port(eps):
    used = {e["app_port"] for e in eps}
    return next((p for p in ENTRY if p not in used and p not in FWD_ERR), None)

RUN = {"on": False, "done": 0, "total": 0, "t0": 0, "dur": 0}
def all_rows(force=False):
    rows = [dict(r) for r in rw_all(force)]
    eps, have = endpoints(), {r["key"] for r in rows}
    for e in eps:                                                # panel-managed TCPs are always included (env / manual / token missing)
        if e["key"] not in have: rows.append({"key": e["key"], "id": e["id"], "domain": e["domain"], "port": e["port"], "app_port": e["app_port"], "project": "", "env": "", "service": ""})
    mine = {e["key"] for e in eps}
    rows.sort(key=lambda r: (r["key"] not in mine, r["project"], r["service"], r["domain"], r["port"]))
    return rows

def check_rows_async(rows):
    """Start probing every row at once in the background; results land in CHECKS one by one, so the UI fills in live."""
    if RUN["on"]: return False
    RUN.update(on=True, done=0, total=len(rows), t0=time.time())
    def work():
        try:
            eps, dn = {e["key"]: e for e in endpoints()}, threading.Lock()
            u = next(iter(active_users().values()), None); secret = (u or {}).get("secret") or secrets.token_hex(16)
            def one(r):
                try:
                    if r["key"] in eps: check_endpoint(eps[r["key"]], 4)
                    else: record(r["key"], *tls_probe(r["domain"], r["port"], secret, 4))
                except Exception as ex: print("rall:", ex)
                finally:
                    with dn: RUN["done"] += 1
            with ThreadPoolExecutor(max_workers=min(200, max(1, len(rows)))) as ex: list(ex.map(one, rows))
            keep = {r["key"] for r in rows}
            for k in [k for k in CHECKS if k not in eps and k not in keep]: CHECKS.pop(k, None)
        finally: RUN.update(on=False, dur=round(time.time() - RUN["t0"], 2))
    threading.Thread(target=work, daemon=True).start(); return True

def rall_out(rows):
    eps, out = {e["key"]: e for e in endpoints()}, []
    for r in rows:
        e, ck = eps.get(r["key"]), CHECKS.get(r["key"], {})
        out.append({**r, "mine": bool(e), "kind": e["kind"] if e else "", "alias": e["alias"] if e else "", "curr": e["curr"] if e else 0, "last_good": e["last_good"] if e else 0,
                    "check": {"mode": ck.get("mode"), "ms": ck.get("ms"), "ts": ck.get("ts"), "hist": ck.get("hist", [])}})
    tok = bool(S.get("railway_token"))
    return {"rows": out, "scope": RWALL["scope"] if tok else "none", "err": RWALL["err"] if tok else "", "token": tok, "run": dict(RUN), "ts": int(time.time())}

# ---------------- metrics, usage, enforcement ----------------
METRIC = re.compile(r'^([a-zA-Z_:][\w:]*)(\{([^}]*)\})?\s+([-+0-9.eE]+|NaN)')
def fetch_metrics(port):
    try: raw = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=3).read().decode()
    except Exception: return None
    g, users = {}, {}
    for line in raw.splitlines():
        m = METRIC.match(line)
        if not m: continue
        name, val = re.sub(r"^mtprotoproxy_", "", m.group(1)), 0.0 if m.group(4) == "NaN" else float(m.group(4))
        lab = dict(re.findall(r'(\w+)="([^"]*)"', m.group(3) or ""))
        if "user" in lab: users.setdefault(lab["user"], {})[name] = val
        elif not lab: g[name] = val
    return {"global": g, "users": users}

SERIES, LAST, SYS = [], {"m": None, "oct": {}, "save": 0}, {"cpu": None, "mem": None, "mem_max": None, "_c": None}
def read_sys():
    try:
        us, now = int(re.search(r"usage_usec (\d+)", Path("/sys/fs/cgroup/cpu.stat").read_text()).group(1)), time.time()
        if SYS["_c"]: SYS["cpu"] = round(min(100.0, (us - SYS["_c"][1]) / 1e6 / (now - SYS["_c"][0]) / max(1, os.cpu_count() or 1) * 100), 1)
        SYS["_c"] = (now, us)
    except Exception: pass
    try:
        SYS["mem"] = int(Path("/sys/fs/cgroup/memory.current").read_text()); mx = Path("/sys/fs/cgroup/memory.max").read_text().strip()
        SYS["mem_max"] = int(mx) if mx.isdigit() else None
    except Exception:
        try:
            mi = {k: int(v) for k, v in re.findall(r"(\w+):\s+(\d+)", Path("/proc/meminfo").read_text())}
            SYS["mem"], SYS["mem_max"] = (mi["MemTotal"] - mi["MemAvailable"]) * 1024, mi["MemTotal"] * 1024
        except Exception: pass

def enforce():
    changed, today = False, time.strftime("%Y-%m-%d")
    for n, u in S["users"].items():
        if not u.get("enabled", True): continue
        q = float(u.get("quota_gb") or 0)
        why = "quota" if q > 0 and S["usage"].get(n, 0) >= q * 1024 ** 3 else "expired" if u.get("expires") and u["expires"] < today else ""
        if why:
            u["enabled"], u["reason"], changed = False, why, True
            event(f"«{n}» " + ("به سقف ترافیک رسید" if why == "quota" else "منقضی شد") + " و غیرفعال شد", "warn")
    if changed: save(); FLEET.sync()

def sampler():
    while True:
        try:
            got = [(i.slot, fetch_metrics(i.mport)) for i in list(FLEET.inst.values())]
            with lock:
                g, users, seen = {}, {}, False
                for n in list(SOCKS_BYTES):
                    d = SOCKS_BYTES.get(n, 0); SOCKS_BYTES[n] -= d
                    if d > 0 and n in S["users"]: S["usage"][n] = S["usage"].get(n, 0) + d
                for slot, m in got:
                    if not m: continue
                    seen = True
                    for k, v in m["global"].items(): g[k] = g.get(k, 0) + v
                    for n, um in m["users"].items():
                        o, key = um.get("user_octets", 0), (slot, n); prev = LAST["oct"].get(key); LAST["oct"][key] = o
                        d = o if prev is None or o < prev else o - prev
                        if n in S["users"] and d > 0: S["usage"][n] = S["usage"].get(n, 0) + d
                        a = users.setdefault(n, {"user_connects_curr": 0, "user_connects": 0})
                        for k in a: a[k] += um.get(k, 0)
                if seen: LAST["m"] = {"global": g, "users": users}
                enforce()
                SERIES.append([int(time.time()), sum(v["curr"] for v in FWD.values()), sum(S["usage"].values())]); del SERIES[:-8640]
                if time.time() - LAST["save"] > 300: save(); LAST["save"] = time.time()
            read_sys()
        except Exception as ex: print("sampler:", ex)
        time.sleep(10)

def series_out():
    pts = SERIES[:]
    if len(pts) > 400: st = len(pts) / 400; pts = [pts[int(i * st)] for i in range(400)] + [pts[-1]]
    out, prev = [], None
    for ts, c, o in pts:
        out.append([ts, c, 0 if prev is None or ts <= prev[0] or o < prev[1] else round((o - prev[1]) / (ts - prev[0]))]); prev = (ts, o)
    return out

def state():
    m, eps = LAST["m"] or {"global": {}, "users": {}}, endpoints()
    prim, g = next((e for e in eps if e["primary"]), None), m["global"]
    users = [{"name": n, "note": u["note"], "max_conns": u["max_conns"], "quota_gb": u["quota_gb"], "expires": u["expires"], "enabled": u["enabled"],
              "reason": u["reason"], "raw_secret": u["secret"], "usage": S["usage"].get(n, 0),
              "curr": m["users"].get(n, {}).get("user_connects_curr", 0),
              "socks_pass": u["socks_pass"], "links": [link_obj(e, n, u) for e in eps]}
             for n, u in S["users"].items()]
    sponsors = [{"name": n, "tag": t, "default": n == S["default_sponsor"], "uses": sum(1 for e in eps if e["sponsor"] == n and e["kind"] != "socks")} for n, t in S["sponsors"].items()]
    return {"running": FLEET.up(), "proxy_uptime": FLEET.uptime() if FLEET.up() else 0, "panel_uptime": int(time.time() - START), "restarts": FLEET.restarts,
            "persistent": PERSISTENT, "tls_domain": S["tls_domain"], "metrics_ok": LAST["m"] is not None, "instances": len(FLEET.inst),
            "railway": {"token_set": bool(S.get("railway_token")), "err": RW["err"]}, "max_endpoints": MAXEP, "max_sponsors": MAXSP,
            "entry_ports": [ENTRY[0], ENTRY[-1]], "endpoints": eps, "sponsors": sponsors, "default_sponsor": S["default_sponsor"],
            "totals": {"curr": sum(v["curr"] for v in FWD.values()), "connects_all": g.get("connects_all", 0), "connects_bad": g.get("connects_bad", 0),
                       "usage": sum(S["usage"].values())},
            "sys": {k: SYS[k] for k in ("cpu", "mem", "mem_max")}, "users": users, "series": series_out(), "log": LOG[-60:],
            "events": EVENTS[-60:][::-1], "qr": segno is not None}

# ---------------- HTTP ----------------
def apply_limits(u, d):
    try:
        if "max_conns" in d: u["max_conns"] = max(0, int(d["max_conns"] or 0))
        if "quota_gb" in d: u["quota_gb"] = max(0.0, float(d["quota_gb"] or 0))
    except ValueError: raise RuntimeError("عدد نامعتبر")
    if "expires" in d:
        exp = str(d["expires"] or "")
        if exp and not DATE_RE.match(exp): raise RuntimeError("تاریخ نامعتبر")
        u["expires"] = exp
    if "note" in d: u["note"] = str(d["note"])[:60]

class H(http.server.BaseHTTPRequestHandler):
    server_version = "NullProxy"
    log_message = lambda *a: None
    def _send(self, code, body, ctype="application/json", extra=None):
        b = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        for k, v in {"Content-Type": ctype + "; charset=utf-8", "Content-Length": len(b), "Cache-Control": "no-store", "X-Frame-Options": "DENY",
                     "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", **(extra or {})}.items(): self.send_header(k, str(v))
        self.end_headers(); self.wfile.write(b)
    ok = lambda self, **kw: self._send(200, {"ok": True, **kw})
    err = lambda self, msg, code=400: self._send(code, {"error": msg})
    def _authed(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return "np" in c and hmac.compare_digest(c["np"].value, session_token())
    def _json(self):
        n = int(self.headers.get("Content-Length") or 0)
        try: return json.loads(self.rfile.read(n) or b"{}") if n <= 2_000_000 else {}
        except Exception: return {}
    def _cookie(self, val, age):
        sec = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        return {"Set-Cookie": f"np={val}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{sec}"}

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path in ("/", "/index.html"): return self._send(200, Path(HERE, "index.html").read_bytes(), "text/html")
        if u.path == "/healthz": return self.ok()
        if not self._authed(): return self.err("auth", 401)
        if u.path == "/api/state":
            with lock: return self._send(200, state())
        if u.path == "/api/rwall": return self._send(200, rall_out(all_rows(bool(q.get("refresh")))))
        if u.path == "/api/qr" and segno:
            svg = segno.make((q.get("t") or [""])[0][:1000], error="m").svg_inline(scale=5, dark="#111", light="#fff", border=2)
            return self._send(200, svg.encode(), "image/svg+xml")
        if u.path == "/api/backup":
            with lock: b = json.dumps(S, ensure_ascii=False, indent=1).encode()
            return self._send(200, b, "application/json", {"Content-Disposition": 'attachment; filename="nullproxy-backup.json"'})
        self.err("not found", 404)

    def do_DELETE(self):
        if not self._authed(): return self.err("auth", 401)
        m = re.match(r"^/api/(users|sponsors)/([A-Za-z0-9_\-]+)$", self.path); key = urllib.parse.unquote(self.path[len("/api/endpoints/"):])
        with lock:
            if m and m.group(1) == "users":
                n = m.group(2)
                if n not in S["users"]: return self.err("کاربر پیدا نشد", 404)
                if len(S["users"]) == 1: return self.err("حداقل یک کاربر باید بماند")
                del S["users"][n]; S["usage"].pop(n, None); save(); event(f"کاربر «{n}» حذف شد"); FLEET.sync(); return self.ok()
            if m:
                n = m.group(2)
                if n not in S["sponsors"]: return self.err("پیدا نشد", 404)
                del S["sponsors"][n]; S["port_sponsor"] = {p: v for p, v in S["port_sponsor"].items() if v != n}
                if S["default_sponsor"] == n: S["default_sponsor"] = ""
                save(); event(f"اسپانسر «{n}» حذف شد"); FLEET.sync(); return self.ok()
            if self.path.startswith("/api/endpoints/"):
                e = next((x for x in endpoints() if x["key"] == key), None)
                if not e: return self.err("پیدا نشد", 404)
                try:
                    if e["source"] == "railway": rw_delete(e["id"])
                    elif e["source"] == "manual": S["manual_endpoints"] = [x for x in S["manual_endpoints"] if x.get("id") != e["id"]]
                    else: return self.err("این آدرس از متغیرهای Railway میاد. اول توکن Railway رو توی تنظیمات بذار.")
                except Exception as ex: return self.err(str(ex))
                if not any(x["app_port"] == e["app_port"] and x["key"] != key for x in endpoints()): S["port_sponsor"].pop(str(e["app_port"]), None); S["port_kind"].pop(str(e["app_port"]), None)
                S["aliases"].pop(key, None); CHECKS.pop(key, None); save(); event(f"TCP {key} حذف شد"); FLEET.sync(); return self.ok()
        self.err("not found", 404)

    def do_POST(self):
        p = self.path
        if p == "/api/login":
            if check_password(str(self._json().get("password", ""))): return self._send(200, {"ok": True}, extra=self._cookie(session_token(), 2592000))
            time.sleep(1.5); return self.err("رمز اشتباهه", 403)
        if p == "/api/logout": return self._send(200, {"ok": True}, extra=self._cookie("", 0))
        if not self._authed(): return self.err("auth", 401)
        d = self._json()
        if p == "/api/rwall/check":                                  # outside the global lock: starts a parallel run and returns at once
            try: rows = all_rows(bool(d.get("refresh"))); check_rows_async(rows); return self._send(200, rall_out(rows))
            except Exception as ex: return self.err(str(ex))
        try:
            with lock: return self._post(p, d)
        except Exception as ex: return self.err(str(ex))

    def _post(self, p, d):
        if p == "/api/restart": FLEET.sync(True); event("پروکسی دستی ریستارت شد"); return self.ok()
        if p == "/api/settings":
            dom = str(d.get("tls_domain", S["tls_domain"])).strip().lower()
            if not DOMAIN_RE.match(dom): return self.err("دامنه نامعتبره")
            ch, S["tls_domain"] = dom != S["tls_domain"], dom; save()
            if ch: FLEET.sync(True); event("دامنه‌ی Fake-TLS عوض شد")
            return self.ok()
        if p == "/api/password":
            if not check_password(str(d.get("current", ""))): return self.err("رمز فعلی اشتباهه", 403)
            new = str(d.get("new", ""))
            if len(new) < 6: return self.err("رمز جدید حداقل ۶ کاراکتر")
            salt = secrets.token_hex(8); S["admin"] = {"salt": salt, "hash": pw_hash(new, salt)}; save(); event("رمز پنل عوض شد")
            return self._send(200, {"ok": True}, extra=self._cookie(session_token(), 2592000))
        if p == "/api/restore":
            b = d.get("backup") or {}
            if not isinstance(b.get("users"), dict) or not b["users"]: return self.err("فایل بکاپ نامعتبره")
            for n, u in b["users"].items():
                if not NAME_RE.match(n) or not HEX32.match(str(u.get("secret", ""))): return self.err(f"کاربر نامعتبر: {n}")
            Path(SETTINGS_FILE).write_text(json.dumps(b, ensure_ascii=False)); new = load_settings(); S.clear(); S.update(new); save()
            RW.update(ts=0, mode=None); FLEET.sync(True); event("بکاپ بازگردانی شد"); return self.ok()
        if p == "/api/railway":
            S["railway_token"] = str(d.get("token", "")).strip(); RW.update(mode=None, ts=0)
            if S["railway_token"]:
                if not (RW_ENV and RW_SVC): return self.err("شناسه‌های Railway پیدا نشد (این پنل باید روی Railway اجرا بشه)")
                rw_list(True)
                if RW["err"]: e, S["railway_token"] = RW["err"], ""; return self.err("توکن کار نکرد: " + e)
            save(); event("توکن Railway " + ("ذخیره شد" if S["railway_token"] else "حذف شد")); return self.ok()
        # ---- sponsors ----
        if p == "/api/sponsors":
            name, tag = str(d.get("name", "")).strip(), hexonly(d.get("tag", ""))
            if not NAME_RE.match(name): return self.err("اسم فقط حروف انگلیسی، عدد، - و _ (حداکثر ۳۲)")
            if len(tag) != 32: return self.err("AD_TAG باید ۳۲ کاراکتر هگز باشه")
            if name not in S["sponsors"] and len(S["sponsors"]) >= MAXSP: return self.err(f"حداکثر {MAXSP} اسپانسر")
            S["sponsors"][name] = tag; S["default_sponsor"] = S["default_sponsor"] or name
            save(); event(f"اسپانسر «{name}» ذخیره شد", "ok"); FLEET.sync(); return self.ok()
        if p == "/api/sponsors/default":
            n = str(d.get("name", ""))
            if n and n not in S["sponsors"]: return self.err("پیدا نشد")
            S["default_sponsor"] = n; save(); FLEET.sync(); return self.ok()
        # ---- endpoints ----
        if p == "/api/endpoints":
            eps = endpoints()
            if sum(e["source"] == "railway" for e in eps) >= MAXEP: return self.err(f"حداکثر {MAXEP} TCP")
            port = free_entry_port(eps)
            if not port: return self.err("پورت آزاد نمونده (MAX_ENDPOINTS رو بیشتر کن)")
            n = rw_create(port); S["port_sponsor"].pop(str(port), None); k = f"{n['domain']}:{n['proxyPort']}"
            if d.get("kind") == "socks": S["port_kind"][str(port)] = "socks"
            else: S["port_kind"].pop(str(port), None)
            save()
            event(f"TCP جدید ساخته شد: {k}", "ok"); FLEET.sync()
            threading.Thread(target=lambda: (time.sleep(5), [check_endpoint(e) for e in endpoints() if e["key"] == k]), daemon=True).start()
            return self.ok(endpoint=n)
        if p == "/api/endpoints/replace":
            key, eps = str(d.get("key", "")), endpoints(); e = next((x for x in eps if x["key"] == key), None)
            if not e or e["source"] != "railway": return self.err("فقط TCP های Railway (با توکن) قابل تعویضن")
            port = free_entry_port(eps)
            try:
                if not port: raise RuntimeError("no port")
                n = rw_create(port); rw_delete(e["id"])
            except Exception: rw_delete(e["id"]); n = rw_create(e["app_port"])
            nk, na = f"{n['domain']}:{n['proxyPort']}", int(n["applicationPort"])
            if na != e["app_port"] and (sp := S["port_sponsor"].pop(str(e["app_port"]), None)): S["port_sponsor"][str(na)] = sp
            if na != e["app_port"] and (kd := S["port_kind"].pop(str(e["app_port"]), None)): S["port_kind"][str(na)] = kd
            if (al := S["aliases"].pop(key, None)): S["aliases"][nk] = al
            if S["primary"] == key: S["primary"] = nk
            CHECKS.pop(key, None); save(); event(f"TCP عوض شد: {key} ← {nk}", "ok"); FLEET.sync(); return self.ok(endpoint=n)
        if p == "/api/endpoints/manual":
            dom = str(d.get("domain", "")).strip().lower()
            try: port, app = int(d.get("port")), int(d.get("app_port") or BASE)
            except Exception: return self.err("پورت نامعتبر")
            if not DOMAIN_RE.match(dom) or not 1 <= port <= 65535: return self.err("آدرس نامعتبر")
            if app not in ENTRY: return self.err(f"پورت داخلی باید بین {ENTRY[0]} تا {ENTRY[-1]} باشه")
            S["manual_endpoints"].append({"id": secrets.token_hex(4), "domain": dom, "port": port, "app_port": app}); S["port_kind"].update({str(app): "socks"} if d.get("kind") == "socks" else {}); save()
            event(f"TCP دستی اضافه شد: {dom}:{port}"); return self.ok()
        if p == "/api/endpoints/alias":
            key, al = str(d.get("key", "")), str(d.get("alias", "")).strip().lower()
            if al and not DOMAIN_RE.match(al): return self.err("دامنه نامعتبره")
            if al: S["aliases"][key] = al
            else: S["aliases"].pop(key, None)
            CHECKS.pop(key, None); save(); return self.ok()
        if p == "/api/endpoints/sponsor":
            e, sp = next((x for x in endpoints() if x["key"] == d.get("key")), None), str(d.get("sponsor", ""))
            if not e or (sp not in ("", "-") and sp not in S["sponsors"]): return self.err("پیدا نشد")
            if sp: S["port_sponsor"][str(e["app_port"])] = sp
            else: S["port_sponsor"].pop(str(e["app_port"]), None)
            save(); FLEET.sync(); return self.ok()
        if p == "/api/endpoints/kind":
            e, kd = next((x for x in endpoints() if x["key"] == d.get("key")), None), str(d.get("kind"))
            if not e or kd not in ("mtproto", "socks"): return self.err("پیدا نشد")
            if kd == "socks": S["port_kind"][str(e["app_port"])] = "socks"
            else: S["port_kind"].pop(str(e["app_port"]), None)
            CHECKS.pop(e["key"], None); save(); FLEET.sync(); return self.ok()
        if p == "/api/endpoints/primary": S["primary"] = str(d.get("key", "")); save(); return self.ok()
        if p == "/api/endpoints/check": threading.Thread(target=lambda: [check_endpoint(e) for e in endpoints()], daemon=True).start(); return self.ok()
        if p == "/api/endpoints/probe":
            for e in endpoints():
                if e["key"] in set(d.get("keys") or []) and e["app_port"] in FWD: FWD[e["app_port"]]["pending"] += 2; FWD[e["app_port"]]["pts"] = time.time()
            return self.ok()
        if p == "/api/endpoints/refresh": rw_list(True); return self.ok()
        # ---- users ----
        if p == "/api/users":
            name = str(d.get("name", "")).strip()
            if not NAME_RE.match(name): return self.err("اسم فقط حروف انگلیسی، عدد، - و _ (حداکثر ۳۲)")
            if name in S["users"]: return self.err("این اسم وجود داره")
            u = new_user(); apply_limits(u, d); S["users"][name] = u; save(); event(f"کاربر «{name}» ساخته شد", "ok"); FLEET.sync(); return self.ok()
        m = re.match(r"^/api/users/([A-Za-z0-9_\-]+)(/rotate_socks|/rotate|/toggle|/reset)?$", p)
        if m:
            n, act = m.group(1), m.group(2); u = S["users"].get(n)
            if not u: return self.err("کاربر پیدا نشد", 404)
            if act == "/rotate": u["secret"] = secrets.token_hex(16); event(f"لینک «{n}» عوض شد")
            elif act == "/rotate_socks": u["socks_pass"] = secrets.token_hex(8); event(f"پسورد SOCKS5 «{n}» عوض شد")
            elif act == "/toggle": u["enabled"] = not u["enabled"]; u["reason"] = "" if u["enabled"] else "manual"
            elif act == "/reset": S["usage"][n] = 0; u["reason"] = "" if u["reason"] == "quota" else u["reason"]
            else:
                apply_limits(u, d)
                if not u["enabled"] and u["reason"] in ("quota", "expired"): u["enabled"], u["reason"] = True, ""
            save(); enforce(); FLEET.sync(); return self.ok()
        self.err("not found", 404)

class Server(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = allow_reuse_address = True

def main():
    save(); a = S["admin"]
    print("=================== NULL PROXY PANEL ===================")
    print("Admin password:", "(custom, set in panel)" if a.get("hash") else "(from ADMIN_PASSWORD)" if E("ADMIN_PASSWORD") else env_password())
    print(f"Panel: {WEB} | Entry ports: {ENTRY[0]}-{ENTRY[-1]} | Data: {DATA_DIR} ({'persistent' if PERSISTENT else 'temporary'})")
    print("========================================================")
    threading.Thread(target=run_forwarders, daemon=True).start()
    FLEET.sync()
    for t in (FLEET.watchdog, sampler, checker): threading.Thread(target=t, daemon=True).start()
    def bye(*_):
        FLEET.want = False
        try: save()
        except Exception: pass
        for i in FLEET.inst.values(): i.stop()
        os._exit(0)
    signal.signal(signal.SIGTERM, bye); signal.signal(signal.SIGINT, bye)
    event("پنل روشن شد", "ok"); Server(("0.0.0.0", WEB), H).serve_forever()

if __name__ == "__main__": main()
