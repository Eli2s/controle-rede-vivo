"""
Painel de Controle de Rede - Roteador Vivo
Bloqueia e libera dispositivos via firewall do roteador.
"""

import hashlib
import re
import threading
import time
import webbrowser
from flask import Flask, jsonify, render_template_string, request
import requests
from requests.exceptions import RequestException
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# ── Configurações ──────────────────────────────────────────────────────────────
# Lê do arquivo .env se existir, senão usa variáveis de ambiente
import os, pathlib

_env = pathlib.Path(__file__).parent / ".env"
if _env.exists():
    for _line in _env.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

ROUTER_IP   = os.environ.get("ROUTER_IP",  "192.168.15.1")
USERNAME    = os.environ.get("ROUTER_USER", "admin")
PASSWORD    = os.environ.get("ROUTER_PASS", "")
ROUTER_BASE = f"http://{ROUTER_IP}"
RULE_PREFIX = "BLOQUEAR_"

if not PASSWORD:
    raise SystemExit("Erro: defina ROUTER_PASS no arquivo .env")

app = Flask(__name__)

# ── Sessão HTTP ────────────────────────────────────────────────────────────────

DEVICE_PATTERN = (
    r'<td class="cinza">([^<]*)</td>\s*'
    r'<td class="center">((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})</td>\s*'
    r'<td class="center">([\d.]+)</td>\s*'
    r'<td class="center">([^<]+)</td>'
)
RULE_PATTERN = (
    r'<td class="cinza">(' + re.escape(RULE_PREFIX) + r'[^<]*)</td>'
    r'.*?<td class="center">([^<]+)</td>'
    r'.*?<td class="center">([^<]+)</td>'
    r'.*?<td class="center">([^<]*(?:\d{1,3}\.){3}\d{1,3}[^<]*)</td>'
    r'.*?editClick\((\d+)\)'
)
FW_REFERER = {"Referer": f"{ROUTER_BASE}/cgi-bin/settings-firewall.cgi"}


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})
    adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.5,
                                            allowed_methods=["GET", "POST"]))
    s.mount("http://", adapter)
    return s


def _login(session: requests.Session) -> bool:
    """Autentica e retorna True se bem-sucedido."""
    try:
        r = session.get(f"{ROUTER_BASE}/cgi-bin/login.cgi", timeout=12)
        sid = re.search(r"var sid = '([^']+)'", r.text)
        if not sid:
            return False
        h = hashlib.md5(f"{PASSWORD}:{sid.group(1)}".encode()).hexdigest()
        session.post(f"{ROUTER_BASE}/cgi-bin/login.cgi",
                     data={"Loginuser": USERNAME, "LoginPasswordValue": h,
                           "acceptLoginIndex": "1"}, timeout=12)
        return "COOKIE_SESSION_KEY" in session.cookies
    except RequestException:
        return False


def _rget(session: requests.Session, path: str, **kw) -> requests.Response:
    """GET com re-login automático se a sessão expirar."""
    r = session.get(f"{ROUTER_BASE}{path}", timeout=30, **kw)
    if "login.cgi" in r.url or r.status_code == 302:
        _login(session)
        r = session.get(f"{ROUTER_BASE}{path}", timeout=30, **kw)
    return r


def _rpost(session: requests.Session, path: str, data: dict, **kw) -> requests.Response:
    """POST com re-login automático se a sessão expirar."""
    r = session.post(f"{ROUTER_BASE}{path}", data=data, timeout=30, **kw)
    if "login.cgi" in r.url or r.status_code == 302:
        _login(session)
        r = session.post(f"{ROUTER_BASE}{path}", data=data, timeout=30, **kw)
    return r


# ── Cache ──────────────────────────────────────────────────────────────────────

_cache = {"devices": [], "blocked": {}, "error": "", "ts": 0.0}
_cache_lock   = threading.Lock()
_fetch_lock   = threading.Lock()   # garante apenas 1 fetch simultâneo
_POLL_INTERVAL = 30.0              # segundos entre atualizações


def _fetch_devices(session: requests.Session) -> list:
    r = _rget(session, "/cgi-bin/device-management-statistics.cgi")
    devices = []
    for hostname, mac, ip, uptime in re.findall(DEVICE_PATTERN, r.text):
        devices.append({"hostname": hostname.strip() or "(sem nome)",
                        "mac": mac.upper(), "ip": ip, "uptime": uptime.strip()})
    return devices


def _fetch_blocked(session: requests.Session) -> dict:
    r = _rget(session, "/cgi-bin/TR181FirewallRule.cgi", headers=FW_REFERER)
    blocked = {}
    for *_, local_ip, idx in re.findall(RULE_PATTERN, r.text, re.DOTALL):
        ip = local_ip.strip()
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            blocked[ip] = int(idx)
    return blocked


def refresh_cache():
    """
    Busca dados do roteador e atualiza o cache.
    Usa sessões separadas por requisição para contornar a expiração de sessão
    que ocorre após carregar a página de estatísticas.
    """
    if not _fetch_lock.acquire(blocking=False):
        return   # já tem um fetch em andamento
    try:
        # Sessão 1: dispositivos (a mais lenta — ~10s — e invalida a sessão)
        s1 = _make_session()
        if not _login(s1):
            raise RuntimeError("Falha no login ao buscar dispositivos.")
        devices = _fetch_devices(s1)

        # Sessão 2: regras de firewall (rápida — usa nova sessão)
        s2 = _make_session()
        if not _login(s2):
            raise RuntimeError("Falha no login ao buscar regras.")
        blocked = _fetch_blocked(s2)

        with _cache_lock:
            _cache["devices"] = devices
            _cache["blocked"] = blocked
            _cache["error"]   = ""
            _cache["ts"]      = time.monotonic()
    except Exception as e:
        with _cache_lock:
            _cache["error"] = str(e)
    finally:
        _fetch_lock.release()


def _poller():
    """Atualiza o cache periodicamente em background."""
    while True:
        refresh_cache()
        time.sleep(_POLL_INTERVAL)


def get_cache():
    """Retorna o cache atual (sem bloquear)."""
    with _cache_lock:
        return dict(_cache)


# ── Ações diretas no roteador ─────────────────────────────────────────────────

def block_device(ip: str, hostname: str) -> bool:
    safe = re.sub(r'[^A-Za-z0-9_-]', '', hostname)[:10]
    name = (RULE_PREFIX + safe)[:20]
    s = _make_session()
    if not _login(s):
        raise RuntimeError("Falha no login ao bloquear.")
    resp = _rpost(s, "/cgi-bin/settings-firewall.cgi", headers=FW_REFERER, data={
        "firewallAction": "add", "ruleEditIndex": "0",
        "ruleName": name, "ruleTarget": "Reject", "ruleSrcInterface": "Lan",
        "ruleProtocol": "TCPUDP", "ruleIPVersion": "4",
        "ruleLocalPort": "", "ruleLocalPortRangeMax": "",
        "ruleLocalIP": ip, "ruleLocalMask": "",
        "ruleRemotePort": "", "ruleRemotePortRangeMax": "",
        "ruleRemoteIP": "", "ruleRemoteMask": "",
    })
    return resp.status_code < 400


def unblock_device(rule_index: int) -> bool:
    s = _make_session()
    if not _login(s):
        raise RuntimeError("Falha no login ao liberar.")
    resp = _rpost(s, "/cgi-bin/settings-firewall.cgi", headers=FW_REFERER, data={
        "firewallAction": "delete",
        "firewallRuleIndex": str(rule_index),
        "firewallSystemReboot": "No",
    })
    return resp.status_code < 400


# ── HTML ───────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Controle de Rede</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e2e8f0;min-height:100vh;padding:28px 24px}
h1{font-size:1.45rem;font-weight:700;color:#fff;letter-spacing:-.02em}
.subtitle{font-size:.82rem;color:#4b5563;margin-top:3px}
.toolbar{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.btn-refresh{padding:7px 16px;background:#161b22;border:1px solid #30363d;border-radius:8px;color:#8b949e;font-size:.8rem;cursor:pointer;transition:background .15s}
.btn-refresh:hover{background:#21262d;color:#e2e8f0}
.stats{display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.stat{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:10px 16px;font-size:.8rem;color:#8b949e}
.stat strong{color:#e2e8f0;font-size:1.1rem;display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.card{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:16px 18px;display:flex;flex-direction:column;gap:10px;transition:border-color .2s}
.card:hover{border-color:#30363d}
.card.blocked{border-color:#7f1d1d;background:#160d0d}
.card-top{display:flex;align-items:center;gap:12px}
.avatar{width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.1rem;flex-shrink:0}
.av-on{background:#0f4c41}.av-off{background:#450a0a}
.name{font-weight:600;font-size:.9rem;color:#e2e8f0;word-break:break-all}
.badge{display:inline-block;padding:1px 7px;border-radius:999px;font-size:.7rem;font-weight:700;margin-left:6px;vertical-align:middle}
.b-online{background:#134e4a;color:#2dd4bf}.b-blocked{background:#450a0a;color:#fca5a5}
.meta{display:grid;grid-template-columns:60px 1fr;gap:2px 8px;font-size:.76rem}
.ml{color:#4b5563}.mv{color:#8b949e;word-break:break-all}
.btn{width:100%;padding:8px;border:none;border-radius:8px;font-size:.82rem;font-weight:600;cursor:pointer;transition:opacity .15s,transform .1s;margin-top:2px}
.btn:hover{opacity:.85}.btn:active{transform:scale(.98)}
.btn-block{background:#b91c1c;color:#fff}.btn-unblock{background:#0f766e;color:#fff}
.btn-busy{background:#1f2937;color:#4b5563;cursor:not-allowed}
.toast{position:fixed;bottom:22px;right:22px;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:11px 18px;font-size:.82rem;max-width:280px;opacity:0;transform:translateY(6px);transition:opacity .22s,transform .22s;z-index:99}
.toast.show{opacity:1;transform:translateY(0)}
.toast.ok{border-color:#0f4c41;color:#2dd4bf}.toast.err{border-color:#7f1d1d;color:#fca5a5}
.foot{font-size:.75rem;color:#374151;margin-top:22px}
.spin{display:inline-block;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.empty{text-align:center;padding:48px;color:#4b5563;grid-column:1/-1}
.loading-bar{height:2px;background:linear-gradient(90deg,#0d9488,#0f766e);border-radius:2px;margin-bottom:16px;animation:pulse 1.5s ease-in-out infinite;display:none}
@keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}
</style>
</head>
<body>
<div class="toolbar">
  <div>
    <h1>Controle de Rede</h1>
    <div class="subtitle">Roteador Vivo &mdash; 192.168.15.1</div>
  </div>
  <button class="btn-refresh" onclick="load()">&#8635;&nbsp; Atualizar</button>
</div>
<div class="loading-bar" id="lbar"></div>
<div class="stats">
  <div class="stat"><strong id="s-total">—</strong>Conectados</div>
  <div class="stat"><strong id="s-blocked">—</strong>Bloqueados</div>
  <div class="stat"><strong id="s-free">—</strong>Livres</div>
  <div class="stat"><strong id="s-age">—</strong>Dados com</div>
</div>
<div class="grid" id="grid">
  <div class="empty"><span class="spin">&#9696;</span>&nbsp; Carregando — primeira carga leva ~15s...</div>
</div>
<div class="foot" id="foot"></div>
<div class="toast" id="toast"></div>

<script>
let devices=[], blocked={}, cacheAge=0;

function setLoading(on){
  document.getElementById('lbar').style.display = on ? 'block' : 'none';
}

async function load(){
  setLoading(true);
  document.getElementById('foot').innerHTML='<span class="spin">&#9696;</span> Buscando...';
  try{
    const r = await fetch('/api/devices');
    const d = await r.json();
    if(!d.ok) throw new Error(d.error||'Erro');
    devices=d.devices; blocked=d.blocked; cacheAge=d.age_s;
    render();
    const n=devices.length, b=Object.keys(blocked).length;
    document.getElementById('s-total').textContent=n;
    document.getElementById('s-blocked').textContent=b;
    document.getElementById('s-free').textContent=n-b;
    document.getElementById('s-age').textContent=cacheAge+'s';
    document.getElementById('foot').textContent='Atualizado em '+new Date().toLocaleTimeString('pt-BR');
  }catch(e){
    document.getElementById('foot').textContent='Erro: '+e.message;
    toast('Falha: '+e.message,'err');
  } finally { setLoading(false); }
}

function render(){
  const g=document.getElementById('grid');
  if(!devices.length){g.innerHTML='<div class="empty">Nenhum dispositivo encontrado.</div>';return;}
  g.innerHTML=devices.map(d=>{
    const bl=d.ip in blocked, ri=blocked[d.ip]??null;
    return `<div class="card${bl?' blocked':''}" id="c-${d.ip.replace(/\\./g,'-')}">
      <div class="card-top">
        <div class="avatar ${bl?'av-off':'av-on'}">${bl?'🚫':'💻'}</div>
        <div class="name">${d.hostname}<span class="badge ${bl?'b-blocked':'b-online'}">${bl?'Bloqueado':'Online'}</span></div>
      </div>
      <div class="meta">
        <span class="ml">IP</span><span class="mv">${d.ip}</span>
        <span class="ml">MAC</span><span class="mv">${d.mac}</span>
        <span class="ml">Tempo</span><span class="mv">${d.uptime}</span>
      </div>
      ${bl
        ?`<button class="btn btn-unblock" onclick="unblock('${d.ip}',${ri},this)">&#9654; Liberar acesso</button>`
        :`<button class="btn btn-block"   onclick="block('${d.ip}','${d.hostname}',this)">&#128683; Bloquear internet</button>`
      }</div>`;
  }).join('');
}

async function block(ip,hostname,btn){
  setBusy(btn,'Bloqueando...');
  try{
    const r=await fetch('/api/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,hostname})});
    const d=await r.json();
    if(!d.ok) throw new Error(d.error);
    toast(`${hostname} bloqueado.`,'ok');
    await load();
  }catch(e){toast('Erro: '+e.message,'err');await load();}
}

async function unblock(ip,ri,btn){
  setBusy(btn,'Liberando...');
  try{
    const r=await fetch('/api/unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,rule_index:ri})});
    const d=await r.json();
    if(!d.ok) throw new Error(d.error);
    toast(`${ip} liberado.`,'ok');
    await load();
  }catch(e){toast('Erro: '+e.message,'err');await load();}
}

function setBusy(btn,txt){btn.className='btn btn-busy';btn.textContent=txt;btn.disabled=true;}
function toast(msg,type){
  const t=document.getElementById('toast');
  t.textContent=msg; t.className=`toast show ${type}`;
  clearTimeout(t._t); t._t=setTimeout(()=>t.className='toast',3500);
}

load();
setInterval(load, 35000);
</script>
</body>
</html>"""


# ── Rotas ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/devices")
def api_devices():
    c = get_cache()
    if c["error"] and not c["devices"]:
        return jsonify({"ok": False, "error": c["error"]}), 500
    age = round(time.monotonic() - c["ts"], 1) if c["ts"] else None
    return jsonify({"ok": True, "devices": c["devices"],
                    "blocked": c["blocked"], "age_s": age})


@app.route("/api/block", methods=["POST"])
def api_block():
    data     = request.get_json()
    ip       = (data.get("ip") or "").strip()
    hostname = (data.get("hostname") or "device").strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return jsonify({"ok": False, "error": "IP inválido"}), 400
    try:
        ok = block_device(ip, hostname)
        if ok:
            threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"ok": ok})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data       = request.get_json()
    rule_index = data.get("rule_index")
    if rule_index is None:
        return jsonify({"ok": False, "error": "rule_index não informado"}), 400
    try:
        ok = unblock_device(int(rule_index))
        if ok:
            threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"ok": ok})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    PORT = 5000
    print(f"\n  Painel de Controle de Rede")
    print(f"  Roteador : http://{ROUTER_IP}")
    print(f"  Painel   : http://localhost:{PORT}")
    print(f"  (Primeira carga leva ~15s enquanto o cache é construído)")
    print(f"  Para parar: Ctrl+C\n")

    # Poller em background: atualiza o cache a cada 30s
    threading.Thread(target=_poller, daemon=True).start()

    threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{PORT}")).start()
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
