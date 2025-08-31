#!/usr/bin/env python3
# veracode_local_runner.py
#
# Customer-ready Veracode exporter
# Modes:
#   - tenant-all-in-one (Apps, Summaries, FrequencyCompliance, ReportingAPI, OpenFlawsSummary)
#   - scan-compliance (per-app)
#   - tenant-scan-compliance (tenant-wide)
#
# Listing: v1 ONLY -> /appsec/v1/applications?page=&size=&published_scans_only=false
# Summaries: ALWAYS derived from Reporting (open_sev_5..0 + last_scan_*), optionally enrich with summary_report (v2->v1)
# OpenFlawsSummary: pivot OPEN counts by severity 5..0 for STATIC/DYNAMIC/SCA/MPT (+ Total) + per-type charts (labels + colors)
#
# pip install: requests python-dotenv pandas openpyxl veracode-api-signing httpie rich

import os, sys, time, argparse, json, re, subprocess, shutil, html
from typing import Dict, Any, Optional, List, Tuple, Callable
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from datetime import datetime, timezone, timedelta, date
import requests
from dotenv import load_dotenv

# ===== Config / Flags
load_dotenv()
BASE = os.environ.get("VERACODE_BASE", "https://api.veracode.com").rstrip("/")
KEY_ID = os.environ.get("VERACODE_API_KEY_ID")
KEY_SECRET = os.environ.get("VERACODE_API_KEY_SECRET")
PAGE_SLEEP = float(os.environ.get("PAGE_SLEEP", "0.0"))
DEBUG = os.environ.get("VERACODE_DEBUG", "0").lower() in ("1","true","yes")
QUIET = False
PRETTY = False
RICH = None
PROGRESS = None

if not KEY_ID or not KEY_SECRET:
    print("ERROR: VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET must be set.", file=sys.stderr)

try:
    from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
except Exception:
    print("Missing veracode-api-signing package. Install: pip install veracode-api-signing", file=sys.stderr)
    raise
AUTH = RequestsAuthPluginVeracodeHMAC(api_key_id=KEY_ID, api_key_secret=KEY_SECRET)

def log(*args):
    if DEBUG and not QUIET:
        print("[DEBUG]", *args, file=sys.stderr)

def _full_url(p: str) -> str:
    return p if p.startswith(("http://","https://")) else urljoin(BASE + "/", p.lstrip("/"))

# ===== HTTP (requests + HTTPie fallback; preserve query)
def _requests_json(method:str, url:str, params=None, body=None, timeout:int=120):
    r = requests.get(url, params=params, auth=AUTH, timeout=timeout) if method=="GET" \
        else requests.post(url, json=body, auth=AUTH, timeout=timeout)
    if r.status_code in (200,201): return r.json()
    try: err = r.json()
    except Exception: err = {"http_code": r.status_code, "http_status": r.reason, "message": r.text[:400]}
    raise RuntimeError(json.dumps(err))

def _httpie_json(method:str, url:str, body=None):
    if shutil.which("http") is None:
        raise RuntimeError("HTTPie ('http') not found. pip install httpie")
    cmd = ["http","--body","-A","veracode_hmac",method,url]
    p = subprocess.run(cmd, input=json.dumps(body) if body is not None else None, text=True, capture_output=True)
    if p.returncode != 0: raise RuntimeError(p.stderr.strip())
    return json.loads(p.stdout)

def get_json(path:str, params:Optional[Dict[str,Any]]=None, timeout:int=120)->Dict[str,Any]:
    url = _full_url(path)
    try:
        return _requests_json("GET", url, params=params, timeout=timeout)
    except Exception as e:
        log("requests GET failed; using httpie", url, "->", e)
        if params: url = url + ("?" + urlencode(params, doseq=True))
        return _httpie_json("GET", url)

def post_json(path:str, body:Dict[str,Any], timeout:int=120)->Dict[str,Any]:
    url = _full_url(path)
    try:
        return _requests_json("POST", url, body=body, timeout=timeout)
    except Exception as e:
        log("requests POST failed; using httpie", url, "->", e)
        return _httpie_json("POST", url, body=body)

# ===== Text & time helpers
_HTML_RE = re.compile(r"<[^>]+>"); _WS_RE = re.compile(r"\s+")
_TS_KEYS = ("last_seen","updated","modified","published","created","first_seen","first_found","completed")

def _clean_text(x: Any, max_len:int=20000)->Optional[str]:
    if x is None: return None
    s = json.dumps(x, ensure_ascii=False) if isinstance(x,(dict,list)) else str(x)
    s = html.unescape(s); s = _HTML_RE.sub(" ", s); s = _WS_RE.sub(" ", s).strip()
    return s[:max_len] if max_len and len(s) > max_len else s

def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts or not isinstance(ts, str): return None
    ts = ts.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ","%Y-%m-%dT%H:%M:%SZ","%Y-%m-%d %H:%M:%S","%Y-%m-%d"):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except Exception: pass
    if ts.endswith("Z"):
        try: return datetime.strptime(ts[:-1], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
        except Exception: pass
    return None

def _latest_iso(a: Optional[str], b: Optional[str]) -> Optional[str]:
    da, db = _parse_iso(a), _parse_iso(b)
    if da and db: return a if da >= db else b
    return a or b

def _extract_latest_ts(d: Any) -> Optional[str]:
    best=None; stack=[d]
    while stack:
        node=stack.pop()
        if isinstance(node, dict):
            for k,v in node.items():
                if isinstance(v,(dict,list)): stack.append(v)
                elif isinstance(v,str) and any(x in k.lower() for x in _TS_KEYS):
                    best=_latest_iso(best, v)
        elif isinstance(node, list):
            stack.extend(node)
    return best

def _parse_as_of(s: Optional[str]) -> datetime:
    return datetime.now(timezone.utc) if not s else datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)

# ===== Half-year windows
def _windows_half_year(start_dt: date, end_dt: date) -> List[Tuple[date, date]]:
    wins=[]; cur=date(start_dt.year, 1 if start_dt.month<=6 else 7, 1)
    while cur<=end_dt:
        w_end=date(cur.year, 6, 30) if cur.month==1 else date(cur.year, 12, 31)
        if w_end>end_dt: w_end=end_dt
        wins.append((max(cur,start_dt), w_end))
        cur = date(cur.year, 7, 1) if cur.month==1 else date(cur.year+1, 1, 1)
    return wins

# ===== Apps utilities
CF_KEYS = [f"cf_Custom_{i}" for i in range(1, 26)]  # 1..25

def _extract_custom_fields_from_profile(prof: Dict[str,Any]) -> Dict[str,Any]:
    out = {k: None for k in CF_KEYS}
    lst = prof.get("custom_fields") or prof.get("customFields")
    if isinstance(lst, list):
        idx = 1
        for it in lst:
            if not isinstance(it, dict): continue
            name = str(it.get("name") or it.get("key") or "").strip()
            val  = it.get("value")
            m = re.match(r"custom\s*(\d+)", name, re.IGNORECASE)
            if m:
                n = int(m.group(1))
                if 1 <= n <= 25:
                    out[f"cf_Custom_{n}"] = val
                    continue
            while idx <= 25 and out[f"cf_Custom_{idx}"] is not None:
                idx += 1
            if idx <= 25:
                out[f"cf_Custom_{idx}"] = val; idx += 1
    return out

def _app_row_from_listing(item: Dict[str,Any]) -> Dict[str,Any]:
    prof = item.get("profile") if isinstance(item.get("profile"), dict) else {}
    bu   = prof.get("business_unit") if isinstance(prof.get("business_unit"), dict) else {}
    pols = prof.get("policies") if isinstance(prof.get("policies"), list) else []; pol = pols[0] if pols else {}
    teams = prof.get("teams") if isinstance(prof.get("teams"), list) else []
    base = {
        "guid": item.get("guid"), "id": item.get("id"), "name": prof.get("name"),
        "business_criticality": prof.get("business_criticality"),
        "business_unit_name": bu.get("name"), "business_unit_guid": bu.get("guid"),
        "policy_guid": pol.get("guid"), "policy_name": pol.get("name"),
        "policy_status": pol.get("policy_compliance_status"),
        "tags": prof.get("tags"),
        "teams": ",".join(t.get("team_name","") for t in teams if isinstance(t,dict)),
        "created": item.get("created"), "modified": item.get("modified"),
        "last_completed_scan_date": item.get("last_completed_scan_date"),
        "last_policy_compliance_check_date": item.get("last_policy_compliance_check_date"),
    }
    base.update(_extract_custom_fields_from_profile(prof))
    return base

# ===== Listing pretty progress (apps/sec)
def _fmt_listing_desc(pages_fetched: int, total_pages: Optional[int], apps_found: int, apps_per_sec: float) -> str:
    rate = f"{apps_per_sec:.1f}/s" if apps_per_sec >= 0 else "n/a"
    if total_pages is None:
        return f"🌀 Listing applications — pages: {pages_fetched}/?  apps: {apps_found}  rate: {rate}"
    return f"🌀 Listing applications — pages: {pages_fetched}/{total_pages}  apps: {apps_found}  rate: {rate}"

def list_apps(q: Optional[str], limit: int, page_size: int,
              progress_cb: Optional[Callable[[int, Optional[int], int], None]] = None) -> List[Dict[str, Any]]:
    """
    v1-only listing (captures all apps, even if no published scans)
    GET /appsec/v1/applications?page=&size=&published_scans_only=false
    """
    base={"size":page_size, "published_scans_only":"false"}
    if q: base["name"]=q
    out=[]; total_collected=0
    obj = get_json("/appsec/v1/applications", dict(base, page=0))
    items = (obj.get("_embedded") or {}).get("applications") or []
    out.extend(items); total_collected += len(items)
    page_meta = obj.get("page") or {}
    cur = page_meta.get("number", 0)
    total_pages = page_meta.get("total_pages")
    if progress_cb: progress_cb(total_collected, total_pages, cur)
    while True:
        if len(out) >= limit: break
        cur += 1
        obj = get_json("/appsec/v1/applications", dict(base, page=cur))
        items = (obj.get("_embedded") or {}).get("applications") or []
        if not items: break
        out.extend(items); total_collected += len(items)
        page_meta = obj.get("page") or {}
        total_pages = page_meta.get("total_pages", total_pages)
        if progress_cb: progress_cb(total_collected, total_pages, cur)
        if PAGE_SLEEP: time.sleep(PAGE_SLEEP)
        if total_pages is not None and cur >= (total_pages-1): break
    return out[:limit]

def get_app_details(app_guid: str) -> Dict[str, Any]:
    try:
        return get_json(f"/appsec/v1/applications/{app_guid}")
    except Exception:
        return {"guid": app_guid}

# ===== Policy & Compliance (core)
FREQ_TO_DAYS = {"WEEKLY":7,"BIWEEKLY":14,"MONTHLY":30,"QUARTERLY":90,"SEMI_ANNUAL":182,"ANNUAL":365,"ONCE":10**9}
FREQ_ALIASES = {
    "WEEK":"WEEKLY","WEEKLY":"WEEKLY","BIWEEKLY":"BIWEEKLY","MONTH":"MONTHLY","MONTHLY":"MONTHLY",
    "QUARTER":"QUARTERLY","QUARTERLY":"QUARTERLY","SEMI-ANNUAL":"SEMI_ANNUAL","SEMIANNUAL":"SEMI_ANNUAL",
    "BIANNUAL":"SEMI_ANNUAL","SEMI_ANNUAL":"SEMI_ANNUAL","ANNUAL":"ANNUAL","YEARLY":"ANNUAL",
    "ONCE":"ONCE","ONE_TIME":"ONCE","ONE-TIME":"ONCE",
}

def normalize_scan_type(st: Optional[str])->str:
    s = (st or "").strip().lower()
    if not s: return "UNKNOWN"
    if "static" in s or "sast" in s: return "STATIC"
    if "dynamic" in s or "dast" in s: return "DYNAMIC"
    if "sca" in s or "composition" in s: return "SCA"
    if "manual" in s or "pen" in s or "mpt" in s: return "MANUAL_PEN_TEST"
    s2 = (st or "").upper().replace(" ","_")
    return {"SAST":"STATIC","STATIC":"STATIC","DAST":"DYNAMIC","DYNAMIC":"DYNAMIC",
            "SCA":"SCA","MANUAL":"MANUAL_PEN_TEST","MPT":"MANUAL_PEN_TEST",
            "MANUAL_PEN_TEST":"MANUAL_PEN_TEST"}.get(s2, s2)

def _norm_freq(freq_raw: Optional[str], days_hint: Optional[int] = None) -> Tuple[str, Optional[int]]:
    if days_hint and isinstance(days_hint,int):
        for k,v in FREQ_TO_DAYS.items():
            if v == days_hint: return (k, days_hint)
        return ((freq_raw or "ANNUAL").upper(), days_hint)
    lab = FREQ_ALIASES.get((freq_raw or "ANNUAL").upper(), (freq_raw or "ANNUAL").upper())
    return (lab, FREQ_TO_DAYS.get(lab))

def get_policy_evaluation(app_guid:str)->Optional[Dict[str,Any]]:
    for p in (f"/appsec/v2/applications/{app_guid}/policy_evaluation",
              f"/appsec/v1/applications/{app_guid}/policy_evaluation",
              f"/policy/v2/applications/{app_guid}/evaluation"):
        try: return get_json(p)
        except Exception: continue
    return None

def parse_required_scans(eval_obj: Optional[Dict[str,Any]])->List[Dict[str,Any]]:
    if not isinstance(eval_obj, dict): return []
    reqs=[]; cands=[]
    if isinstance(eval_obj.get("required_scans"),list): cands=eval_obj["required_scans"]
    elif isinstance(eval_obj.get("policy"),dict):
        pol=eval_obj["policy"]
        if isinstance(pol.get("required_scans"),list): cands=pol["required_scans"]
        elif isinstance(pol.get("requirements"),list): cands=pol["requirements"]
    for it in cands:
        st=normalize_scan_type(it.get("type") or it.get("scan_type") or it.get("name"))
        freq_raw=(it.get("frequency") or it.get("scan_frequency") or it.get("requirement_frequency") or it.get("frequency_code"))
        days_hint=(it.get("frequency_days") or it.get("interval_days") or it.get("days"))
        freq,_=_norm_freq(freq_raw, days_hint if isinstance(days_hint,int) else None)
        due=it.get("next_due_date") or it.get("due") or it.get("due_date")
        reqs.append({"type":st,"frequency":freq,"next_due_date":due})
    return reqs

_POLICY_CACHE: Dict[str, List[Dict[str,Any]]] = {}
def get_policy_requirements_from_policy_guid(policy_guid: str) -> List[Dict[str, Any]]:
    if not policy_guid: return []
    if policy_guid in _POLICY_CACHE: return _POLICY_CACHE[policy_guid]
    try:
        obj = get_json(f"/appsec/v1/policies/{policy_guid}")
    except Exception as e:
        log("policy guid fetch failed", policy_guid, "->", e); _POLICY_CACHE[policy_guid]=[]; return []
    out: List[Dict[str, Any]] = []
    def _add(it: Dict[str,Any]):
        st=normalize_scan_type(it.get("type") or it.get("scan_type") or it.get("name"))
        freq_raw=(it.get("frequency") or it.get("scan_frequency") or it.get("requirement_frequency") or it.get("frequency_code"))
        days_hint=(it.get("frequency_days") or it.get("interval_days") or it.get("days"))
        freq,_=_norm_freq(freq_raw, days_hint if isinstance(days_hint,int) else None)
        due=it.get("next_due_date") or it.get("due_date") or it.get("due")
        out.append({"type":st,"frequency":freq,"next_due_date":due})
    for k in ("scan_frequency_rules","required_scans"):
        arr=obj.get(k)
        if isinstance(arr,list):
            for it in arr:
                if isinstance(it,dict): _add(it)
    emb=obj.get("_embedded") or {}
    for k in ("requirements","rules"):
        arr=emb.get(k)
        if isinstance(arr,list):
            for it in arr:
                if isinstance(it,dict): _add(it)
    _POLICY_CACHE[policy_guid]=out
    return out

def compute_frequency_rows(app_guid:str, app_name:str, requirements:List[Dict[str,Any]],
                           last_seen_by_type:Dict[str,str], cf_row: Optional[Dict[str,Any]]=None) -> List[Dict[str,Any]]:
    rows=[]; now=datetime.now(timezone.utc)
    cf_row = cf_row or {k: None for k in CF_KEYS}
    if requirements:
        for r in requirements:
            st=normalize_scan_type(r.get("type"))
            freq=(r.get("frequency") or "ANNUAL").upper(); freq=FREQ_ALIASES.get(freq,freq)
            if freq not in FREQ_TO_DAYS: freq="ANNUAL"
            last=last_seen_by_type.get(st)
            due=r.get("next_due_date")
            if not due and last:
                last_dt=_parse_iso(last)
                if last_dt: due=(last_dt+timedelta(days=FREQ_TO_DAYS[freq])).strftime("%Y-%m-%dT%H:%M:%SZ")
            if not last and not due:
                status="UNKNOWN"
            else:
                if due:
                    status="PAST_DUE" if (_parse_iso(due) and _parse_iso(due)<now) else "IN_COMPLIANCE"
                else:
                    last_dt=_parse_iso(last)
                    status="IN_COMPLIANCE" if (last_dt and (now-last_dt).days<=FREQ_TO_DAYS.get(freq,10**9)) else "PAST_DUE"
            row={"app_guid":app_guid,"app_name":app_name,"scan_type":st,"frequency":freq,
                 "last_policy_scan":last,"next_due":due,"status":status}
            row.update(cf_row); rows.append(row)
    if not rows:
        for st,last in (last_seen_by_type or {"UNKNOWN": None}).items():
            freq="ANNUAL"; due=None
            if last:
                last_dt=_parse_iso(last)
                if last_dt: due=(last_dt+timedelta(days=FREQ_TO_DAYS[freq])).strftime("%Y-%m-%dT%H:%M:%SZ")
            status="UNKNOWN" if (not due and not last) else ("PAST_DUE" if (due and _parse_iso(due) and _parse_iso(due)<now) else "IN_COMPLIANCE")
            row={"app_guid":app_guid,"app_name":app_name,"scan_type":st,"frequency":freq,
                 "last_policy_scan":last,"next_due":due,"status":status}
            row.update(cf_row); rows.append(row)
    return rows

# ===== Reporting (POST→POLL→GET; HAL next normalized; page guard)
def _normalize_hal_link(next_link:str, current_page:int, page_size:int)->str:
    if not next_link: return next_link
    if not next_link.startswith(("http://","https://")): next_link = _full_url(next_link)
    parsed = urlparse(next_link); q = parse_qs(parsed.query)
    if "page" not in q: q["page"] = [str(current_page + 1)]
    if "size" not in q: q["size"] = [str(page_size)]
    return parsed._replace(query=urlencode(q, doseq=True)).geturl()

def _reporting_post(report_type:str, payload:Dict[str,Any])->str:
    obj=post_json("/appsec/v1/analytics/report", {"report_type":report_type, **payload})
    rid=obj.get("id") or (obj.get("_embedded") or {}).get("id")
    if not rid: raise RuntimeError(f"Reporting POST returned no id: {obj}")
    return rid

def _reporting_get_page(report_id:str, page:int, size:int)->Dict[str,Any]:
    url = f"/appsec/v1/analytics/report/{report_id}?{urlencode({'page':page,'size':size})}"
    try:
        return get_json(url, params=None)
    except RuntimeError as e:
        if "Valid page numbers are" in str(e) and "BAD_REQUEST" in str(e):
            return {"findings": [], "page": {"number": page}}
        raise

def _extract_items_meta_links(obj:Dict[str,Any])->Tuple[List[Dict[str,Any]], Dict[str,Any], Optional[str]]:
    items = (obj.get("findings") or (obj.get("_embedded") or {}).get("findings") or obj.get("results") or obj.get("items") or [])
    meta  = (obj.get("page_metadata") or obj.get("page") or obj.get("_page") or {})
    nxt=None
    links=obj.get("_links") or obj.get("links") or {}
    if isinstance(links, dict):
        ln=links.get("next") or links.get("Next")
        if isinstance(ln, dict): nxt = ln.get("href")
        elif isinstance(ln, list) and ln: nxt = ln[0].get("href")
    return items, meta, nxt

def _poll_until_ready(report_id:str, tries:int, delay:float)->None:
    for _ in range(tries):
        probe=_reporting_get_page(report_id, 0, 1)
        status=(probe.get("status") or "").upper()
        items,_meta,_next=_extract_items_meta_links(probe)
        if status=="COMPLETED" or (items and len(items)>0): return
        time.sleep(delay)

def collect_reporting_findings_all_fields(report_type:str, start_date:str, end_date:Optional[str],
                                          page_size:int, poll_delay:float, poll_tries:int)->List[Dict[str,Any]]:
    sdt=datetime.strptime(start_date,"%Y-%m-%d").date()
    edt=(datetime.strptime(end_date,"%Y-%m-%d").date() if end_date else datetime.now(timezone.utc).date())
    if sdt>edt: sdt,edt=edt,sdt
    all_rows=[]; wins=_windows_half_year(sdt, edt)
    t_rep=None
    if PROGRESS: t_rep = PROGRESS.add_task("🌀 Reporting windows", total=len(wins))
    for ws,we in wins:
        try:
            rid=_reporting_post("findings", {"last_updated_start_date":f"{ws} 00:00:00",
                                             "last_updated_end_date":f"{we} 23:59:59"})
            _poll_until_ready(rid, poll_tries, poll_delay)
            first=_reporting_get_page(rid, 0, page_size)
            items, meta, next_link=_extract_items_meta_links(first)
            if items:
                for r in items: r["_window_start"]=str(ws); r["_window_end"]=str(we); r["_report_id"]=rid
                all_rows.extend(items)
            current = int((meta.get("number") or meta.get("pageNumber") or 0))
            total_p = int((meta.get("total_pages") or meta.get("totalPages") or 0))
            last_p  = (total_p-1) if total_p>0 else None
            # HAL follow
            hops=0
            while next_link and hops<1000:
                next_link = _normalize_hal_link(next_link, current, page_size)
                q = parse_qs(urlparse(next_link).query)
                target = int(q.get("page",[current+1])[0])
                if last_p is not None and target>last_p: break
                obj=get_json(next_link, params=None)
                items2, _m2, next_link = _extract_items_meta_links(obj)
                if not items2: break
                for r in items2: r["_window_start"]=str(ws); r["_window_end"]=str(we); r["_report_id"]=rid
                all_rows.extend(items2); hops+=1; current=target
            # Numeric paging if known
            if total_p>1:
                for pg in range(1,total_p):
                    obj=_reporting_get_page(rid, pg, page_size)
                    its,_m,_n = _extract_items_meta_links(obj)
                    if not its: break
                    for r in its: r["_window_start"]=str(ws); r["_window_end"]=str(we); r["_report_id"]=rid
                    all_rows.extend(its)
            elif not next_link:
                pg=1
                while True:
                    obj=_reporting_get_page(rid, pg, page_size)
                    its,_m,_n = _extract_items_meta_links(obj)
                    if not its: break
                    for r in its: r["_window_start"]=str(ws); r["_window_end"]=str(we); r["_report_id"]=rid
                    all_rows.extend(its); pg+=1
        except Exception as e:
            log("Reporting window failed", f"{ws}..{we}", "->", e)
        if PROGRESS and t_rep is not None: PROGRESS.advance(t_rep, 1)
        if PAGE_SLEEP: time.sleep(PAGE_SLEEP)
    if PROGRESS and t_rep is not None: PROGRESS.update(t_rep, completed=len(wins), description="✅ Reporting windows")
    return all_rows

# ===== Error envelope detection for summary endpoints
def _is_error_shape(obj: Dict[str,Any]) -> bool:
    if not isinstance(obj, dict): return True
    if any(k in obj for k in ("http_code","http_status","message")): return True
    emb = obj.get("_embedded") or {}
    if isinstance(emb, dict) and "error" in emb: return True
    return False

def get_summary_endpoint(app_guid: str) -> Optional[Dict[str, Any]]:
    for path in (f"/appsec/v2/applications/{app_guid}/summary_report",
                 f"/appsec/v1/applications/{app_guid}/summary_report"):
        try:
            obj=get_json(path, None)
            if _is_error_shape(obj): continue
            return obj
        except Exception:
            continue
    return None

# ===== Robust extraction helpers for summaries & open flaws
def _severity_to_int(sev: Any) -> Optional[int]:
    if sev is None: return None
    if isinstance(sev,(int,float)): s=int(sev); return s if 0<=s<=5 else None
    s=str(sev).strip().upper()
    m=re.match(r"^\s*(\d)\b", s)
    if m:
        d=int(m.group(1)); return d if 0<=d<=5 else None
    mapn={"VERY HIGH":5,"VERY_HIGH":5,"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"VERY LOW":1,"VERY_LOW":1,"INFORMATIONAL":0,"INFO":0}
    return mapn.get(s)

def _is_open_status(s: Optional[str]) -> bool:
    if not isinstance(s,str): return True
    ss=s.strip().upper()
    closed={"CLOSED","RESOLVED","FIXED","FALSE_POSITIVE","ACCEPTED","MITIGATED","SUPPRESSED","IGNORED","NOT_AFFECTED"}
    return False if ss in closed else True

def _extract_app_ref(rep_row: Dict[str,Any]) -> Tuple[Optional[str], Optional[int]]:
    guid=None; app_id=None
    for k in ("application_guid","app_guid","guid"):
        v=rep_row.get(k)
        if isinstance(v,str) and len(v)>=8: guid=v; break
    if not guid:
        a=rep_row.get("application") or {}
        v=a.get("guid")
        if isinstance(v,str) and len(v)>=8: guid=v
    for k in ("application_id","app_id","id","applicationId"):
        v=rep_row.get(k) or (rep_row.get("application") or {}).get(k)
        if isinstance(v,int): app_id=v; break
        if isinstance(v,str) and v.isdigit(): app_id=int(v); break
    return guid, app_id

def build_summaries_from_reporting(app_rows: List[Dict[str,Any]], reporting_rows: List[Dict[str,Any]]) -> List[Dict[str,Any]]:
    from collections import defaultdict
    by_guid=defaultdict(list); by_id=defaultdict(list)
    for r in reporting_rows or []:
        g,i=_extract_app_ref(r)
        if g: by_guid[g].append(r)
        if i is not None: by_id[i].append(r)
    out=[]
    for a in app_rows:
        ag=a.get("guid") or a.get("id"); nm=a.get("name")
        rows = by_guid.get(ag, []) or by_id.get(a.get("id"), [])
        sev_counts={i:0 for i in (5,4,3,2,1,0)}
        last_by_type={}
        for r in rows:
            st=normalize_scan_type(r.get("scan_type") or r.get("analysis_type") or r.get("type") or r.get("category"))
            if not _is_open_status(r.get("status") or r.get("finding_status") or r.get("state")): continue
            sev=(r.get("custom_severity") or r.get("customSeverity") or r.get("custom_severity_level") or
                 r.get("severity") or r.get("severity_level") or r.get("severity_num"))
            sev=_severity_to_int(sev)
            if sev is not None: sev_counts[sev]+=1
            ts=(r.get("last_seen") or r.get("lastUpdated") or r.get("last_updated") or
                r.get("updated") or r.get("modified") or r.get("published") or r.get("completed") or r.get("created"))
            if not ts: ts=_extract_latest_ts(r)
            if ts: last_by_type[st]=_latest_iso(last_by_type.get(st), ts)
        out.append({
            "app_guid":ag,"app_name":nm,
            "open_sev_5":sev_counts[5],"open_sev_4":sev_counts[4],"open_sev_3":sev_counts[3],
            "open_sev_2":sev_counts[2],"open_sev_1":sev_counts[1],"open_sev_0":sev_counts[0],
            "last_scan_STATIC":last_by_type.get("STATIC"),
            "last_scan_DYNAMIC":last_by_type.get("DYNAMIC"),
            "last_scan_SCA":last_by_type.get("SCA"),
            "last_scan_MANUAL_PEN_TEST":last_by_type.get("MANUAL_PEN_TEST"),
            "policy_status":a.get("policy_status")
        })
    return out

# ===== OpenFlawsSummary (pivot + charts, severity 5..0) with labels & colors
SEV_COLORS = {5:"D32F2F",4:"F57C00",3:"FBC02D",2:"1976D2",1:"757575",0:"388E3C"}

def build_open_flaws_pivot(report_rows: List[Dict[str,Any]]) -> Dict[str,Dict[int,int]]:
    from collections import defaultdict
    agg=defaultdict(lambda:{s:0 for s in (5,4,3,2,1,0)})
    for r in report_rows or []:
        st=normalize_scan_type(r.get("scan_type") or r.get("analysis_type") or r.get("finding_type") or r.get("type") or r.get("category"))
        if not _is_open_status(r.get("status") or r.get("finding_status") or r.get("state")): continue
        sev=(r.get("custom_severity") or r.get("customSeverity") or r.get("custom_severity_level") or
             r.get("severity") or r.get("severity_level") or r.get("severity_num"))
        sev=_severity_to_int(sev)
        if sev is not None: agg[st][sev]+=1
    for st in ("STATIC","DYNAMIC","SCA","MANUAL_PEN_TEST"):
        agg[st]=agg.get(st,{s:0 for s in (5,4,3,2,1,0)})
    return agg

def write_open_flaws_summary(xw, reporting_rows: List[Dict[str,Any]]):
    import pandas as pd
    from openpyxl.chart import BarChart, Reference
    from openpyxl.chart.series import DataPoint
    from openpyxl.chart.label import DataLabelList
    try:
        from openpyxl.chart.shapes import GraphicalProperties
    except Exception:
        GraphicalProperties = None

    agg=build_open_flaws_pivot(reporting_rows)
    severities=[5,4,3,2,1,0]; cols=["STATIC","DYNAMIC","SCA","MANUAL_PEN_TEST"]

    # Pivot table
    data=[]
    for s in severities:
        row={"severity":s}; total=0
        for c in cols:
            cnt=agg[c][s]; row[c]=cnt; total+=cnt
        row["Total"]=total; data.append(row)
    pivot_df=pd.DataFrame(data, columns=["severity"]+cols+["Total"])

    sheet="OpenFlawsSummary"
    start_row=0; start_col=0
    pivot_df.to_excel(xw, sheet_name=sheet, startrow=start_row, startcol=start_col, index=False)
    ws=xw.book[sheet]
    header_row = start_row + 1
    first_data_row = header_row + 1
    last_row = first_data_row + len(severities) - 1

    # Charts per analysis, with value labels and per-data-point colors
    for idx, c in enumerate(cols, start=2):
        chart=BarChart()
        chart.title=f"{c} — OPEN flaws by severity (5→0)"
        chart.y_axis.title="Count"; chart.x_axis.title="Severity"
        data_ref = Reference(ws, min_col=start_col+idx, min_row=header_row, max_col=start_col+idx, max_row=last_row)
        cats_ref = Reference(ws, min_col=start_col+1,  min_row=first_data_row, max_row=last_row)
        chart.add_data(data_ref, titles_from_data=True)
        chart.set_categories(cats_ref)
        chart.dLbls = DataLabelList(); chart.dLbls.showVal = True
        try:
            ser = chart.series[0]
            ser.dPt = []
            for i, sev in enumerate(severities):
                dp = DataPoint(idx=i)
                if GraphicalProperties is not None:
                    gp = GraphicalProperties()
                    gp.solidFill = SEV_COLORS.get(sev, "999999")
                    dp.graphicalProperties = gp
                ser.dPt.append(dp)
        except Exception:
            pass
        anchor_row = start_row + 1 + (idx-2)*(len(severities)+8)
        ws.add_chart(chart, f"G{anchor_row}")

# ===== Writer
def write_workbook(app_rows, summary_rows, freq_rows, reporting_rows, out_path:str):
    import pandas as pd
    from pandas import json_normalize
    if out_path.lower().endswith(".xls"): out_path = out_path + "x"
    with pd.ExcelWriter(out_path, engine="openpyxl") as xw:
        apps = pd.DataFrame(app_rows or [])
        for k in CF_KEYS:
            if k not in apps.columns: apps[k]=None
        apps.to_excel(xw, sheet_name="Apps", index=False)

        pd.DataFrame(summary_rows or []).to_excel(xw, sheet_name="Summaries", index=False)

        freq = pd.DataFrame(freq_rows or [])
        for k in CF_KEYS:
            if k not in freq.columns: freq[k]=None
        freq = freq[[c for c in freq.columns if c not in CF_KEYS] + CF_KEYS]
        freq.to_excel(xw, sheet_name="FrequencyCompliance", index=False)

        try:
            json_normalize(reporting_rows or [], max_level=2).to_excel(xw, sheet_name="ReportingAPI", index=False)
        except Exception:
            pd.DataFrame(reporting_rows or []).to_excel(xw, sheet_name="ReportingAPI", index=False)

        write_open_flaws_summary(xw, reporting_rows or [])

# ===== Pretty UI
def _start_progress():
    global RICH, PROGRESS
    if not PRETTY or QUIET: return None
    try:
        from rich.console import Console
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
        RICH = Console()
        PROGRESS = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=True,
            console=RICH
        )
        PROGRESS.start()
        RICH.print("▫ [bold]Legend[/]: ✅ done   🌀 working   ❌ failed")
        return PROGRESS
    except Exception:
        PROGRESS=None; return None

def _stop_progress_print_done(msg: str):
    if PROGRESS:
        try:
            PROGRESS.stop()
            from rich.console import Console
            Console().print(f"✅ [bold]{msg}[/]")
        except Exception:
            print(f"✅ {msg}")
    else:
        print(f"✅ {msg}")

# ===== Main
def main():
    global QUIET, PRETTY, RICH, PROGRESS
    p=argparse.ArgumentParser(description="Veracode Local Runner (read-only)")
    sub=p.add_subparsers(dest="cmd", required=True)

    # All-in-one
    s_all=sub.add_parser("tenant-all-in-one", help="Apps, Summaries, FrequencyCompliance, ReportingAPI, OpenFlawsSummary")
    s_all.add_argument("--limit-apps", type=int, default=10000)
    s_all.add_argument("--page-size", type=int, default=200)
    s_all.add_argument("--sleep", type=float, default=0.0)
    s_all.add_argument("--as-of", default=None)
    s_all.add_argument("--out", default="tenant_all_in_one.xlsx")
    s_all.add_argument("--reporting-start", default="2018-01-01")
    s_all.add_argument("--reporting-end", default=None)
    s_all.add_argument("--reporting-page-size", type=int, default=600)
    s_all.add_argument("--reporting-poll-delay", type=float, default=float(os.environ.get("VERACODE_REPORTING_POLL_DELAY", "3.0")))
    s_all.add_argument("--reporting-poll-tries", type=int, default=int(os.environ.get("VERACODE_REPORTING_POLL_TRIES", "60")))
    s_all.add_argument("--quiet", action="store_true")
    s_all.add_argument("--pretty", action="store_true")

    # Per-app compliance
    s_comp=sub.add_parser("scan-compliance", help="Per-app frequency compliance only")
    s_comp.add_argument("--app", required=True)
    s_comp.add_argument("--out", default="app_compliance.xlsx")
    s_comp.add_argument("--quiet", action="store_true")
    s_comp.add_argument("--pretty", action="store_true")

    # Tenant-wide compliance
    s_tenant=sub.add_parser("tenant-scan-compliance", help="Tenant-wide frequency compliance only")
    s_tenant.add_argument("--limit-apps", type=int, default=10000)
    s_tenant.add_argument("--page-size", type=int, default=200)
    s_tenant.add_argument("--sleep", type=float, default=0.0)
    s_tenant.add_argument("--out", default="tenant_compliance.xlsx")
    s_tenant.add_argument("--quiet", action="store_true")
    s_tenant.add_argument("--pretty", action="store_true")

    args=p.parse_args()

    # ---------- tenant-all-in-one ----------
    if args.cmd=="tenant-all-in-one":
        QUIET=args.quiet; PRETTY=args.pretty and not QUIET
        asof=_parse_as_of(args.as_of)
        if PRETTY: _start_progress()
        try:
            # v1 listing with live pages/apps/apps-sec
            t_apps=None
            if PROGRESS:
                t_apps = PROGRESS.add_task(_fmt_listing_desc(0, None, 0, -1.0), total=100)
            collected=[0]; total_pages=[None]; pages_fetched=[0]; t0=time.time()
            def _apps_cb(current_total, tot_pages, page_no):
                pages_fetched[0] = page_no + 1
                collected[0] = current_total
                total_pages[0] = tot_pages
                elapsed = max(0.001, time.time() - t0)
                rate = current_total / elapsed
                if PROGRESS and t_apps:
                    if tot_pages is not None:
                        PROGRESS.update(
                            t_apps, total=tot_pages, completed=page_no + 1,
                            description=_fmt_listing_desc(page_no + 1, tot_pages, current_total, rate)
                        )
                    else:
                        soft_total = max(100, page_no + 10)
                        PROGRESS.update(
                            t_apps, total=soft_total, completed=page_no + 1,
                            description=_fmt_listing_desc(page_no + 1, None, current_total, rate)
                        )
            apps=list_apps(q=None, limit=args.limit_apps, page_size=args.page_size, progress_cb=_apps_cb)
            if PROGRESS and t_apps:
                elapsed = max(0.001, time.time() - t0)
                rate = collected[0] / elapsed
                if total_pages[0] is not None:
                    PROGRESS.update(t_apps, total=total_pages[0], completed=pages_fetched[0],
                                    description=f"✅ Applications listed — pages: {pages_fetched[0]}/{total_pages[0]}  apps: {collected[0]}  rate: {rate:.1f}/s")
                else:
                    PROGRESS.update(t_apps, total=pages_fetched[0] or 1, completed=pages_fetched[0] or 1,
                                    description=f"✅ Applications listed — pages: {pages_fetched[0]}/?  apps: {collected[0]}  rate: {rate:.1f}/s")

            # Apps rows (+ cf 1..25)
            app_rows=[]
            for a in apps:
                row=_app_row_from_listing(a)
                for k in CF_KEYS:
                    if k not in row: row[k]=None
                app_rows.append(row)

            # Reporting API
            t_rep=None
            if PROGRESS: t_rep=PROGRESS.add_task("🌀 Reporting API", total=None)
            reporting_rows=collect_reporting_findings_all_fields(
                report_type="findings",
                start_date=args.reporting_start,
                end_date=args.reporting_end or (asof.strftime("%Y-%m-%d") if args.as_of else None),
                page_size=args.reporting_page_size,
                poll_delay=args.reporting_poll_delay,
                poll_tries=args.reporting_poll_tries
            )
            if PROGRESS and t_rep: PROGRESS.update(t_rep, completed=1, description="✅ Reporting API")

            # Summaries (always derived); optionally enrich with endpoint scalars
            summaries=build_summaries_from_reporting(app_rows, reporting_rows)
            idx={r["app_guid"]: r for r in summaries}
            for ar in app_rows:
                ag=ar.get("guid"); s=get_summary_endpoint(ag)
                if s and ag in idx:
                    for k,v in s.items():
                        if not isinstance(v,(dict,list)):
                            key=f"summary_{k}"
                            if key not in idx[ag]: idx[ag][key]=v

            # FrequencyCompliance
            t_fc=None
            if PROGRESS: t_fc=PROGRESS.add_task("🌀 Computing compliance", total=len(app_rows))
            freq_rows=[]; app_index={r.get("guid"): r for r in app_rows}
            for a in apps:
                ag=a.get("guid") or a.get("id") or a.get("application_guid")
                an=(a.get("profile") or {}).get("name") or a.get("name") or ""
                if not ag:
                    if PROGRESS and t_fc: PROGRESS.advance(t_fc); continue
                last_seen_by_type={}
                for sc in (a.get("scans") or []):
                    st=normalize_scan_type(sc.get("scan_type"))
                    status=(sc.get("status") or sc.get("internal_status") or "").upper()
                    if "PUBLISH" in status or "RESULTSREADY" in status or status in ("PUBLISHED","RESULTSREADY","COMPLETE"):
                        ts=sc.get("modified_date") or sc.get("published_date") or sc.get("completed_date") or sc.get("last_updated")
                        if ts: last_seen_by_type[st]=_latest_iso(last_seen_by_type.get(st), ts)
                eval_obj=get_policy_evaluation(ag); reqs=parse_required_scans(eval_obj) if eval_obj else []
                if not reqs:
                    pol_guid=app_index.get(ag,{}).get("policy_guid")
                    if pol_guid: reqs=get_policy_requirements_from_policy_guid(pol_guid)
                cf_only={k: app_index.get(ag,{}).get(k) for k in CF_KEYS}
                freq_rows.extend(compute_frequency_rows(ag, an, reqs, last_seen_by_type, cf_only))
                if PROGRESS and t_fc: PROGRESS.advance(t_fc)
            if PROGRESS and t_fc: PROGRESS.update(t_fc, completed=len(app_rows), description="✅ Compliance")

            # Write workbook
            write_workbook(app_rows, summaries, freq_rows, reporting_rows, args.out)
            _stop_progress_print_done(f"Wrote {args.out} (Sheets: Apps, Summaries, FrequencyCompliance, ReportingAPI, OpenFlawsSummary)")
        except Exception:
            if PROGRESS: PROGRESS.stop()
            raise
        return

    # ---------- scan-compliance (per-app) ----------
    if args.cmd=="scan-compliance":
        QUIET=args.quiet; PRETTY=args.pretty and not QUIET
        if PRETTY: _start_progress()
        try:
            ag = args.app
            app = get_app_details(ag)
            an = app.get("name") or app.get("application_name") or (app.get("profile") or {}).get("name") or ag
            # cf
            cf = _extract_custom_fields_from_profile(app.get("profile") or {})
            for k in CF_KEYS:
                if k not in cf: cf[k]=None
            # last seen via v1 app scans
            try: listing = get_json(f"/appsec/v1/applications/{ag}")
            except Exception: listing = {}
            last_seen_by_type={}
            for sc in (listing.get("scans") or []):
                st=normalize_scan_type(sc.get("scan_type"))
                status=(sc.get("status") or sc.get("internal_status") or "").upper()
                if "PUBLISH" in status or "RESULTSREADY" in status or status in ("PUBLISHED","RESULTSREADY","COMPLETE"):
                    ts=sc.get("modified_date") or sc.get("published_date") or sc.get("completed_date") or sc.get("last_updated")
                    if ts: last_seen_by_type[st]=_latest_iso(last_seen_by_type.get(st), ts)
            # requirements
            eval_obj=get_policy_evaluation(ag); reqs=parse_required_scans(eval_obj) if eval_obj else []
            if not reqs:
                pols = ((listing.get("profile") or {}).get("policies") or [])
                pol_guid = pols[0].get("guid") if pols and isinstance(pols[0], dict) else None
                if pol_guid: reqs=get_policy_requirements_from_policy_guid(pol_guid)
            comp_rows = compute_frequency_rows(ag, an, reqs, last_seen_by_type, cf)
            # Write workbook
            import pandas as pd
            with pd.ExcelWriter(args.out, engine="openpyxl") as xw:
                pd.DataFrame([app]).to_excel(xw, sheet_name="App", index=False)
                pd.DataFrame(comp_rows).to_excel(xw, sheet_name="Compliance", index=False)
            _stop_progress_print_done(f"Wrote {args.out} (Sheets: App, Compliance)")
        except Exception:
            if PROGRESS: PROGRESS.stop()
            raise
        return

    # ---------- tenant-scan-compliance (tenant-wide) ----------
    if args.cmd=="tenant-scan-compliance":
        QUIET=args.quiet; PRETTY=args.pretty and not QUIET
        if PRETTY: _start_progress()
        try:
            # v1 listing with live pages/apps/apps-sec
            t_apps=None
            if PROGRESS:
                t_apps = PROGRESS.add_task(_fmt_listing_desc(0, None, 0, -1.0), total=100)
            collected=[0]; total_pages=[None]; pages_fetched=[0]; t0=time.time()
            def _apps_cb(current_total, tot_pages, page_no):
                pages_fetched[0] = page_no + 1
                collected[0] = current_total
                total_pages[0] = tot_pages
                elapsed = max(0.001, time.time() - t0)
                rate = current_total / elapsed
                if PROGRESS and t_apps:
                    if tot_pages is not None:
                        PROGRESS.update(
                            t_apps, total=tot_pages, completed=page_no + 1,
                            description=_fmt_listing_desc(page_no + 1, tot_pages, current_total, rate)
                        )
                    else:
                        soft_total = max(100, page_no + 10)
                        PROGRESS.update(
                            t_apps, total=soft_total, completed=page_no + 1,
                            description=_fmt_listing_desc(page_no + 1, None, current_total, rate)
                        )
            apps=list_apps(q=None, limit=args.limit_apps, page_size=args.page_size, progress_cb=_apps_cb)
            if PROGRESS and t_apps:
                elapsed = max(0.001, time.time() - t0)
                rate = collected[0] / elapsed
                if total_pages[0] is not None:
                    PROGRESS.update(t_apps, total=total_pages[0], completed=pages_fetched[0],
                                    description=f"✅ Applications listed — pages: {pages_fetched[0]}/{total_pages[0]}  apps: {collected[0]}  rate: {rate:.1f}/s")
                else:
                    PROGRESS.update(t_apps, total=pages_fetched[0] or 1, completed=pages_fetched[0] or 1,
                                    description=f"✅ Applications listed — pages: {pages_fetched[0]}/?  apps: {collected[0]}  rate: {rate:.1f}/s")

            # Build Apps + Compliance
            import pandas as pd
            app_rows=[]; comp_rows=[]
            for a in apps:
                ag=a.get("guid") or a.get("id") or a.get("application_guid")
                an=(a.get("profile") or {}).get("name") or a.get("name") or ""
                if not ag:
                    continue
                row=_app_row_from_listing(a)
                for k in CF_KEYS:
                    if k not in row: row[k]=None
                app_rows.append(row)

                # last seen
                last_seen_by_type={}
                for sc in (a.get("scans") or []):
                    st=normalize_scan_type(sc.get("scan_type"))
                    status=(sc.get("status") or sc.get("internal_status") or "").upper()
                    if "PUBLISH" in status or "RESULTSREADY" in status or status in ("PUBLISHED","RESULTSREADY","COMPLETE"):
                        ts=sc.get("modified_date") or sc.get("published_date") or sc.get("completed_date") or sc.get("last_updated")
                        if ts: last_seen_by_type[st]=_latest_iso(last_seen_by_type.get(st), ts)

                # requirements
                eval_obj=get_policy_evaluation(ag); reqs=parse_required_scans(eval_obj) if eval_obj else []
                if not reqs and row.get("policy_guid"):
                    reqs=get_policy_requirements_from_policy_guid(row["policy_guid"])

                cf_only = {k: row.get(k) for k in CF_KEYS}
                comp_rows.extend(compute_frequency_rows(ag, an, reqs, last_seen_by_type, cf_only))

                if PAGE_SLEEP: time.sleep(PAGE_SLEEP)
                if args.sleep: time.sleep(args.sleep)

            with pd.ExcelWriter(args.out, engine="openpyxl") as xw:
                pd.DataFrame(app_rows).to_excel(xw, sheet_name="Apps", index=False)
                pd.DataFrame(comp_rows).to_excel(xw, sheet_name="Compliance", index=False)

            _stop_progress_print_done(f"Wrote {args.out} (Sheets: Apps, Compliance)")
        except Exception:
            if PROGRESS: PROGRESS.stop()
            raise
        return

if __name__ == "__main__":
    main()
