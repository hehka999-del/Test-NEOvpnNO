#!/usr/bin/env python3
"""
Neo VPN builder for Happ.

Pipeline:
  sources -> decode subscriptions -> deduplicate -> parse endpoints
  -> TCP/TLS transport probe -> optional GeoIP -> country quotas
  -> latency ranking -> Happ-friendly names/output.

Important:
- TCP/TLS probing proves network reachability, not that a VPN credential works end-to-end.
- For true protocol authentication, install an Xray/sing-box core and add it to the
  optional external checker; this script deliberately uses Python standard library only.
"""
import argparse
import base64
import concurrent.futures
import json
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit, quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "config" / "sources.json"
OUT = ROOT / "output"
ALLOWED = (
    "vless://", "vmess://", "trojan://", "ss://",
    "hysteria2://", "hy2://", "socks://"
)

COUNTRY_ORDER = [
    "🇯🇵 JAPAN", "🇺🇸 UNITED STATES", "🇩🇪 GERMANY", "🇳🇱 NETHERLANDS",
    "🇬🇧 UNITED KINGDOM", "🇫🇷 FRANCE", "🇸🇬 SINGAPORE", "🇨🇦 CANADA",
    "🇰🇷 SOUTH KOREA", "🇭🇰 HONG KONG", "🇨🇭 SWITZERLAND", "🇸🇪 SWEDEN",
    "🇵🇱 POLAND", "🇮🇹 ITALY", "🇪🇸 SPAIN", "🇫🇮 FINLAND", "🇦🇹 AUSTRIA",
    "🇦🇺 AUSTRALIA", "🇹🇷 TÜRKİYE", "🇷🇺 RUSSIA", "🌍 GLOBAL"
]

def fetch(url, timeout=25):
    req = Request(url, headers={"User-Agent": "Neo-VPN-Builder/2.0"})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

def strip_name(uri):
    return uri.split("#", 1)[0].strip()

def b64decode_text(s):
    s = re.sub(r"\s+", "", s)
    s += "=" * (-len(s) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(s).decode("utf-8", "replace")
        except Exception:
            pass
    return ""

def expand_source_text(text):
    """Accept plain URI lists and common base64 subscription payloads."""
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    if any(x.startswith(ALLOWED) for x in lines):
        return lines

    # Some subscription files are one large base64 blob.
    decoded = b64decode_text("".join(lines))
    if decoded and any(x.startswith(ALLOWED) for x in decoded.splitlines()):
        return [x.strip() for x in decoded.splitlines() if x.strip()]

    # A source may contain base64 on multiple lines.
    out = []
    for line in lines:
        d = b64decode_text(line)
        if d:
            out.extend(x.strip() for x in d.splitlines() if x.strip())
    return out or lines

def parse_vmess(uri):
    try:
        raw = uri.split("://", 1)[1].split("#", 1)[0]
        obj = json.loads(b64decode_text(raw))
        host = obj.get("add") or obj.get("host")
        port = int(obj.get("port"))
        tls = str(obj.get("tls", "")).lower() in ("tls", "true", "1")
        sni = obj.get("sni") or obj.get("host") or host
        return host, port, tls, sni
    except Exception:
        return None

def parse_endpoint(uri):
    try:
        if uri.startswith("vmess://"):
            return parse_vmess(uri)
        u = urlsplit(uri)
        host = u.hostname
        port = u.port
        if not host or not port:
            return None
        q = parse_qs(u.query)
        security = (q.get("security") or [""])[0].lower()
        tls = security in ("tls", "reality", "xtls") or (q.get("tls") or [""])[0].lower() in ("tls", "1", "true")
        sni = (q.get("sni") or q.get("peer") or q.get("host") or [host])[0]
        return host, port, tls, sni
    except Exception:
        return None

def probe(item, timeout):
    endpoint = parse_endpoint(item["uri"])
    if not endpoint:
        return None
    host, port, tls, sni = endpoint
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if tls:
                ctx = ssl.create_default_context()
                # Certificate validation is intentionally disabled for public nodes:
                # a valid TCP/TLS handshake is the useful transport signal here.
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=sni or host):
                    pass
        return round((time.perf_counter() - t0) * 1000, 1)
    except Exception:
        return None

def unique_pairs(pairs):
    seen = set()
    out = []
    for uri, source_country in pairs:
        if not uri.startswith(ALLOWED):
            continue
        key = strip_name(uri)
        if key in seen:
            continue
        seen.add(key)
        out.append((uri, source_country))
    return out

def get_host(uri):
    ep = parse_endpoint(uri)
    return ep[0] if ep else None

def geoip_lookup(hosts, timeout=8):
    """Optional best-effort GeoIP. Uses ip-api batch endpoint; failures are ignored."""
    import json as _json
    import urllib.request as _ur

    ips = []
    for h in hosts:
        try:
            socket.inet_aton(h)
            ips.append(h)
        except Exception:
            pass
    ips = list(dict.fromkeys(ips))
    result = {}
    for start in range(0, len(ips), 100):
        batch = ips[start:start + 100]
        payload = _json.dumps([{"query": ip, "fields": "query,countryCode"} for ip in batch]).encode()
        try:
            req = _ur.Request(
                "http://ip-api.com/batch?fields=query,countryCode",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "Neo-VPN-Builder/2.0"},
                method="POST",
            )
            with _ur.urlopen(req, timeout=timeout) as r:
                rows = _json.loads(r.read().decode("utf-8", "replace"))
            for row in rows:
                if row.get("query") and row.get("countryCode"):
                    result[row["query"]] = row["countryCode"].upper()
        except Exception:
            continue
    return result

def code_to_country(code):
    mapping = {
        "JP":"🇯🇵 JAPAN","US":"🇺🇸 UNITED STATES","DE":"🇩🇪 GERMANY","NL":"🇳🇱 NETHERLANDS",
        "GB":"🇬🇧 UNITED KINGDOM","FR":"🇫🇷 FRANCE","SG":"🇸🇬 SINGAPORE","CA":"🇨🇦 CANADA",
        "KR":"🇰🇷 SOUTH KOREA","HK":"🇭🇰 HONG KONG","CH":"🇨🇭 SWITZERLAND","SE":"🇸🇪 SWEDEN",
        "PL":"🇵🇱 POLAND","IT":"🇮🇹 ITALY","ES":"🇪🇸 SPAIN","FI":"🇫🇮 FINLAND",
        "AT":"🇦🇹 AUSTRIA","AU":"🇦🇺 AUSTRALIA","TR":"🇹🇷 TÜRKİYE","RU":"🇷🇺 RUSSIA"
    }
    return mapping.get(code, "🌍 GLOBAL")

def rename(uri, country, number):
    label = f"Neo VPN | {country} #{number}"
    return strip_name(uri) + "#" + quote(label, safe="|")

def write_outputs(final, stats):
    header = """#profile-title: Neo VPN
#announce: Neo VPN — public configurations; availability is not guaranteed.
#subscription-pin: true
#subscription-autoconnect: 1
#subscription-autoconnect-type: lowestdelay
#subscription-ping-onopen-enabled: 1
#subscriptions-sort-type: ping
#subscription-auto-update-enable: 1
#profile-update-interval: 6
"""
    OUT.mkdir(exist_ok=True)
    tmp = OUT / "neo_vpn.txt.tmp"
    tmp.write_text(header + "\n".join(final) + "\n", encoding="utf-8")
    tmp.replace(OUT / "neo_vpn.txt")

    byproto = {k: [] for k in ["vless", "vmess", "trojan", "ss", "hy2", "socks"]}
    for line in final:
        p = line.split("://", 1)[0]
        if p == "hysteria2":
            p = "hy2"
        byproto.setdefault(p, []).append(line)

    for p, arr in byproto.items():
        (OUT / f"{p}.txt").write_text(header + "\n".join(arr) + "\n", encoding="utf-8")

    (OUT / "stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8"
    )

def run(target, do_check, geoip=False, workers=128):
    cfg = json.loads(CFG.read_text(encoding="utf-8"))
    target = int(target or cfg["target"])
    multiplier = max(2, int(cfg.get("candidate_multiplier", 8)))
    candidate_target = max(target * multiplier, int(cfg.get("minimum_candidates", target * 4)))

    pool = []
    for country, urls in cfg["country_sources"].items():
        if isinstance(urls, str):
            urls = [urls]
        for url in urls:
            try:
                text = fetch(url)
                for line in expand_source_text(text):
                    if line.startswith(ALLOWED):
                        pool.append((line, country))
            except Exception as e:
                print(f"[WARN] source failed: {url} -> {e}", file=sys.stderr)

    if len(pool) < candidate_target:
        for url in cfg.get("fallback_sources", []):
            try:
                text = fetch(url)
                for line in expand_source_text(text):
                    if line.startswith(ALLOWED):
                        pool.append((line, "🌍 GLOBAL"))
                        if len(pool) >= candidate_target:
                            break
            except Exception as e:
                print(f"[WARN] fallback failed: {url} -> {e}", file=sys.stderr)

    pairs = unique_pairs(pool)[:candidate_target]
    items = [{"uri": u, "country": c} for u, c in pairs]

    if do_check:
        print(f"[INFO] probing {len(items)} candidates...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(probe, it, cfg.get("probe_timeout", 3.5)): it for it in items}
            checked = []
            for fut in concurrent.futures.as_completed(futures):
                it = futures[fut]
                try:
                    ms = fut.result()
                except Exception:
                    ms = None
                if ms is not None:
                    it["ms"] = ms
                    checked.append(it)
        items = checked
    else:
        for it in items:
            it["ms"] = 999999.0

    if geoip:
        hosts = [get_host(x["uri"]) for x in items]
        geo = geoip_lookup([h for h in hosts if h])
        for it in items:
            host = get_host(it["uri"])
            if host in geo:
                it["country"] = code_to_country(geo[host])

    # Rank inside each country first, then take up to the configured quota.
    quotas = cfg.get("country_quotas", {})
    buckets = {}
    for it in items:
        buckets.setdefault(it["country"], []).append(it)
    for arr in buckets.values():
        arr.sort(key=lambda x: x["ms"])

    final_items = []
    used = set()
    # Explicit country quotas preserve a useful geographic spread.
    for country in COUNTRY_ORDER:
        quota = int(quotas.get(country, 0))
        if quota <= 0:
            continue
        for it in buckets.get(country, [])[:quota]:
            final_items.append(it)
            used.add(strip_name(it["uri"]))

    # Fill any remaining slots globally by lowest latency.
    leftovers = [it for it in items if strip_name(it["uri"]) not in used]
    leftovers.sort(key=lambda x: x["ms"])
    for it in leftovers:
        if len(final_items) >= target:
            break
        final_items.append(it)

    final_items = final_items[:target]

    counters = {}
    final = []
    for it in final_items:
        c = it["country"]
        counters[c] = counters.get(c, 0) + 1
        final.append(rename(it["uri"], c, counters[c]))

    stats = {
        "generated": len(final),
        "target": target,
        "candidates": len(pairs),
        "checked": bool(do_check),
        "geoip": bool(geoip),
        "countries": {},
        "protocols": {},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    for it in final_items:
        stats["countries"][it["country"]] = stats["countries"].get(it["country"], 0) + 1
        proto = it["uri"].split("://", 1)[0]
        if proto == "hysteria2":
            proto = "hy2"
        stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1

    if do_check and len(final) < int(cfg.get("minimum_output", min(1000, target))):
        raise RuntimeError(
            f"Only {len(final)} working transport endpoints found; "
            f"minimum_output={cfg.get('minimum_output')}. "
            "Add/refresh sources instead of publishing a mostly dead list."
        )

    write_outputs(final, stats)
    print(f"[OK] wrote {len(final)} configs to {OUT}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=None)
    ap.add_argument("--check", action="store_true", help="TCP/TLS transport check and latency sort")
    ap.add_argument("--geoip", action="store_true", help="best-effort GeoIP for literal IP endpoints")
    ap.add_argument("--workers", type=int, default=128)
    args = ap.parse_args()
    cfg = json.loads(CFG.read_text(encoding="utf-8"))
    run(args.target or cfg["target"], args.check, args.geoip, args.workers)
