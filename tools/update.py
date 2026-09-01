#!/usr/bin/env python3
import argparse, concurrent.futures, json, re, socket, sys, time
from pathlib import Path
from urllib.parse import urlsplit, unquote, quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / 'config' / 'sources.json'
OUT = ROOT / 'output'
ALLOWED = ('vless://','vmess://','trojan://','ss://','hysteria2://','hy2://','socks://')

def fetch(url, timeout=20):
    req = Request(url, headers={'User-Agent':'Neo-VPN-Builder/1.0'})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', 'replace')

def strip_name(uri):
    return uri.split('#',1)[0]

def parse_host_port(uri):
    try:
        u = urlsplit(uri)
        host = u.hostname
        port = u.port
        if host and port:
            return host, port
    except Exception:
        pass
    # vmess:// is base64/json and not trivially handled without decoding here
    return None

def tcp_probe(item):
    host_port = parse_host_port(item['uri'])
    if not host_port:
        return None
    host, port = host_port
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=3.5):
            ms = round((time.perf_counter()-t0)*1000, 1)
            return ms
    except Exception:
        return None

def rename(uri, country, number):
    label = f'Neo VPN | {country} #{number}'
    return strip_name(uri) + '#' + quote(label, safe='|')

def unique(lines):
    seen=set(); out=[]
    for x in lines:
        x=x.strip()
        if not x or x.startswith('#') or not x.startswith(ALLOWED):
            continue
        base=strip_name(x)
        if base in seen: continue
        seen.add(base); out.append(x)
    return out

def run(target, do_check):
    cfg=json.loads(CFG.read_text(encoding='utf-8'))
    pool=[]
    for country,url in cfg['country_sources'].items():
        try:
            text=fetch(url)
            for line in unique(text.splitlines()):
                pool.append((line,country))
        except Exception as e:
            print(f'[WARN] source failed: {url} -> {e}', file=sys.stderr)
    # fallback only if country sources did not supply enough
    if len(pool) < target:
        for url in cfg['fallback_sources']:
            try:
                text=fetch(url)
                for line in unique(text.splitlines()):
                    pool.append((line,'🌍 GLOBAL'))
                    if len(pool) >= target*2: break
            except Exception as e:
                print(f'[WARN] fallback failed: {url} -> {e}', file=sys.stderr)
    # dedup by actual URI payload while retaining first country label
    seen=set(); items=[]
    for uri,country in pool:
        base=strip_name(uri)
        if base in seen: continue
        seen.add(base); items.append({'uri':uri,'country':country})
        if len(items)>=target*2: break
    if do_check:
        print(f'[INFO] TCP checking {len(items)} candidates...')
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
            futs={ex.submit(tcp_probe,it):it for it in items}
            checked=[]
            for fut in concurrent.futures.as_completed(futs):
                it=futs[fut]
                try: ms=fut.result()
                except Exception: ms=None
                if ms is not None:
                    it['ms']=ms; checked.append(it)
        checked.sort(key=lambda x:x['ms'])
        items=checked[:target]
    else:
        items=items[:target]
    # assign country-local numbering from 1 upward
    counters={}; final=[]
    for it in items:
        c=it['country']; counters[c]=counters.get(c,0)+1
        final.append(rename(it['uri'], c, counters[c]))
    header='''#profile-title: Neo VPN\n#announce: Neo VPN — public configurations. Availability is not guaranteed; use end-to-end encryption.\n#subscription-pin: true\n#subscription-autoconnect: 1\n#subscription-autoconnect-type: lowestdelay\n#subscription-ping-onopen-enabled: 1\n#subscriptions-sort-type: ping\n#subscription-auto-update-enable: 1\n#profile-update-interval: 6\n'''
    OUT.mkdir(exist_ok=True)
    (OUT/'neo_vpn.txt').write_text(header+'\n'.join(final)+'\n',encoding='utf-8')
    byproto={k:[] for k in ['vless','vmess','trojan','ss','hy2','socks']}
    for line in final:
        p=line.split('://',1)[0]
        if p=='hysteria2': p='hy2'
        byproto.setdefault(p,[]).append(line)
    for p,arr in byproto.items():
        (OUT/f'{p}.txt').write_text(header+'\n'.join(arr)+'\n',encoding='utf-8')
    stats={"generated":len(final),"checked":do_check,"countries":{},"timestamp":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    for it in items: stats['countries'][it['country']]=stats['countries'].get(it['country'],0)+1
    (OUT/'stats.json').write_text(json.dumps(stats,ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'[OK] wrote {len(final)} configs to {OUT}')

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--target',type=int,default=None)
    ap.add_argument('--check',action='store_true',help='TCP-check endpoints and sort by latency')
    a=ap.parse_args(); cfg=json.loads(CFG.read_text()); run(a.target or cfg['target'],a.check)
