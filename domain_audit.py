import streamlit as st
import pandas as pd
import dns.resolver
import requests
import ssl
import socket
import concurrent.futures
import time
import random
import re
import os
import sqlite3
from datetime import datetime
from OpenSSL import crypto
import urllib3

# 關閉 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 設定頁面標題
st.set_page_config(page_title="Andy的全能網管工具 (v13修正版)", layout="wide")

# ==========================================
#  資料庫 (SQLite) 核心模組
# ==========================================
DB_FILE = "audit_data.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS domain_audit (
            domain TEXT PRIMARY KEY,
            cdn_provider TEXT, cloud_hosting TEXT, multi_ip TEXT, cname TEXT, ips TEXT,
            country TEXT, city TEXT, isp TEXT, tls_1_3 TEXT, protocol TEXT, issuer TEXT,
            ssl_days TEXT, global_ping TEXT, simple_ping TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS ip_reverse (
            input_ip TEXT, domain TEXT, current_resolved_ip TEXT, ip_match TEXT, http_status TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (input_ip, domain)
        )
    ''')
    conn.commit()
    conn.close()

def get_existing_domains():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("SELECT domain FROM domain_audit")
        return set([r[0] for r in c.fetchall()])
    except: return set()
    finally: conn.close()

def save_domain_result(data):
    conn = sqlite3.connect(DB_FILE, timeout=30)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT OR REPLACE INTO domain_audit (
                domain, cdn_provider, cloud_hosting, multi_ip, cname, ips, 
                country, city, isp, tls_1_3, protocol, issuer, ssl_days, 
                global_ping, simple_ping
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['Domain'], data['CDN Provider'], data['Cloud/Hosting'], data['Multi-IP'],
            data['CNAME'], data['IPs'], data['Country'], data['City'], data['ISP'],
            data['TLS 1.3'], data['Protocol'], data['Issuer'], str(data['SSL Days']),
            data['Global Ping'], data['Simple Ping']
        ))
        conn.commit()
    except Exception as e: print(f"DB Error: {e}")
    finally: conn.close()

def get_all_domain_results():
    conn = sqlite3.connect(DB_FILE)
    try:
        df = pd.read_sql_query("SELECT * FROM domain_audit", conn)
        df = df.rename(columns={
            "domain": "Domain", "cdn_provider": "CDN Provider", "cloud_hosting": "Cloud/Hosting",
            "multi_ip": "Multi-IP", "cname": "CNAME", "ips": "IPs", "country": "Country", 
            "city": "City", "isp": "ISP", "tls_1_3": "TLS 1.3", "protocol": "Protocol", 
            "issuer": "Issuer", "ssl_days": "SSL Days", "global_ping": "Global Ping", 
            "simple_ping": "Simple Ping"
        })
        if "updated_at" in df.columns: df = df.drop(columns=["updated_at"])
        return df
    finally: conn.close()

def save_ip_result(data):
    conn = sqlite3.connect(DB_FILE, timeout=30)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT OR REPLACE INTO ip_reverse (
                input_ip, domain, current_resolved_ip, ip_match, http_status
            ) VALUES (?, ?, ?, ?, ?)
        ''', (data['Input_IP'], data['Domain'], data['Current_Resolved_IP'], data['IP_Match'], data['HTTP_Status']))
        conn.commit()
    except Exception as e: print(f"DB Error: {e}")
    finally: conn.close()

def get_all_ip_results():
    conn = sqlite3.connect(DB_FILE)
    try:
        df = pd.read_sql_query("SELECT * FROM ip_reverse", conn)
        df = df.rename(columns={
            "input_ip": "Input_IP", "domain": "Domain", 
            "current_resolved_ip": "Current_Resolved_IP", 
            "ip_match": "IP_Match", "http_status": "HTTP_Status"
        })
        if "updated_at" in df.columns: df = df.drop(columns=["updated_at"])
        return df
    finally: conn.close()

def clear_database():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        init_db()

init_db()

# ==========================================
#  共用輔助函式
# ==========================================

def get_dns_resolver():
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1'] 
    resolver.timeout = 5
    resolver.lifetime = 5
    return resolver

def parse_input_raw(raw_text):
    processed_text = re.sub(r'(\.[a-z]{2,5})(www\.|http)', r'\1\n\2', raw_text, flags=re.IGNORECASE)
    processed_text = processed_text.replace('https://', '\nhttps://').replace('http://', '\nhttp://')
    processed_text = processed_text.replace('未找到', '\n未找到\n')
    tokens = re.split(r'[\s,;]+', processed_text)
    final_items = []
    for token in tokens:
        token = token.strip()
        if not token: continue 
        clean = token.replace('https://', '').replace('http://', '')
        clean = clean.split('/')[0].split('?')[0].split(':')[0]
        clean = re.sub(r'^[^a-zA-Z0-9\u4e00-\u9fa5\.]+|[^a-zA-Z0-9\u4e00-\u9fa5]+$', '', clean)
        if clean: final_items.append(clean)
    return final_items

# ==========================================
#  核心檢測邏輯
# ==========================================

def detect_providers(cname_record, isp_name):
    cname = cname_record.lower()
    isp = isp_name.lower()
    cdn_found = "-"
    cloud_found = "-"
    
    cdn_sigs = {
        "Cloudflare": ["cloudflare", "cdn.cloudflare.net"],
        "AWS CloudFront": ["cloudfront.net"],
        "Akamai": ["akamai", "edgekey", "akamaiedge"],
        "Azure CDN": ["azureedge", "msecnd"],
        "Fastly": ["fastly"],
        "Imperva": ["incapdns", "imperva"],
        "Edgio": ["edgecast", "systemcdn"],
        "CDNetworks": ["cdnetworks", "panthercdn"],
        "Wangsu": ["wswebpic", "wscdns"],
        "Tencent CDN": ["cdntip"],
        "Alibaba CDN": ["kunlun", "alikunlun"],
    }
    for provider, keywords in cdn_sigs.items():
        for kw in keywords:
            if kw in cname:
                cdn_found = f"⚡ {provider}"
                break
        if cdn_found != "-": break
        
    if cdn_found == "-":
        if "cloudflare" in isp: cdn_found = "⚡ Cloudflare"
        elif "akamai" in isp: cdn_found = "⚡ Akamai"
        elif "fastly" in isp: cdn_found = "⚡ Fastly"

    if cdn_found == "-":
        cloud_sigs = {
            "AWS": ["amazon", "amazonaws"],
            "Google Cloud": ["google", "googleusercontent"],
            "Azure": ["microsoft", "azure"],
            "Alibaba": ["alibaba", "aliyun"],
        }
        for provider, keywords in cloud_sigs.items():
            for kw in keywords:
                if kw in cname or kw in isp:
                    cloud_found = f"☁️ {provider}"
                    break
            if cloud_found != "-": break
    return cdn_found, cloud_found

def run_globalping_api(domain):
    url = "https://api.globalping.io/v1/measurements"
    headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    payload = {"limit": 2, "locations": [], "target": domain, "type": "http", "measurementOptions": {"protocol": "HTTPS"}}
    for attempt in range(3):
        try:
            time.sleep(random.uniform(2.0, 4.0) + attempt)
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
            if resp.status_code == 202:
                ms_id = resp.json()['id']
                for _ in range(10):
                    time.sleep(1)
                    res_resp = requests.get(f"{url}/{ms_id}", headers=headers, timeout=5)
                    if res_resp.status_code == 200:
                        data = res_resp.json()
                        if data['status'] == 'finished':
                            results = data['results']
                            success_count = sum(1 for r in results if r['result']['status'] == 'finished' and str(r['result']['rawOutput']).startswith('HTTP'))
                            return f"{success_count}/{len(results)} OK"
                return "Timeout"
            elif resp.status_code == 429:
                time.sleep(5) 
                continue
            elif resp.status_code == 400: return "Invalid Domain"
            else:
                if attempt == 2: return f"Err {resp.status_code}"
        except: time.sleep(1)
    return "Too Busy"

def run_simple_ping(domain):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        resp = requests.get(f"https://{domain}", timeout=10, headers=headers, verify=False)
        return f"✅ {resp.status_code}"
    except:
        try:
            resp = requests.get(f"http://{domain}", timeout=10, headers=headers)
            return f"⚠️ {resp.status_code} (HTTP)"
        except: return "❌ Fail"

def process_domain_audit(args):
    index, domain, config = args
    result = {
        "Domain": domain, "CDN Provider": "-", "Cloud/Hosting": "-", "Multi-IP": "-",
        "CNAME": "-", "IPs": "-", "Country": "-", "City": "-", "ISP": "-",
        "TLS 1.3": "-", "Protocol": "-", "Issuer": "-", "SSL Days": "-", 
        "Global Ping": "-", "Simple Ping": "-"
    }
    if "未找到" in domain:
        result["IPs"] = "❌ Source Not Found"
        return (index, result)
    if '.' not in domain or len(domain) < 3:
        result["IPs"] = "❌ Format Error"
        return (index, result)

    try:
        if config['dns']:
            resolver = get_dns_resolver()
            try:
                cname_ans = resolver.resolve(domain, 'CNAME')
                result["CNAME"] = str(cname_ans[0].target).rstrip('.')
            except: pass
            ip_list = []
            try:
                a_ans = resolver.resolve(domain, 'A')
                ip_list = [str(r.address) for r in a_ans]
            except:
                try:
                    ais = socket.getaddrinfo(domain, 0, socket.AF_INET, socket.SOCK_STREAM)
                    ip_list = list(set([ai[4][0] for ai in ais]))
                except: pass
            if ip_list:
                result["IPs"] = ", ".join(ip_list)
                if len(ip_list) > 1: result["Multi-IP"] = f"✅ Yes ({len(ip_list)})"
                if config['geoip']:
                    first_ip = ip_list[0]
                    if not first_ip.endswith('.'):
                        for attempt in range(3):
                            try:
                                time.sleep(random.uniform(0.5, 1.5))
                                resp = requests.get(f"http://ip-api.com/json/{first_ip}?fields=country,city,isp,status", timeout=5).json()
                                if resp.get("status") == "success":
                                    result["Country"] = resp.get("country", "-")
                                    result["City"] = resp.get("city", "-")
                                    result["ISP"] = resp.get("isp", "-")
                                    break
                            except: time.sleep(1)
                cdn, cloud = detect_providers(result["CNAME"], result["ISP"])
                result["CDN Provider"] = cdn
                result["Cloud/Hosting"] = cloud
            else: result["IPs"] = "No Record"

        if config['ssl']:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = None
            try:
                sock = socket.create_connection((domain, 443), timeout=5)
                conn = ctx.wrap_socket(sock, server_hostname=domain)
                
                # --- 這裡修正了變數名稱 ---
                result["Protocol"] = conn.version() # 修正：原本誤寫為 Actual_Protocol
                result["TLS 1.3"] = "✅ Yes" if conn.version() == 'TLSv1.3' else "❌ No"
                # -----------------------
                
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, conn.getpeercert(binary_form=True))
                issuer_obj = cert.get_issuer()
                result["Issuer"] = issuer_obj.O if issuer_obj.O else (issuer_obj.CN if issuer_obj.CN else "Unknown")
                not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                result["SSL Days"] = (not_after - datetime.now()).days
            except: result["Protocol"] = "Connect Fail"
            finally:
                if conn: conn.close()

        if config['global_ping']: result["Global Ping"] = run_globalping_api(domain)
        if config['simple_ping']: result["Simple Ping"] = run_simple_ping(domain)

    except Exception as e: result["IPs"] = str(e)
    return (index, result)

def check_single_domain_status(domain, target_ip):
    resolver = get_dns_resolver()
    status_result = {"Domain": domain, "Current_Resolved_IP": "-", "IP_Match": "-", "HTTP_Status": "-"}
    current_ips = []
    try:
        a_ans = resolver.resolve(domain, 'A')
        current_ips = [str(r.address) for r in a_ans]
        status_result["Current_Resolved_IP"] = ", ".join(current_ips)
    except: status_result["Current_Resolved_IP"] = "No DNS Record"
    
    if current_ips:
        if target_ip in current_ips: status_result["IP_Match"] = "✅ Yes"
        else: status_result["IP_Match"] = "❌ No"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        try:
            resp = requests.get(f"https://{domain}", timeout=10, headers=headers, verify=False)
            status_result["HTTP_Status"] = f"✅ {resp.status_code}"
        except:
            try:
                resp = requests.get(f"http://{domain}", timeout=10, headers=headers)
                status_result["HTTP_Status"] = f"⚠️ {resp.status_code} (HTTP)"
            except: status_result["HTTP_Status"] = "❌ Unreachable"
    else: status_result["HTTP_Status"] = "❌ DNS Fail"
    return status_result

def process_ip_vt_lookup(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
    headers = {"x-apikey": api_key}
    try:
        params = {"limit": 40}
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data:
                domains = list(set([item['attributes']['host_name'] for item in data['data']]))
                return "Success", domains
            return "Success", []
        elif resp.status_code == 429: return "RateLimit", []
        elif resp.status_code == 401: return "AuthError", []
        else: return f"Error {resp.status_code}", []
    except Exception as e: return f"Exception: {str(e)}", []


# ==========================================
#  UI 主程式
# ==========================================

with st.sidebar:
    st.header("🗄️ 資料庫管理")
    st.caption("所有資料均存於本地 SQLite，關閉程式不會遺失。")
    if st.button("🗑️ 清空資料庫 (重來)", type="secondary"):
        clear_database()
        st.toast("資料庫已清空！")
        time.sleep(1)
        st.rerun()
    st.divider()
    st.subheader("📥 匯出資料")
    df_domains = get_all_domain_results()
    if not df_domains.empty:
        st.download_button(f"📄 下載域名報告 ({len(df_domains)}筆)", df_domains.to_csv(index=False).encode('utf-8-sig'), "domain_audit_db.csv", "text/csv")
    else: st.write("域名資料庫為空")
    df_ips = get_all_ip_results()
    if not df_ips.empty:
        st.download_button(f"📄 下載 IP 反查報告 ({len(df_ips)}筆)", df_ips.to_csv(index=False).encode('utf-8-sig'), "ip_reverse_db.csv", "text/csv")
    else: st.write("IP 反查資料庫為空")

tab1, tab2 = st.tabs(["🔍 域名檢測", "🕵️ IP 反查域名 (VT)"])

# --- 分頁 1: 域名檢測 ---
with tab1:
    st.header("批量域名體檢 (DB 自動存檔)")
    col1, col2 = st.columns([1, 3])
    with col1:
        st.subheader("1. 檢測項目")
        check_dns = st.checkbox("DNS 解析 (基礎)", value=True, help="解析 A 紀錄與 CNAME，速度快")
        check_geoip = st.checkbox("GeoIP 查詢 (國家/ISP)", value=True, help="查詢 IP 的地理位置，需呼叫外部 API，速度較慢")
        check_ssl = st.checkbox("SSL & TLS 憑證", value=True, help="顯示憑證組織 (O)、過期日與 TLS 1.3 支援")
        
        st.subheader("2. 連線測試")
        check_simple_ping = st.checkbox("Simple Ping (本機)", value=True, help="從目前主機發送請求，適合內網或本機測試")
        check_global_ping = st.checkbox("Global Ping (全球)", value=True, help="透過 API 從國外節點測試，速度較慢")
        
        st.divider()
        st.subheader("3. 掃描速度")
        workers = st.slider("併發執行緒", 1, 5, 3)
        
        st.info("💡 速度設定建議：")
        st.markdown("""
        * **1-2 (龜速)**：適合 **1000+** 筆資料。保證 GeoIP 不會被封鎖。
        * **3 (平衡)**：適合 **100-500** 筆資料。
        * **4-5 (極速)**：適合 **<100** 筆資料。
        """)

    with col2:
        raw_input = st.text_area("輸入域名 (會自動跳過已掃描項目)", height=150, placeholder="example.com\nwww.google.com")
        if st.button("🚀 開始掃描域名", type="primary"):
            full_list = parse_input_raw(raw_input)
            existing_domains = get_existing_domains()
            domain_list = [d for d in full_list if d not in existing_domains]
            skipped_count = len(full_list) - len(domain_list)
            
            if not domain_list:
                if skipped_count > 0: st.success(f"🎉 所有 {skipped_count} 筆域名都已經在資料庫中了！請直接從側邊欄下載。")
                else: st.warning("請輸入域名")
            else:
                if skipped_count > 0: st.info(f"⏩ 已自動跳過 {skipped_count} 筆重複資料，本次將掃描 {len(domain_list)} 筆。")
                config = {'dns': check_dns, 'geoip': check_geoip, 'ssl': check_ssl, 'global_ping': check_global_ping, 'simple_ping': check_simple_ping}
                indexed_domains = list(enumerate(domain_list))
                progress_bar = st.progress(0)
                status_text = st.empty()
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = {executor.submit(process_domain_audit, (idx, dom, config)): idx for idx, dom in indexed_domains}
                    completed = 0
                    for future in concurrent.futures.as_completed(futures):
                        data = future.result()
                        save_domain_result(data[1])
                        completed += 1
                        progress_bar.progress(completed / len(domain_list))
                        status_text.text(f"已處理: {completed}/{len(domain_list)} (已存入 DB)")
                status_text.success("掃描完成！所有資料已寫入資料庫，請從側邊欄下載。")
                st.balloons()
                time.sleep(1)
                st.rerun()

# --- 分頁 2: IP 反查 ---
with tab2:
    st.header("IP 反查與存活驗證 (DB 自動存檔)")
    api_key = st.text_input("請輸入 VirusTotal API Key", type="password")
    ip_input = st.text_area("輸入 IP 清單", height=150, placeholder="8.8.8.8")
    if st.button("🕵️ 開始反查 IP", type="primary"):
        if not api_key: st.error("請輸入 API Key！")
        else:
            ip_list = parse_input_raw(ip_input)
            if not ip_list: st.warning("請輸入 IP")
            else:
                st.toast(f"準備查詢 {len(ip_list)} 個 IP...")
                vt_counter = 0
                status_log = st.empty()
                for i, ip in enumerate(ip_list):
                    status_log.markdown(f"**[{i+1}/{len(ip_list)}] 正在查詢 VT:** `{ip}` ...")
                    status, domains = process_ip_vt_lookup(ip, api_key)
                    rows_to_save = []
                    if status == "Success":
                        if not domains: rows_to_save.append({"Input_IP": ip, "Domain": "(no data)", "Current_Resolved_IP": "-", "IP_Match": "-", "HTTP_Status": "-"})
                        else:
                            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                                verify_futures = {executor.submit(check_single_domain_status, dom, ip): dom for dom in domains}
                                for future in concurrent.futures.as_completed(verify_futures):
                                    v_res = future.result()
                                    rows_to_save.append({
                                        "Input_IP": ip, "Domain": v_res["Domain"],
                                        "Current_Resolved_IP": v_res["Current_Resolved_IP"], "IP_Match": v_res["IP_Match"], "HTTP_Status": v_res["HTTP_Status"]
                                    })
                    else: rows_to_save.append({"Input_IP": ip, "Domain": f"Error: {status}", "Current_Resolved_IP": "-", "IP_Match": "-", "HTTP_Status": "-"})
                    
                    for row in rows_to_save: save_ip_result(row)
                    vt_counter += 1
                    if i < len(ip_list) - 1:
                        if vt_counter % 4 == 0:
                            for sec in range(60, 0, -1):
                                status_log.warning(f"⏳ Rate Limit 冷卻中... 剩餘 {sec} 秒")
                                time.sleep(1)
                        else: time.sleep(15)
                status_log.success("查詢完成！資料已存入 DB。")
                st.balloons()
                time.sleep(1)
                st.rerun()
