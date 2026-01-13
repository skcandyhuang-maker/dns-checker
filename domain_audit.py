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
from datetime import datetime
from OpenSSL import crypto

# 設定頁面標題
st.set_page_config(page_title="域名檢測 (Multi-IP版)", layout="wide")

# --- 輔助：雙欄位判別邏輯 ---

def detect_providers(cname_record, isp_name):
    cname = cname_record.lower()
    isp = isp_name.lower()
    cdn_found = "-"
    cloud_found = "-"
    
    # 1. CDN 特徵庫
    cdn_sigs = {
        "Cloudflare": ["cloudflare", "cdn.cloudflare.net"],
        "AWS CloudFront": ["cloudfront.net"],
        "Akamai": ["akamai", "edgekey", "akamaiedge", "acadn"],
        "Azure CDN": ["azureedge", "msecnd"],
        "Fastly": ["fastly"],
        "Imperva": ["incapdns", "imperva"],
        "Edgio (EdgeCast)": ["edgecast", "systemcdn", "transactcdn"],
        "CDNetworks": ["cdnetworks", "panthercdn"],
        "Wangsu (網宿)": ["wswebpic", "wscdns", "chinanetcenter"],
        "Tencent CDN": ["cdntip"],
        "Alibaba CDN": ["kunlun", "alikunlun"],
        "Gcore": ["gcore"],
        "BunnyCDN": ["bunnycdn"],
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
        elif "imperva" in isp: cdn_found = "⚡ Imperva"
        elif "edgecast" in isp or "edgio" in isp: cdn_found = "⚡ Edgio"

    # 2. Cloud/Hosting 特徵庫
    if cdn_found == "-":
        cloud_sigs = {
            "AWS": ["amazon", "amazonaws"],
            "Google Cloud": ["google", "googleusercontent"],
            "Microsoft Azure": ["microsoft", "azure"],
            "Alibaba Cloud": ["alibaba", "aliyun"],
            "Tencent Cloud": ["tencent"],
            "DigitalOcean": ["digitalocean"],
            "Linode": ["linode"],
            "Oracle Cloud": ["oracle"],
            "Hetzner": ["hetzner"],
            "OVH": ["ovh"],
        }
        for provider, keywords in cloud_sigs.items():
            for kw in keywords:
                if kw in cname or kw in isp:
                    cloud_found = f"☁️ {provider}"
                    break
            if cloud_found != "-": break

    return cdn_found, cloud_found

# --- 核心：萬能智慧分詞 ---

def parse_input_raw(raw_text):
    processed_text = re.sub(r'(\.[a-z]{2,5})(www\.|http)', r'\1\n\2', raw_text, flags=re.IGNORECASE)
    processed_text = processed_text.replace('https://', '\nhttps://').replace('http://', '\nhttp://')
    processed_text = processed_text.replace('未找到', '\n未找到\n')

    tokens = re.split(r'[\s,;]+', processed_text)
    final_domains = []
    
    for token in tokens:
        token = token.strip()
        if not token: continue 
        clean = token.replace('https://', '').replace('http://', '')
        clean = clean.split('/')[0].split('?')[0].split(':')[0]
        clean = re.sub(r'^[^a-zA-Z0-9\u4e00-\u9fa5]+|[^a-zA-Z0-9\u4e00-\u9fa5]+$', '', clean)
        if clean: final_domains.append(clean)
    
    return final_domains

# --- 檢測函式 ---

def get_dns_geoip(domain):
    result = {"CNAME": "-", "IP": "-", "Country": "-", "City": "-", "ISP": "-"}
    try:
        cname_answers = dns.resolver.resolve(domain, 'CNAME')
        result["CNAME"] = str(cname_answers[0].target).rstrip('.')
    except: pass 

    ip_list = []
    try:
        a_answers = dns.resolver.resolve(domain, 'A')
        ip_list = [str(r.address) for r in a_answers]
    except:
        try:
            ais = socket.getaddrinfo(domain, 0, socket.AF_INET, socket.SOCK_STREAM)
            ip_list = list(set([ai[4][0] for ai in ais]))
        except: pass 

    if ip_list:
        result["IP"] = ", ".join(ip_list)
        first_ip = ip_list[0]
        
        if first_ip.endswith('.'):
             result["IP"] = f"{first_ip} (Incomplete)"
             return result

        for attempt in range(4):
            try:
                sleep_time = random.uniform(1.0, 2.0) + (attempt * 1.5)
                time.sleep(sleep_time)
                
                uas = [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
                ]
                headers = {'User-Agent': random.choice(uas)}
                
                resp = requests.get(
                    f"http://ip-api.com/json/{first_ip}?fields=country,city,isp,status", 
                    headers=headers, 
                    timeout=5
                )
                if resp.status_code == 429: continue
                if resp.status_code == 200:
                    geo_data = resp.json()
                    if geo_data.get("status") == "success":
                        result["Country"] = geo_data.get("country", "-")
                        result["City"] = geo_data.get("city", "-")
                        result["ISP"] = geo_data.get("isp", "-")
                        break
            except: time.sleep(1)
    else:
        result["IP"] = "No Record"
        
    return result

def get_ssl_info(domain):
    result = {"SSL_Issuer": "-", "SSL_Days_Left": "-", "TLS_1.3_Status": "❌", "Actual_Protocol": "-"}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = None
    try:
        sock = socket.create_connection((domain, 443), timeout=5)
        conn = context.wrap_socket(sock, server_hostname=domain)
        protocol_ver = conn.version()
        result["Actual_Protocol"] = protocol_ver
        result["TLS_1.3_Status"] = "✅ Yes" if protocol_ver == 'TLSv1.3' else "❌ No"
        cert_bin = conn.getpeercert(binary_form=True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
        issuer_components = x509.get_issuer().get_components()
        issuer_cn = [v.decode() for k, v in issuer_components if k == b'CN']
        issuer_o = [v.decode() for k, v in issuer_components if k == b'O']
        result["SSL_Issuer"] = issuer_cn[0] if issuer_cn else (issuer_o[0] if issuer_o else "Unknown")
        not_after = x509.get_notAfter().decode('ascii')
        exp_date = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
        days_left = (exp_date - datetime.now()).days
        result["SSL_Days_Left"] = days_left
    except Exception as e:
        result["Actual_Protocol"] = "Connect Fail"
    finally:
        if conn: conn.close()
    return result

def run_globalping(domain):
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

def process_single_domain(args):
    index, domain, config = args
    result_dict = {
        "Domain": domain, 
        "CDN Provider": "-", 
        "Cloud/Hosting": "-",
        "Multi-IP": "-",     # 新增欄位：Multi-IP
        "CNAME": "-", "IPs": "-", "Country": "-", "City": "-", "ISP": "-",
        "TLS 1.3": "-", "Protocol": "-", "Issuer": "-", "SSL Days": "-", "Global Ping": "-"
    }
    
    if "未找到" in domain:
        result_dict["IPs"] = "❌ Source Not Found"
        return (index, result_dict)

    if '.' not in domain or len(domain) < 3:
        result_dict["IPs"] = "❌ Format Error"
        return (index, result_dict)

    try:
        if config['dns']:
            dns_data = get_dns_geoip(domain)
            cdn, cloud = detect_providers(dns_data["CNAME"], dns_data["ISP"])
            
            # --- Multi-IP 判斷邏輯 ---
            ip_str = dns_data["IP"]
            multi_ip_status = "-"
            if "," in ip_str and "Record" not in ip_str and "Incomplete" not in ip_str:
                count = len(ip_str.split(','))
                multi_ip_status = f"✅ Yes ({count})"
            # -----------------------

            result_dict.update({
                "CDN Provider": cdn,
                "Cloud/Hosting": cloud,
                "Multi-IP": multi_ip_status, # 更新 Multi-IP
                "CNAME": dns_data["CNAME"],
                "IPs": dns_data["IP"],
                "Country": dns_data["Country"],
                "City": dns_data["City"],
                "ISP": dns_data["ISP"]
            })
        
        if config['ssl']:
            ssl_data = get_ssl_info(domain)
            result_dict.update({"TLS 1.3": ssl_data["TLS_1.3_Status"], "Protocol": ssl_data["Actual_Protocol"], "Issuer": ssl_data["SSL_Issuer"], "SSL Days": ssl_data["SSL_Days_Left"]})
        
        if config['ping']:
            gp_result = run_globalping(domain)
            result_dict["Global Ping"] = gp_result
            
        return (index, result_dict)
    except Exception as e:
        return (index, {
            "Domain": domain, "CDN Provider": "Error", "Cloud/Hosting": "Error", "Multi-IP": "-", "CNAME": "Error", "IPs": str(e),
            "Country": "-", "City": "-", "ISP": "-", "TLS 1.3": "-", "Protocol": "-", "Issuer": "-", "SSL Days": "-", "Global Ping": "-"
        })

# --- UI 介面 ---

st.title("🌐 域名檢測 (Multi-IP 版)")
st.caption("✅ CDN/雲端判別 ✅ Multi-IP 偵測 ✅ 自動修復黏連 ✅ 抗 API 封鎖")

with st.sidebar:
    st.header("⚙️ 掃描設定")
    check_dns = st.checkbox("DNS & GeoIP & Provider", value=True)
    check_ssl = st.checkbox("SSL & TLS 1.3", value=True)
    check_ping = st.checkbox("Global Ping", value=True)
    workers = st.slider("掃描速度 (建議維持在 2)", 1, 5, 2)

raw_input = st.text_area("請貼上資料", height=250)

if st.button("🚀 開始掃描", type="primary"):
    domain_list = parse_input_raw(raw_input)
    indexed_domains = list(enumerate(domain_list))
    current_config = {'dns': check_dns, 'ssl': check_ssl, 'ping': check_ping}
    
    if not domain_list:
        st.warning("輸入為空")
    else:
        st.success(f"已識別 {len(domain_list)} 筆資料")
        
        task_args = [(idx, dom, current_config) for idx, dom in indexed_domains]
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_domain = {executor.submit(process_single_domain, arg): arg for arg in task_args}
            
            completed_count = 0
            for future in concurrent.futures.as_completed(future_to_domain):
                data = future.result()
                if data: results.append(data)
                completed_count += 1
                progress_bar.progress(completed_count / len(domain_list))
                status_text.text(f"掃描中... ({completed_count}/{len(domain_list)})")

        st.success("掃描完成！")
        results.sort(key=lambda x: x[0])
        final_data = [x[1] for x in results]
        df = pd.DataFrame(final_data)
        
        def style_dataframe(row):
            styles = [''] * len(row)
            
            # CDN Provider (綠色粗體)
            if "⚡" in str(row['CDN Provider']):
                styles[1] = 'color: #009900; font-weight: bold;'
            
            # Cloud/Hosting (藍色)
            if "☁️" in str(row['Cloud/Hosting']):
                styles[2] = 'color: #0000FF;'

            # Multi-IP (綠色粗體) - Index 3
            if "Yes" in str(row['Multi-IP']):
                styles[3] = 'color: #009900; font-weight: bold;'

            # SSL Days (紅色/黃色背景)
            if isinstance(row['SSL Days'], int):
                ssl_idx = df.columns.get_loc("SSL Days")
                if row['SSL Days'] < 30: styles[ssl_idx] = 'background-color: #ffcccc'
                elif row['SSL Days'] < 90: styles[ssl_idx] = 'background-color: #ffffcc'

            if "No" in str(row['TLS 1.3']) and row['TLS 1.3'] != "-":
                 tls_idx = df.columns.get_loc("TLS 1.3")
                 styles[tls_idx] = 'color: red; font-weight: bold;'
                 
            if "Format Error" in str(row['IPs']) or "Not Found" in str(row['IPs']):
                return ['background-color: #eeeeee; color: #888888'] * len(row)
                
            return styles

        st.dataframe(
            df.style.apply(style_dataframe, axis=1), 
            use_container_width=True, 
            hide_index=True,
            column_config={
                "CDN Provider": st.column_config.TextColumn("CDN Provider", width="small"),
                "Cloud/Hosting": st.column_config.TextColumn("Cloud/Hosting", width="small"),
                "Multi-IP": st.column_config.TextColumn("Multi-IP", width="small"),
                "IPs": st.column_config.TextColumn("IP Addresses", width="medium"),
            }
        )
        csv = df.to_csv(index=False).encode('utf-8-sig')
        st.download_button("📥 下載報告 CSV", csv, "dns_audit_multiip.csv", "text/csv")
