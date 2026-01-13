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
st.set_page_config(page_title="域名檢測 (不去重/不遺漏版)", layout="wide")

# --- 核心：智慧提取 (不去重、不遺漏) ---

def parse_input_raw(raw_text):
    """
    智慧分詞，但保留重複項與無效格式。
    """
    # 1. 處理黏在一起的網址 (強制切分)
    processed_text = raw_text.replace('https://', '\nhttps://').replace('http://', '\nhttp://')
    
    # 2. 使用分隔符號切分 (換行, 空白, 逗號, 分號)
    tokens = re.split(r'[\s,;]+', processed_text)
    
    final_domains = []
    
    for token in tokens:
        token = token.strip()
        if not token: continue # 只有完全空白的才跳過
        
        # 3. 清洗協定頭與路徑 (盡量救回域名)
        clean = token.replace('https://', '').replace('http://', '')
        clean = clean.split('/')[0].split('?')[0].split(':')[0]
        
        # 4. 移除前後雜訊
        clean = re.sub(r'^[^a-zA-Z0-9]+|[^a-zA-Z0-9]+$', '', clean)
        
        if clean:
            # 關鍵修改：不做去重 (set)，也不做嚴格過濾 (if '.' in clean)
            # 直接加入列表，留給後續檢測去判斷
            final_domains.append(clean)
    
    return final_domains

# --- 檢測函式 ---

def get_dns_geoip(domain):
    """取得 DNS 與 GeoIP"""
    result = {
        "CNAME": "None", "IP": "None", 
        "Country": "-", "City": "-", "ISP": "-"
    }
    
    try:
        cname_answers = dns.resolver.resolve(domain, 'CNAME')
        result["CNAME"] = str(cname_answers[0].target).rstrip('.')
    except:
        pass 

    ip_list = []
    try:
        a_answers = dns.resolver.resolve(domain, 'A')
        ip_list = [str(r.address) for r in a_answers]
    except:
        try:
            ais = socket.getaddrinfo(domain, 0, socket.AF_INET, socket.SOCK_STREAM)
            ip_list = list(set([ai[4][0] for ai in ais]))
        except:
            pass 

    if ip_list:
        result["IP"] = ", ".join(ip_list)
        try:
            first_ip = ip_list[0]
            time.sleep(random.uniform(0.1, 0.3))
            headers = {'User-Agent': 'Mozilla/5.0'}
            geo_resp = requests.get(
                f"http://ip-api.com/json/{first_ip}?fields=country,city,isp,status", 
                headers=headers, timeout=5
            ).json()
            
            if geo_resp.get("status") == "success":
                result["Country"] = geo_resp.get("country", "-")
                result["City"] = geo_resp.get("city", "-")
                result["ISP"] = geo_resp.get("isp", "-")
        except:
            pass
    else:
        result["IP"] = "No Record"
    
    return result

def get_ssl_info(domain):
    """取得 SSL/TLS 資訊"""
    result = {
        "SSL_Issuer": "-", "SSL_Days_Left": "-", 
        "TLS_1.3_Status": "❌", "Actual_Protocol": "-"
    }
    
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
    """Globalping API"""
    url = "https://api.globalping.io/v1/measurements"
    
    uas = [
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    ]
    
    headers = {
        'User-Agent': random.choice(uas),
        'Content-Type': 'application/json'
    }
    
    payload = {
        "limit": 2, 
        "locations": [], 
        "target": domain,
        "type": "http",
        "measurementOptions": {"protocol": "HTTPS"}
    }
    
    for attempt in range(3):
        try:
            time.sleep(random.uniform(2.0, 4.0))
            
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
                wait_time = 5 * (attempt + 1)
                time.sleep(wait_time) 
                continue
            elif resp.status_code == 400:
                return "Invalid Domain"
            else:
                if attempt == 2: return f"Err {resp.status_code}"
        except Exception as e:
            time.sleep(1)
            
    return "Too Busy"

def process_single_domain(args):
    index, domain, config = args
    
    # 初始化結果字典
    result_dict = {
        "Domain": domain,
        "CNAME": "-", "IPs": "-", "Country": "-", "City": "-", "ISP": "-",
        "TLS 1.3": "-", "Protocol": "-", "Issuer": "-", "SSL Days": "-",
        "Global Ping": "-"
    }

    # 1. 檢查域名格式 (若無效，直接標記但不跳過)
    # 簡單判斷：是否有點，長度是否合理
    if '.' not in domain or len(domain) < 3:
        result_dict["IPs"] = "❌ Format Error"
        # 即使格式錯誤，也回傳這行，讓報表顯示
        return (index, result_dict)

    try:
        if config['dns']:
            dns_data = get_dns_geoip(domain)
            result_dict.update({
                "CNAME": dns_data["CNAME"],
                "IPs": dns_data["IP"],
                "Country": dns_data["Country"],
                "City": dns_data["City"],
                "ISP": dns_data["ISP"]
            })

        if config['ssl']:
            ssl_data = get_ssl_info(domain)
            result_dict.update({
                "TLS 1.3": ssl_data["TLS_1.3_Status"],
                "Protocol": ssl_data["Actual_Protocol"],
                "Issuer": ssl_data["SSL_Issuer"],
                "SSL Days": ssl_data["SSL_Days_Left"]
            })

        if config['ping']:
            gp_result = run_globalping(domain)
            result_dict["Global Ping"] = gp_result

        return (index, result_dict)
        
    except Exception as e:
        return (index, {
            "Domain": domain,
            "CNAME": "Error",
            "IPs": str(e),
            "Country": "-", "City": "-", "ISP": "-",
            "TLS 1.3": "-", "Protocol": "-", "Issuer": "-", "SSL Days": "-", "Global Ping": "-"
        })

# --- UI 介面 ---

st.title("🌐 域名檢測 (有問題請找Andy Huang)")

with st.sidebar:
    st.header("⚙️ 掃描設定")
    st.subheader("1. 檢測項目")
    check_dns = st.checkbox("DNS 解析 & GeoIP", value=True)
    check_ssl = st.checkbox("SSL & TLS 1.3", value=True)
    check_ping = st.checkbox("Global Ping", value=True)
    
    st.divider()
    st.subheader("2. 效能")
    workers = st.slider("併發執行緒", 1, 5, 2)

with st.expander("ℹ️ 說明", expanded=True):
    st.write("支援重複域名與無效格式顯示。輸入幾行，輸出就是幾行。")

raw_input = st.text_area("請輸入域名 (不去重)", height=200)

if st.button("🚀 開始掃描", type="primary"):
    # 使用新版分詞函式 (不去重)
    domain_list = parse_input_raw(raw_input)
    # 保存原始順序
    indexed_domains = list(enumerate(domain_list))
    
    current_config = {'dns': check_dns, 'ssl': check_ssl, 'ping': check_ping}
    
    if not domain_list:
        st.warning("輸入為空")
    else:
        task_args = [(idx, dom, current_config) for idx, dom in indexed_domains]
        
        st.toast(f"開始掃描 {len(domain_list)} 筆資料...")
        
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_domain = {executor.submit(process_single_domain, arg): arg for arg in task_args}
            
            completed_count = 0
            for future in concurrent.futures.as_completed(future_to_domain):
                data = future.result()
                if data:
                    results.append(data)
                
                completed_count += 1
                progress_bar.progress(completed_count / len(domain_list))
                status_text.text(f"掃描中... ({completed_count}/{len(domain_list)})")

        st.success("完成！")
        
        results.sort(key=lambda x: x[0])
        final_data = [x[1] for x in results]
        df = pd.DataFrame(final_data)
        
        def style_dataframe(row):
            styles = [''] * len(row)
            if isinstance(row['SSL Days'], int):
                if row['SSL Days'] < 30: styles[9] = 'background-color: #ffcccc'
                elif row['SSL Days'] < 90: styles[9] = 'background-color: #ffffcc'
            
            if "No" in str(row['TLS 1.3']) and row['TLS 1.3'] != "-":
                styles[6] = 'color: red; font-weight: bold;'
                
            if ("Busy" in str(row['Global Ping']) or "Err" in str(row['Global Ping'])) and row['Global Ping'] != "-":
                 styles[10] = 'color: red;'
            
            # 標記格式錯誤的行
            if "Format Error" in str(row['IPs']):
                return ['background-color: #eeeeee; color: #888888'] * len(row)
                
            return styles

        st.dataframe(
            df.style.apply(style_dataframe, axis=1), 
            use_container_width=True,
            hide_index=True,
            column_config={
                "IPs": st.column_config.TextColumn("IP Addresses", width="medium"),
            }
        )
        
        csv = df.to_csv(index=False).encode('utf-8-sig')
        st.download_button("📥 下載報告 CSV", csv, "dns_audit_raw.csv", "text/csv")
