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
st.set_page_config(page_title="域名檢測 (萬能修復版)", layout="wide")

# --- 核心：萬能智慧分詞 ---

def parse_input_raw(raw_text):
    """
    智慧分詞：
    1. 萬能修復：針對任何 TLD (.com, .tw, .hk, .vn...) 後面黏著 www/http 的情況
    2. 保留無效格式以便核對
    """
    # 步驟 1: 萬能防沾黏切割
    # 邏輯：只要看到 "點+2~5個字母" (如 .com, .tw, .hk) 後面緊接著 "www." 或 "http"，就強制切一刀
    processed_text = re.sub(r'(\.[a-z]{2,5})(www\.|http)', r'\1\n\2', raw_text, flags=re.IGNORECASE)
    
    # 步驟 2: 處理常見的 http 黏連
    processed_text = processed_text.replace('https://', '\nhttps://').replace('http://', '\nhttp://')
    processed_text = processed_text.replace('未找到', '\n未找到\n')

    # 步驟 3: 分詞與清洗
    tokens = re.split(r'[\s,;]+', processed_text)
    final_domains = []
    
    for token in tokens:
        token = token.strip()
        if not token: continue 
        
        # 移除協定頭與路徑
        clean = token.replace('https://', '').replace('http://', '')
        clean = clean.split('/')[0].split('?')[0].split(':')[0]
        
        # 移除前後雜訊 (保留中文與點)
        clean = re.sub(r'^[^a-zA-Z0-9\u4e00-\u9fa5]+|[^a-zA-Z0-9\u4e00-\u9fa5]+$', '', clean)
        
        if clean:
            final_domains.append(clean)
    
    return final_domains

# --- 檢測函式 (抗封鎖增強版) ---

def get_dns_geoip(domain):
    result = {"CNAME": "-", "IP": "-", "Country": "-", "City": "-", "ISP": "-"}
    
    # 1. DNS 查詢
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

    # 2. GeoIP 查詢 (重點：嚴格限速與重試)
    if ip_list:
        result["IP"] = ", ".join(ip_list)
        first_ip = ip_list[0]
        
        # 如果 IP 看起來不完整 (例如 118.163.203.)，就不查 GeoIP 以免報錯
        if first_ip.endswith('.'):
             result["IP"] = f"{first_ip} (Incomplete)"
             return result

        # 重試機制 (指數退避)
        for attempt in range(4): # 增加到 4 次重試
            try:
                # 隨機延遲：這對於 1000 筆資料非常重要，避免瞬間觸發 45 req/min 限制
                # 第一次快一點，失敗後會越來越慢
                sleep_time = random.uniform(1.0, 2.0) + (attempt * 2)
                time.sleep(sleep_time)
                
                # 隨機 UA 偽裝
                uas = [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                ]
                headers = {'User-Agent': random.choice(uas)}
                
                resp = requests.get(
                    f"http://ip-api.com/json/{first_ip}?fields=country,city,isp,status", 
                    headers=headers, 
                    timeout=5
                )
                
                if resp.status_code == 429:
                    # 遇到 429 Too Many Requests，直接進入下一次迴圈 (會睡更久)
                    continue

                if resp.status_code == 200:
                    geo_data = resp.json()
                    if geo_data.get("status") == "success":
                        result["Country"] = geo_data.get("country", "-")
                        result["City"] = geo_data.get("city", "-")
                        result["ISP"] = geo_data.get("isp", "-")
                        break # 成功取得資料，跳出
            except:
                time.sleep(1)
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
    # Global Ping 也很容易被擋，這裡也加強防護
    url = "https://api.globalping.io/v1/measurements"
    headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    payload = {"limit": 2, "locations": [], "target": domain, "type": "http", "measurementOptions": {"protocol": "HTTPS"}}
    
    for attempt in range(3):
        try:
            # 增加延遲
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
        "Domain": domain, "CNAME": "-", "IPs": "-", "Country": "-", "City": "-", "ISP": "-",
        "TLS 1.3": "-", "Protocol": "-", "Issuer": "-", "SSL Days": "-", "Global Ping": "-"
    }
    
    if "未找到" in domain:
        result_dict["IPs"] = "❌ Source Not Found"
        return (index, result_dict)

    if '.' not in domain or len(domain) < 3:
        result_dict["IPs"] = "❌ Format Error"
        # 標記格式錯誤，這可能是因為切割不完美導致的殘留
        return (index, result_dict)

    try:
        if config['dns']:
            dns_data = get_dns_geoip(domain)
            result_dict.update({"CNAME": dns_data["CNAME"], "IPs": dns_data["IP"], "Country": dns_data["Country"], "City": dns_data["City"], "ISP": dns_data["ISP"]})
        if config['ssl']:
            ssl_data = get_ssl_info(domain)
            result_dict.update({"TLS 1.3": ssl_data["TLS_1.3_Status"], "Protocol": ssl_data["Actual_Protocol"], "Issuer": ssl_data["SSL_Issuer"], "SSL Days": ssl_data["SSL_Days_Left"]})
        if config['ping']:
            gp_result = run_globalping(domain)
            result_dict["Global Ping"] = gp_result
        return (index, result_dict)
    except Exception as e:
        return (index, {
            "Domain": domain, "CNAME": "Error", "IPs": str(e),
            "Country": "-", "City": "-", "ISP": "-", "TLS 1.3": "-", "Protocol": "-", "Issuer": "-", "SSL Days": "-", "Global Ping": "-"
        })

# --- UI 介面 ---

st.title("🌐 域名檢測 (巨量資料專用版)")
st.caption("✅ 支援自動修復黏連 (.hk, .vn, .com...) ✅ 強力抗 API 封鎖 ✅ 資料完整性優先")

with st.sidebar:
    st.header("⚙️ 掃描設定")
    check_dns = st.checkbox("DNS & GeoIP", value=True)
    check_ssl = st.checkbox("SSL & TLS 1.3", value=True)
    check_ping = st.checkbox("Global Ping", value=True, help="如果只想查 IP 和 SSL，建議取消此項以大幅加快速度")
    
    st.warning("⚠️ 掃描 1000+ 筆資料時：")
    st.caption("為確保 Country/ISP 資料完整，請勿將速度調太快。")
    workers = st.slider("掃描速度 (建議維持在 2)", 1, 5, 2)

raw_input = st.text_area("請貼上 1063 筆資料", height=250)

if st.button("🚀 開始掃描", type="primary"):
    domain_list = parse_input_raw(raw_input)
    indexed_domains = list(enumerate(domain_list))
    current_config = {'dns': check_dns, 'ssl': check_ssl, 'ping': check_ping}
    
    if not domain_list:
        st.warning("輸入為空")
    else:
        st.success(f"已識別 {len(domain_list)} 筆資料 (之前的版本可能只抓到 1002 筆)")
        
        task_args = [(idx, dom, current_config) for idx, dom in indexed_domains]
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # 使用 ThreadPoolExecutor
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
            if isinstance(row['SSL Days'], int):
                if row['SSL Days'] < 30: styles[9] = 'background-color: #ffcccc'
                elif row['SSL Days'] < 90: styles[9] = 'background-color: #ffffcc'
            if "No" in str(row['TLS 1.3']) and row['TLS 1.3'] != "-":
                styles[6] = 'color: red; font-weight: bold;'
            if "Format Error" in str(row['IPs']) or "Not Found" in str(row['IPs']):
                return ['background-color: #eeeeee; color: #888888'] * len(row)
            return styles

        st.dataframe(df.style.apply(style_dataframe, axis=1), use_container_width=True, hide_index=True)
        csv = df.to_csv(index=False).encode('utf-8-sig')
        st.download_button("📥 下載報告 CSV", csv, "dns_audit_ultimate.csv", "text/csv")
