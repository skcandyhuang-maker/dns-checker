import streamlit as st
import pandas as pd
import dns.resolver
import requests
import ssl
import socket
import concurrent.futures
import time
from datetime import datetime
from OpenSSL import crypto

# 設定頁面寬度
st.set_page_config(page_title="域名極速檢測工具 (多IP版)", layout="wide")

# --- 核心檢測函式 ---

def get_dns_geoip(domain):
    """取得 DNS 解析 (支援多 IP) 與 GeoIP 資訊"""
    result = {
        "CNAME": "None", "IP": "None", 
        "Country": "-", "City": "-", "ISP": "-"
    }
    try:
        # 1. 查詢 CNAME (如果有)
        try:
            cname_answers = dns.resolver.resolve(domain, 'CNAME')
            result["CNAME"] = str(cname_answers[0].target).rstrip('.')
        except:
            pass # 沒有 CNAME 是正常的，繼續往下查 IP

        # 2. 查詢 A 紀錄 (IP) - dnspython 會自動追蹤 CNAME 到最終 IP
        try:
            a_answers = dns.resolver.resolve(domain, 'A')
            # 重點修改：使用 list comprehension 抓取所有 IP 並用逗號連接
            ip_list = [str(r.address) for r in a_answers]
            result["IP"] = ", ".join(ip_list)
            
            # 3. 查詢 GeoIP (使用列表中的第一個 IP 作為代表)
            if ip_list:
                first_ip = ip_list[0]
                # 設定 timeout 避免卡住
                geo_resp = requests.get(f"http://ip-api.com/json/{first_ip}?fields=country,city,isp", timeout=2).json()
                result["Country"] = geo_resp.get("country", "-")
                result["City"] = geo_resp.get("city", "-")
                result["ISP"] = geo_resp.get("isp", "-")
        except:
            result["IP"] = "No Record"
            
    except Exception as e:
        result["IP"] = "DNS Error"
    
    return result

def get_ssl_info(domain):
    """取得 SSL 證書資訊並檢查是否支援 TLS 1.3"""
    result = {
        "SSL_Issuer": "-", "SSL_Days_Left": "-", 
        "TLS_1.3_Status": "❌", "Actual_Protocol": "-"
    }
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    conn = None
    try:
        sock = socket.create_connection((domain, 443), timeout=3)
        conn = context.wrap_socket(sock, server_hostname=domain)
        
        protocol_ver = conn.version()
        result["Actual_Protocol"] = protocol_ver
        
        if protocol_ver == 'TLSv1.3':
            result["TLS_1.3_Status"] = "✅ Yes"
        else:
            result["TLS_1.3_Status"] = "❌ No"
        
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
    """Globalping API 測試"""
    url = "https://api.globalping.io/v1/measurements"
    payload = {
        "limit": 5,
        "locations": [], 
        "target": domain,
        "type": "http",
        "measurementOptions": {"protocol": "HTTPS"}
    }
    try:
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code != 202: return "API Error"
        ms_id = resp.json()['id']
        
        for _ in range(5):
            time.sleep(1)
            res_resp = requests.get(f"{url}/{ms_id}", timeout=3)
            data = res_resp.json()
            if data['status'] == 'finished':
                results = data['results']
                success_count = sum(1 for r in results if r['result']['status'] == 'finished' and str(r['result']['rawOutput']).startswith('HTTP'))
                return f"{success_count}/5 OK"
        return "Timeout"
    except:
        return "Check Fail"

def process_single_domain(domain):
    domain = domain.strip().replace("https://", "").replace("http://", "").split('/')[0]
    if not domain: return None
    
    dns_data = get_dns_geoip(domain)
    ssl_data = get_ssl_info(domain)
    gp_result = run_globalping(domain)
    
    return {
        "Domain": domain,
        "CNAME": dns_data["CNAME"],
        "IPs": dns_data["IP"],  # 改名為 IPs 以示區別
        "Country": dns_data["Country"],
        "City": dns_data["City"],
        "ISP": dns_data["ISP"],
        "TLS 1.3": ssl_data["TLS_1.3_Status"],
        "Protocol": ssl_data["Actual_Protocol"],
        "Issuer": ssl_data["SSL_Issuer"],
        "SSL Days": ssl_data["SSL_Days_Left"],
        "Global Ping": gp_result
    }

# --- UI 介面 ---

st.title("🌐 域名深度檢測 (多IP解析版)")

with st.expander("ℹ️ 更新說明", expanded=True):
    st.write("""
    - **IPs**: 現在會列出該域名解析到的**所有 IP 地址**。
    - **CNAME**: 即使有 CNAME，也會繼續追蹤並列出背後的 IP。
    - **ISP/Country**: 以解析到的第一個 IP 為基準進行查詢。
    """)

domains_input = st.text_area("請輸入域名 (一行一個)", height=150)

if st.button("🚀 開始掃描", type="primary"):
    domains = [d.strip() for d in domains_input.split('\n') if d.strip()]
    
    if not domains:
        st.warning("請輸入域名")
    else:
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_domain = {executor.submit(process_single_domain, d): d for d in domains}
            
            completed_count = 0
            for future in concurrent.futures.as_completed(future_to_domain):
                data = future.result()
                if data: results.append(data)
                completed_count += 1
                progress_bar.progress(completed_count / len(domains))
                status_text.text(f"掃描中... ({completed_count}/{len(domains)})")

        st.success("完成！")
        df = pd.DataFrame(results)
        
        def style_dataframe(row):
            styles = [''] * len(row)
            # SSL 天數檢查 (第 9 欄)
            if isinstance(row['SSL Days'], int):
                if row['SSL Days'] < 30: styles[9] = 'background-color: #ffcccc'
                elif row['SSL Days'] < 90: styles[9] = 'background-color: #ffffcc'
            # TLS 1.3 檢查 (第 6 欄)
            if "No" in str(row['TLS 1.3']):
                styles[6] = 'color: red; font-weight: bold;'
            return styles

        st.dataframe(
            df.style.apply(style_dataframe, axis=1), 
            use_container_width=True,
            column_config={
                "IPs": st.column_config.TextColumn("IP Addresses", width="medium"), # 加寬 IP 欄位
            }
        )
        
        csv = df.to_csv(index=False).encode('utf-8-sig')
        st.download_button("📥 下載詳細報告 CSV", csv, "dns_audit_multi_ip.csv", "text/csv")
