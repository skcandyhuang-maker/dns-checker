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
import urllib3

# 關閉 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 設定頁面標題
st.set_page_config(page_title="Andy的全能網管工具", layout="wide")

# ==========================================
#  共用輔助函式
# ==========================================

def get_dns_resolver():
    """建立自訂的 DNS 解析器"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1'] 
    resolver.timeout = 5
    resolver.lifetime = 5
    return resolver

def parse_input_raw(raw_text):
    """
    萬能分詞與清洗
    支援分隔符號：換行(\n)、逗號(,)、分號(;)、空白(space)
    """
    # 1. 先處理黏在一起的網址 (針對域名)
    processed_text = re.sub(r'(\.[a-z]{2,5})(www\.|http)', r'\1\n\2', raw_text, flags=re.IGNORECASE)
    processed_text = processed_text.replace('https://', '\nhttps://').replace('http://', '\nhttp://')
    processed_text = processed_text.replace('未找到', '\n未找到\n')
    
    # 2. 核心切分邏輯：使用正則表達式同時切割 [換行, 逗號, 分號, 空白]
    # r'[\s,;]+' 代表：只要遇到 空白(\s)、逗號(,) 或 分號(;) 的組合，都切開
    tokens = re.split(r'[\s,;]+', processed_text)
    
    final_items = []
    for token in tokens:
        token = token.strip()
        if not token: continue 
        
        # 移除常見雜訊
        clean = token.replace('https://', '').replace('http://', '')
        clean = clean.split('/')[0].split('?')[0].split(':')[0]
        # 移除前後非英數字元 (保留中文與點)
        clean = re.sub(r'^[^a-zA-Z0-9\u4e00-\u9fa5\.]+|[^a-zA-Z0-9\u4e00-\u9fa5]+$', '', clean)
        
        if clean: 
            final_items.append(clean)
            
    # 去重 (Optionally) - 這裡保留原始輸入順序與重複項，若需去重可加 set
    return final_items

# ==========================================
#  核心功能模組
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
    headers = {
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7"
    }
	
    try:
        resp = requests.get(f"https://{domain}", timeout=5, headers=headers, verify=False)
        return f"✅ {resp.status_code}"
    except:
        try:
            resp = requests.get(f"http://{domain}", timeout=5, headers=headers)
            return f"⚠️ {resp.status_code} (HTTP)"
        except:
            return "❌ Fail"

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
        # DNS
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
                
                # GeoIP
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
            else:
                result["IPs"] = "No Record"

        # SSL
        if config['ssl']:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = None
            try:
                sock = socket.create_connection((domain, 443), timeout=5)
                conn = ctx.wrap_socket(sock, server_hostname=domain)
                result["Actual_Protocol"] = conn.version()
                result["TLS 1.3"] = "✅ Yes" if conn.version() == 'TLSv1.3' else "❌ No"
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, conn.getpeercert(binary_form=True))
                subject = cert.get_issuer()
                cn = subject.CN if subject.CN else "Unknown"
                result["Issuer"] = cn
                not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                result["SSL Days"] = (not_after - datetime.now()).days
            except: 
                result["Protocol"] = "Connect Fail"
            finally:
                if conn: conn.close()

        if config['global_ping']:
            result["Global Ping"] = run_globalping_api(domain)

        if config['simple_ping']:
            result["Simple Ping"] = run_simple_ping(domain)

    except Exception as e:
        result["IPs"] = str(e)
    
    return (index, result)

# ==========================================
#  功能模組 B: IP 反查 (VT)
# ==========================================

def check_single_domain_status(domain, target_ip):
    resolver = get_dns_resolver()
    status_result = {
        "Domain": domain,
        "Current_IP": "-",
        "Match_Input_IP": "❌ No",
        "HTTP_Status": "-"
    }
    
    try:
        a_ans = resolver.resolve(domain, 'A')
        current_ips = [str(r.address) for r in a_ans]
        status_result["Current_IP"] = ", ".join(current_ips)
        
        if target_ip in current_ips:
            status_result["Match_Input_IP"] = "✅ Yes"
            headers = {"User-Agent": "Mozilla/5.0"}
            try:
                resp = requests.get(f"https://{domain}", timeout=5, headers=headers, verify=False)
                status_result["HTTP_Status"] = f"✅ {resp.status_code} (HTTPS)"
            except:
                try:
                    resp = requests.get(f"http://{domain}", timeout=5, headers=headers)
                    status_result["HTTP_Status"] = f"✅ {resp.status_code} (HTTP)"
                except:
                    status_result["HTTP_Status"] = "❌ Unreachable"
        else:
             status_result["HTTP_Status"] = "-"
    except:
        status_result["Current_IP"] = "No Record"
        
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
    except Exception as e:
        return f"Exception: {str(e)}", []


# ==========================================
#  UI 主程式
# ==========================================

tab1, tab2 = st.tabs(["🔍 域名檢測", "🕵️ IP 反查域名 (VT)"])

# --- 分頁 1: 域名檢測 ---
with tab1:
    st.header("批量域名體檢")
    
    col1, col2 = st.columns([1, 3])
    with col1:
        st.subheader("設定")
        check_dns = st.checkbox("DNS & GeoIP", value=True)
        check_ssl = st.checkbox("SSL & TLS", value=True)
        
        st.divider()
        st.caption("連線測試")
        check_simple_ping = st.checkbox("Simple Ping (本機)", value=True, help="從你的電腦直接連線測試")
        check_global_ping = st.checkbox("Global Ping (全球)", value=True, help="呼叫外部 API 從國外節點測試 (速度較慢)")
        
        st.divider()
        workers = st.slider("掃描速度", 1, 5, 3)

    with col2:
        raw_input = st.text_area("輸入域名 (支援混亂格式)", height=150, placeholder="example.com\nwww.google.com")
        if st.button("🚀 開始掃描域名", type="primary"):
            domain_list = parse_input_raw(raw_input)
            if not domain_list:
                st.warning("請輸入域名")
            else:
                config = {
                    'dns': check_dns, 
                    'ssl': check_ssl, 
                    'global_ping': check_global_ping, 
                    'simple_ping': check_simple_ping
                }
                indexed_domains = list(enumerate(domain_list))
                st.info(f"開始掃描 {len(domain_list)} 筆資料...")
                
                results = []
                progress_bar = st.progress(0)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = {executor.submit(process_domain_audit, (idx, dom, config)): idx for idx, dom in indexed_domains}
                    completed = 0
                    for future in concurrent.futures.as_completed(futures):
                        data = future.result()
                        results.append(data[1])
                        completed += 1
                        progress_bar.progress(completed / len(domain_list))
                
                df = pd.DataFrame(results)
                
                def highlight_rows(row):
                    styles = [''] * len(row)
                    if "⚡" in str(row.get('CDN Provider', '')):
                        styles[1] = 'color: #009900; font-weight: bold;'
                    if "✅" in str(row.get('Multi-IP', '')):
                        styles[3] = 'color: #009900;'
                    if "✅" in str(row.get('Simple Ping', '')):
                        simple_idx = df.columns.get_loc("Simple Ping")
                        styles[simple_idx] = 'color: #009900; font-weight: bold;'
                    return styles
                
                st.dataframe(df.style.apply(highlight_rows, axis=1), use_container_width=True)
                st.download_button("下載 CSV", df.to_csv(index=False).encode('utf-8-sig'), "domain_audit.csv")


# --- 分頁 2: IP 反查 ---
with tab2:
    st.header("IP 反查與存活驗證 (Powered by VirusTotal)")
    
    api_key = st.text_input("請輸入 VirusTotal API Key", type="password")
    
    # 修改提示文字，明確告知支援逗號分隔
    ip_input = st.text_area("輸入 IP 清單 (支援換行或逗號)", height=150, placeholder="223.26.10.19, 223.26.15.116\n8.8.8.8")
    
    if st.button("🕵️ 開始反查 IP", type="primary"):
        if not api_key:
            st.error("請輸入 API Key！")
        else:
            # 這裡會呼叫更新後的 parse_input_raw
            ip_list = parse_input_raw(ip_input)
            
            if not ip_list:
                st.warning("請輸入 IP")
            else:
                st.toast(f"準備查詢 {len(ip_list)} 個 IP...")
                final_report = []
                vt_counter = 0
                status_log = st.empty()
                
                for i, ip in enumerate(ip_list):
                    status_log.markdown(f"**[{i+1}/{len(ip_list)}] 正在查詢 VT:** `{ip}` ...")
                    status, domains = process_ip_vt_lookup(ip, api_key)
                    
                    if status == "Success":
                        if not domains:
                            final_report.append({"Input_IP": ip, "Domain": "(no data)", "Match_IP": "-", "HTTP": "-"})
                        else:
                            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                                verify_futures = {executor.submit(check_single_domain_status, dom, ip): dom for dom in domains}
                                for future in concurrent.futures.as_completed(verify_futures):
                                    v_res = future.result()
                                    final_report.append({
                                        "Input_IP": ip,
                                        "Domain": v_res["Domain"],
                                        "Match_IP": v_res["Match_Input_IP"],
                                        "HTTP": v_res["HTTP_Status"]
                                    })
                    elif status == "RateLimit":
                        st.error("API 速率限制 (429)！")
                        break
                    elif status == "AuthError":
                        st.error("API Key 錯誤 (401)！")
                        break
                    else:
                        final_report.append({"Input_IP": ip, "Domain": f"Error: {status}", "Match_IP": "-", "HTTP": "-"})
                    
                    vt_counter += 1
                    if i < len(ip_list) - 1:
                        if vt_counter % 4 == 0:
                            for sec in range(60, 0, -1):
                                status_log.warning(f"⏳ Rate Limit 冷卻中... 剩餘 {sec} 秒")
                                time.sleep(1)
                        else:
                            time.sleep(15)

                status_log.success("查詢完成！")
                if final_report:
                    df_vt = pd.DataFrame(final_report)
                    def highlight_vt(row):
                        styles = [''] * len(row)
                        if "Yes" in str(row['Match_IP']) and "200" in str(row['HTTP']):
                            return ['background-color: #d4edda; color: #155724'] * len(row)
                        return styles
                    st.dataframe(df_vt.style.apply(highlight_vt, axis=1), use_container_width=True)
                    st.download_button("下載反查報告", df_vt.to_csv(index=False).encode('utf-8-sig'), "ip_reverse_check.csv")
