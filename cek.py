import streamlit as st
import requests
import re
from urllib.parse import urlparse

# --- 🌐 Konfigurasi Halaman ---
st.set_page_config(
    page_title="Cek Keamanan Situs",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)
st.markdown("""
    <style>
        /* 🌈 Background Gradien Halus */
        body {
            background: linear-gradient(135deg, #89f7fe 0%, #66a6ff 100%);
            font-family: 'Poppins', sans-serif;
            color: #2c3e50;
        }

        /* ✨ Container Utama (Efek Glassmorphism) */
        .main {
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(10px);
            padding: 2.5rem;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            transition: 0.3s ease-in-out;
        }
        .main:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 40px rgba(0,0,0,0.2);
        }

        /* 📝 Judul */
        h1, h2, h3 {
            color: #1a237e;
            text-align: center;
            font-weight: 700;
            letter-spacing: 0.5px;
        }

        /* 🔍 Input URL */
        .stTextInput>div>div>input {
            border-radius: 12px;
            border: 2px solid #d1d9ff;
            padding: 12px 14px;
            transition: all 0.3s ease;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);
        }
        .stTextInput>div>div>input:focus {
            border-color: #5563DE;
            box-shadow: 0 0 6px rgba(85,99,222,0.4);
        }

        /* 🔘 Tombol Cek Situs */
        .stButton>button {
            width: 100%;
            background: linear-gradient(90deg, #5563DE, #5e7bff);
            color: white !important;
            border-radius: 12px;
            font-weight: 600;
            padding: 12px;
            border: none;
            letter-spacing: 0.5px;
            transition: all 0.3s ease-in-out;
            box-shadow: 0 4px 10px rgba(85,99,222,0.3);
        }
        .stButton>button:hover {
            background: linear-gradient(90deg, #4655cc, #3b4cd7);
            transform: scale(1.05);
            box-shadow: 0 6px 14px rgba(85,99,222,0.4);
        }

        /* 📦 Kotak Hasil */
        .result-box {
            background: rgba(240,243,255,0.9);
            border-left: 6px solid #5563DE;
            padding: 15px 18px;
            margin-top: 12px;
            border-radius: 12px;
            color: #2c3e50;
            box-shadow: 0 2px 6px rgba(0,0,0,0.05);
            transition: transform 0.2s;
        }
        .result-box:hover {
            transform: translateX(3px);
        }

        /* 💡 Info Box */
        .info-box {
            background: rgba(255, 249, 196, 0.9);
            border-left: 6px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 12px;
            font-size: 0.95rem;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }

        /* ⚠ Pesan Peringatan */
        .stAlert {
            border-radius: 12px !important;
        }

        /* 🔽 Expander */
        .streamlit-expanderHeader {
            font-weight: 600;
            color: #1a237e;
            font-size: 1rem;
        }

        /* 📜 Riwayat */
        .result-box b {
            color: #1a237e;
        }

        /* 💬 Footer */
        footer {visibility: hidden;}
        footer:after {
            content: "Made with ❤ by Andi | Google Safe Browsing API";
            visibility: visible;
            display: block;
            position: relative;
            top: 20px;
            text-align: center;
            font-size: 13px;
            color: #34495e;
        }
    </style>
""", unsafe_allow_html=True)
# --- 🔑 Ambil API Key dari Streamlit Secrets ---
try:
    API_KEY = st.secrets["API_KEY"]
    ENDPOINT = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
except Exception as e:
    st.error("⚠️ **Error:** API Key tidak ditemukan. Pastikan Anda sudah menambahkan API_KEY di Streamlit Secrets.")
    st.stop()

# --- 🔧 Fungsi Validasi & Format URL ---
def validate_and_format_url(url):
    """Validasi dan format URL agar sesuai standar"""
    url = url.strip()
    
    # Tambahkan https:// jika tidak ada protokol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Validasi format URL
    url_pattern = re.compile(
        r'^https?://'  # http:// atau https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # atau localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # atau IP
        r'(?::\d+)?'  # port opsional
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        return None, "Format URL tidak valid"
    
    return url, None

# --- ⚙️ Fungsi Pemeriksaan URL ---
def check_url(url):
    """Cek keamanan URL menggunakan Google Safe Browsing API"""
    body = {
        "client": {
            "clientId": "streamlit-safe-checker",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(ENDPOINT, json=body, timeout=10)
        response.raise_for_status()
        result = response.json()

        if "matches" in result:
            threats = [match["threatType"] for match in result["matches"]]
            return False, threats
        return True, None
    
    except requests.exceptions.Timeout:
        return None, "Timeout: Permintaan terlalu lama"
    except requests.exceptions.RequestException as e:
        return None, f"Error koneksi: {str(e)}"
    except Exception as e:
        return None, f"Error tidak terduga: {str(e)}"

# --- 📊 Fungsi Terjemahan Jenis Ancaman ---
def translate_threat(threat_type):
    """Terjemahkan jenis ancaman ke Bahasa Indonesia"""
    translations = {
        "MALWARE": "Malware (Perangkat Lunak Berbahaya)",
        "SOCIAL_ENGINEERING": "Social Engineering (Penipuan/Phishing)",
        "UNWANTED_SOFTWARE": "Software Tidak Diinginkan",
        "POTENTIALLY_HARMFUL_APPLICATION": "Aplikasi Berpotensi Berbahaya"
    }
    return translations.get(threat_type, threat_type)

# --- 🧾 Judul ---
st.title("🔍 Cek Keamanan Situs Web")
st.markdown("Gunakan aplikasi ini untuk memeriksa apakah suatu URL **aman** atau **berpotensi berbahaya** menggunakan **Google Safe Browsing API.**")
st.markdown("---")

# --- 💡 Info Box ---
with st.expander("ℹ️ Cara Penggunaan"):
    st.markdown("""
    1. Masukkan URL situs web yang ingin Anda periksa
    2. Klik tombol **Cek Situs**
    3. Tunggu hasil pemeriksaan
    4. Lihat riwayat pengecekan di bawah
    
    **Contoh URL:**
    - `https://google.com`
    - `example.com` (akan otomatis ditambahkan https://)
    - `https://www.facebook.com`
    """)

# --- 💾 Simpan Riwayat di Session State ---
if "history" not in st.session_state:
    st.session_state.history = []

# --- 🌐 Input URL ---
st.markdown("### 🌐 Masukkan URL yang ingin diperiksa")
url_input = st.text_input("", placeholder="contoh: https://example.com atau example.com", label_visibility="collapsed")

# --- 🚦 Tombol Cek Situs ---
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    check_button = st.button("🔎 Cek Situs", use_container_width=True)

if check_button:
    if url_input.strip():
        # Validasi URL
        formatted_url, error = validate_and_format_url(url_input)
        
        if error:
            st.error(f"⚠️ {error}")
        else:
            with st.spinner("🔄 Sedang memeriksa keamanan situs..."):
                safe, threat = check_url(formatted_url)

                if safe is None:
                    # Error terjadi
                    st.error(f"❌ **Gagal memeriksa situs.**\n\n{threat}")
                else:
                    # Simpan ke riwayat
                    st.session_state.history.append({
                        "url": formatted_url,
                        "status": "Aman" if safe else "Berbahaya",
                        "threat": threat if threat else []
                    })

                    st.markdown("---")
                    if safe:
                        st.success("✅ **Situs ini aman dikunjungi.**")
                        st.info("🛡️ Tidak ditemukan ancaman dari Google Safe Browsing Database.")
                        st.balloons()
                    else:
                        st.error("⚠️ **PERINGATAN: Situs ini berpotensi berbahaya!**")
                        st.markdown("**Jenis ancaman yang terdeteksi:**")
                        for t in threat:
                            st.markdown(f"- 🚨 {translate_threat(t)}")
                        st.warning("⚠️ **Hindari mengunjungi situs ini!**")
    else:
        st.warning("⚠️ Masukkan URL terlebih dahulu.")

# --- 🕘 Riwayat Pengecekan ---
if st.session_state.history:
    st.markdown("---")
    st.subheader("📜 Riwayat Pengecekan")
    
    # Tombol hapus riwayat
    if st.button("🗑️ Hapus Riwayat", type="secondary"):
        st.session_state.history = []
        st.rerun()

    for idx, item in enumerate(reversed(st.session_state.history)):
        color = "#2ecc71" if item["status"] == "Aman" else "#e74c3c"
        
        # Format threat list
        if isinstance(item["threat"], list) and item["threat"]:
            threat_text = "<br>".join([f"• {translate_threat(t)}" for t in item["threat"]])
        else:
            threat_text = "-"
        
        st.markdown(
            f"""
            <div class='result-box'>
                <b>#{len(st.session_state.history) - idx}. URL:</b> <span style='color:#5563DE'>{item['url']}</span><br>
                <b>Status:</b> <span style='color:{color}; font-weight:bold;'>{item['status']}</span><br>
                <b>Jenis Ancaman:</b><br>{threat_text}
            </div>
            """, unsafe_allow_html=True
        )

# --- ✨ Footer ---
st.markdown("""
---
<center style='color:#7f8c8d; font-size: 14px;'>
    Made with ❤️ by Andi using Streamlit & Google Safe Browsing API<br>
    <small>© 2024 - Aplikasi Cek Keamanan Situs</small>
</center>
""", unsafe_allow_html=True)

