import streamlit as st
import requests

# --- 🌐 Konfigurasi Halaman ---
st.set_page_config(
    page_title="Cek Keamanan Situs",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# --- 🎨 CSS Kustom untuk Tampilan Lebih Menarik ---
st.markdown("""
    <style>
        body {
            background: linear-gradient(135deg, #74ABE2, #5563DE);
            color: #fff;
        }
        .main {
            background-color: #f8f9fa;
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        }
        h1 {
            text-align: center;
            color: #2C3E50 !important;
        }
        p {
            text-align: center;
            color: #34495E !important;
        }
        .stTextInput>div>div>input {
            border-radius: 10px;
            border: 2px solid #ced6e0;
            padding: 10px;
        }
        .stButton>button {
            width: 100%;
            background-color: #5563DE !important;
            color: white !important;
            border-radius: 10px;
            font-weight: bold;
            padding: 10px;
            transition: 0.3s;
        }
        .stButton>button:hover {
            background-color: #3b4cd7 !important;
            transform: scale(1.02);
        }
    </style>
""", unsafe_allow_html=True)

# --- 🧠 Judul & Deskripsi ---
st.title("🔍 Cek Keamanan Situs Web")
st.markdown("Gunakan aplikasi ini untuk memeriksa apakah suatu URL **aman** atau **berpotensi berbahaya** menggunakan **Google Safe Browsing API.**")

st.markdown("---")

# --- 🔑 Ambil API Key dari Secrets Streamlit Cloud ---
API_KEY = st.secrets["API_KEY"]
ENDPOINT = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

# --- ⚙️ Fungsi Pemeriksaan URL ---
def check_url(url):
    body = {
        "client": {"clientId": "streamlit-safe-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(ENDPOINT, json=body)
    result = response.json()

    if "matches" in result:
        return False, result["matches"][0]["threatType"]
    return True, None

# --- 🧾 Input URL ---
st.markdown("### 🌐 Masukkan URL yang ingin diperiksa")
url_input = st.text_input("", placeholder="contoh: https://example.com")

# --- 🚦 Tombol & Hasil ---
if st.button("🔎 Cek Situs"):
    if url_input.strip():
        with st.spinner("🔄 Sedang memeriksa keamanan situs..."):
            safe, threat = check_url(url_input.strip())
            st.markdown("---")
            if safe:
                st.success("✅ **Situs ini aman dikunjungi.**")
                st.balloons()
            else:
                st.error(f"⚠️ **Situs ini berpotensi berbahaya!**\n\nJenis ancaman: **{threat}**")
    else:
        st.warning("⚠️ Masukkan URL terlebih dahulu.")

# --- ✨ Footer ---
st.markdown("""
---
<center>Made with ❤️ using Streamlit & Google Safe Browsing API</center>
""", unsafe_allow_html=True)
