import streamlit as st
import requests

# --- 🌐 Konfigurasi Halaman ---
st.set_page_config(
    page_title="Cek Keamanan Situs",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# --- 🎨 CSS untuk Tampilan Modern ---
st.markdown("""
    <style>
        body {
            background: linear-gradient(135deg, #74ABE2, #5563DE);
        }
        .main {
            background-color: #fdfdfd;
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.1);
        }
        h1, h2, h3 {
            color: #2C3E50;
            text-align: center;
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
        .result-box {
            background-color: #f0f3ff;
            border-left: 5px solid #5563DE;
            padding: 10px 15px;
            margin-top: 10px;
            border-radius: 8px;
            color: #34495e;
        }
        footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# --- 🔑 Ambil API Key dari Streamlit Secrets ---
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

# --- 🧾 Judul ---
st.title("🔍 Cek Keamanan Situs Web")
st.markdown("Gunakan aplikasi ini untuk memeriksa apakah suatu URL **aman** atau **berpotensi berbahaya** menggunakan **Google Safe Browsing API.**")
st.markdown("---")

# --- 💾 Simpan Riwayat di Session State ---
if "history" not in st.session_state:
    st.session_state.history = []

# --- 🌐 Input URL ---
st.markdown("### 🌐 Masukkan URL yang ingin diperiksa")
url_input = st.text_input("", placeholder="contoh: https://example.com")

# --- 🚦 Tombol Cek Situs ---
if st.button("🔎 Cek Situs"):
    if url_input.strip():
        with st.spinner("🔄 Sedang memeriksa keamanan situs..."):
            safe, threat = check_url(url_input.strip())

            # Simpan ke riwayat
            st.session_state.history.append({
                "url": url_input.strip(),
                "status": "Aman" if safe else "Berbahaya",
                "threat": threat if threat else "-"
            })

            st.markdown("---")
            if safe:
                st.success("✅ **Situs ini aman dikunjungi.**")
                st.balloons()
            else:
                st.error(f"⚠️ **Situs ini berpotensi berbahaya!**\n\nJenis ancaman: **{threat}**")
    else:
        st.warning("⚠️ Masukkan URL terlebih dahulu.")

# --- 🕘 Riwayat Pengecekan ---
if st.session_state.history:
    st.markdown("---")
    st.subheader("📜 Riwayat Pengecekan")

    for item in reversed(st.session_state.history):
        color = "#2ecc71" if item["status"] == "Aman" else "#e74c3c"
        st.markdown(
            f"""
            <div class='result-box'>
                <b>URL:</b> <span style='color:#5563DE'>{item['url']}</span><br>
                <b>Status:</b> <span style='color:{color}'>{item['status']}</span><br>
                <b>Jenis Ancaman:</b> {item['threat']}
            </div>
            """, unsafe_allow_html=True
        )

# --- ✨ Footer ---
st.markdown("""
---
<center style='color:#7f8c8d;'>Made with ❤️ by Andi using Streamlit & Google Safe Browsing API</center>
""", unsafe_allow_html=True)


