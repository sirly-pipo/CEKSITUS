import streamlit as st
import requests

st.set_page_config(page_title="Cek Keamanan Situs", page_icon="🔒")

st.title("🔍 Cek Keamanan Situs Web")
st.write("Gunakan aplikasi ini untuk memeriksa apakah suatu URL aman menggunakan Google Safe Browsing API.")

API_KEY = st.secrets["API_KEY"]
ENDPOINT = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def check_url(url):
    body = {
        "client": {
            "clientId": "streamlit-safe-checker",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
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

url_input = st.text_input("Masukkan URL yang ingin dicek (contoh: https://example.com)")

if st.button("Cek Situs"):
    if url_input.strip():
        with st.spinner("Sedang memeriksa situs..."):
            safe, threat = check_url(url_input.strip())
            if safe:
                st.success("✅ Situs ini aman dikunjungi.")
            else:
                st.error(f"⚠️ Situs ini berpotensi berbahaya! Jenis ancaman: **{threat}**")
    else:
        st.warning("Masukkan URL terlebih dahulu.")
