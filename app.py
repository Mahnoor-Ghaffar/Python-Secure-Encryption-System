import streamlit as st
import hashlib
import json
import time
import uuid
import base64
import os
from cryptography.fernet import Fernet

# -------------------- CONFIGURATION --------------------
# Make sure this is the first command after imports
st.set_page_config(page_title="Secure Encryption System", layout="centered")

MASTER_PASSWORD = "admin123"  # Directly setting the MASTER_PASSWORD

# -------------------- INITIALIZE SESSION STATE --------------------
for key in ['failed_attempts', 'stored_data', 'current_page', 'last_attempt_time']:
    if key not in st.session_state:
        st.session_state[key] = 0 if 'attempts' in key else "Home" if key == "current_page" else {}

# -------------------- UTILITY FUNCTIONS --------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key(passkey):
    return base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest()[:32])

def encrypt_data(data, passkey):
    return Fernet(generate_key(passkey)).encrypt(data.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed = hash_passkey(passkey)
        if st.session_state.stored_data[data_id]["passkey"] == hashed:
            decrypted = Fernet(generate_key(passkey)).decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
    except Exception:
        pass
    st.session_state.failed_attempts += 1
    st.session_state.last_attempt_time = time.time()
    return None

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def generate_data_id():
    return str(uuid.uuid4())

def change_page(page_name):
    st.session_state.current_page = page_name
    st.rerun()

# -------------------- UI PAGES --------------------
def home_page():
    st.title("🔐 Secure Data Encryption System")
    st.write("Store and retrieve encrypted data using secure passkeys.")

    col1, col2 = st.columns(2)
    col1.button("📂 Store Data", on_click=lambda: change_page("Store"))
    col2.button("🔍 Retrieve Data", on_click=lambda: change_page("Retrieve"))

    st.info(f"🔒 Stored Entries: {len(st.session_state.stored_data)}")

    with st.expander("🛠️ Options"):
        if st.button("🗑️ Clear All Data"):
            st.session_state.stored_data = {}
            st.success("All data cleared.")

        uploaded_json = st.file_uploader("📤 Restore Data (JSON)", type="json")
        if uploaded_json:
            try:
                data = json.load(uploaded_json)
                st.session_state.stored_data.update(data)
                st.success("Data restored successfully.")
            except:
                st.error("Invalid JSON file.")

        if st.button("💾 Download Encrypted Data"):
            st.download_button(
                label="📥 Download JSON",
                data=json.dumps(st.session_state.stored_data),
                file_name="encrypted_data.json",
                mime="application/json"
            )

def store_page():
    st.title("📂 Store New Data")

    data = st.text_area("Enter the data you want to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")
    confirm = st.text_input("Confirm passkey:", type="password")

    if st.button("Encrypt & Store"):
        if not data or not passkey or not confirm:
            st.error("All fields are required.")
        elif passkey != confirm:
            st.error("Passkeys do not match.")
        else:
            enc_text = encrypt_data(data, passkey)
            data_id = generate_data_id()
            st.session_state.stored_data[data_id] = {
                "encrypted_text": enc_text,
                "passkey": hash_passkey(passkey)
            }
            st.success("✅ Data stored securely.")
            st.code(data_id, language="text")
            st.info("Save this Data ID to retrieve your data later.")

    if st.button("🔙 Back to Home"):
        change_page("Home")

def retrieve_page():
    st.title("🔍 Retrieve Encrypted Data")

    attempts_left = 3 - st.session_state.failed_attempts
    if st.session_state.failed_attempts >= 3:
        st.warning("Too many incorrect attempts. Please login again.")
        change_page("Login")
        return

    data_id = st.text_input("Enter your Data ID:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if data_id in st.session_state.stored_data:
            decrypted = decrypt_data(st.session_state.stored_data[data_id]["encrypted_text"], passkey, data_id)
            if decrypted:
                st.success("✅ Decryption successful!")
                st.text_area("Decrypted Data", value=decrypted, height=150)
            else:
                st.error(f"Incorrect passkey. Attempts left: {attempts_left - 1}")
        else:
            st.error("❌ Data ID not found.")

    if st.button("🔙 Back to Home"):
        change_page("Home")

def login_page():
    st.title("🔑 Reauthentication Required")

    cooldown = 10 - int(time.time() - st.session_state.last_attempt_time)
    if cooldown > 0 and st.session_state.failed_attempts >= 3:
        st.warning(f"🕒 Wait {cooldown} seconds to retry.")
        return

    login_pass = st.text_input("Enter Master Password", type="password")
    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            reset_failed_attempts()
            st.success("✅ Login successful!")
            change_page("Home")
        else:
            st.error("❌ Incorrect password.")

# -------------------- MAIN ROUTER --------------------
pages = {
    "Home": home_page,
    "Store": store_page,
    "Retrieve": retrieve_page,
    "Login": login_page
}

pages[st.session_state.current_page]()
