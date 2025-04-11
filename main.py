import streamlit as st 
import hashlib  #used to hash the password
import json #for save and load the data
import os
import time
from cryptography.fernet import Fernet # is used for generating text and key
from base64 import urlsafe_b64decode
from hashlib import pbkdf2_hmac

#  user data information
# secure data file in json formate
DATA_FILE = 'secure_data.json'
# used for password secure and hashing
SALT =b'secure_salt_value'
# use time module for user failed attempts and deplay
lockOutDuration = 60

# section login details
if 'authenticated_user' not in st.session_state:
    st.session_state.authenticated_user = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0

# if data is load
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE,'r') as f:
            return json.load(f)
    return {} 


# load and read data now write and saved data
def save_data(data):
    with open(DATA_FILE,'w') as f:
        json.dump(data,f) 

# now generate key 
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT,100000)
    return urlsafe_b64decode(key)

# now create hash password
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode() , SALT,100000).hex()

# secure text encrypting
# def encrypt_text(text, key):
#     cipher = Fernet(generate_key(key))
#     return cipher.encrypt(text.encode()).decode()
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()
# for decrypting text
def decrypt_text(encrypt_text,key):
    try:
        ciper = Fernet(generate_key(key))
        return ciper.decrypt(encrypt_text.encode()).decode()
    except:
        return None
    
# storing the data 
stored_data=load_data()


# Now display data on streamlit
st.title('🛡️ Secure Data Encryption System')
# creating menu bar
menu = ['Home','Registor','Login','Store Data', 'Retrieve Data']
choices = st.sidebar.selectbox('📋Navigation Menu Bar',menu)

if choices == 'Home':
    st.subheader('😄 Welcome to My Data Encryption Sytem!')
    st.caption(' >Develop a Streamlit-based secure data storage and retrieval ')

elif choices == 'Registor':
    username  =  st.text_input('Choose name:')
    password = st.text_input('Choose password:', type='password')

    if st.button('Registor'):
        if username in stored_data and password in stored_data:
            st.warning('⚠️User already exists.')
        else:
            stored_data[username] = {
                'password' : hash_password(password),
                'data':[]
            }
            save_data(stored_data)
            st.success('🌟User successfully registor!')
    else:
        st.error('⚠️ Both fields are requried!')
elif choices == "Login":
    st.subheader("🔑 User Login")
    
    # Lockout check
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + lockOutDuration
                st.error("🔒 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# stored data
elif choices == 'Store Data':
    if not st.session_state.authenticated_user:
        st.warning('🔐Please Login first')
    else:
        st.subheader('📦 Stored Encrypted Data')
        data = st.text_input('Enter data to encrypt')
        passkey = st.text_input('Encryption key(passphrase)', type='password')

        if st.button('Encrypt and save'):
            if data and passkey:
                encrypted =  encrypt_text(data,passkey)
                stored_data[st.session_state.authenticated_user]['data'].append(encrypted)
                save_data(stored_data)
                st.success('☑️ Data encrypted and save successfully! ')
            else:
                st.error('⚠️ All fields are requried!')
# data retieve section
elif choices == 'Retrieve Data':
    if not st.session_state.authenticated_user:
        st.warning('Please login first')
    else:
        st.subheader('🔎 Retieve Data')
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get('data', [])

        if not user_data:
            st.info('No Data found')
        else:
            st.write('Encrypted Data Enteries: ')
            for i, item in enumerate(user_data):
                st.code(item,language='text')

                encrypted_input = st.session_state('Enter Encrypted Text')
                passkey = st.text_input("Enter Passkey to Decrypt", type="password")

                if st.button('Decrypt'):
                    result = decrypt_text(encrypt_text,passkey)
                    if result:
                        st.success(f"✅ Decrypted: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")