import streamlit as st
import requests
import os

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

def get_headers():
    token = st.session_state.get("token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}

def api_get(endpoint: str, timeout: int = 2, **kwargs):
    resp = requests.get(f"{API_URL}{endpoint}", headers=get_headers(), timeout=timeout, **kwargs)
    resp.raise_for_status()
    return resp

def api_post(endpoint: str, json: dict = None, data: dict = None, timeout: int = 2, **kwargs):
    resp = requests.post(f"{API_URL}{endpoint}", json=json, data=data, headers=get_headers(), timeout=timeout, **kwargs)
    resp.raise_for_status()
    return resp
