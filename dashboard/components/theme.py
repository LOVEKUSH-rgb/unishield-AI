import streamlit as st
import os

def inject_darktrace_theme():
    """Injects the custom Darktrace/Cyberpunk CSS theme into Streamlit."""
    css_path = os.path.join(os.path.dirname(__file__), "darktrace.css")
    if os.path.exists(css_path):
        with open(css_path, "r") as f:
            css = f.read()
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
    else:
        st.warning("Darktrace theme CSS not found!")
