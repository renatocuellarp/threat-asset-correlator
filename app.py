# app.py
# Punto de entrada — Threat Asset Correlator
# Renato Cuellar

import streamlit as st
from src.assets.vista import render_inventario

st.set_page_config(
    page_title="Threat Asset Correlator",
    page_icon="🛡️",
    layout="wide"
)

# Menú lateral
pagina = st.sidebar.selectbox(
    "Módulo",
    options=["Inventario de Activos"]
)

if pagina == "Inventario de Activos":
    render_inventario()