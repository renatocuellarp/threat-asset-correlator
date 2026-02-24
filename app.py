# app.py
# Punto de entrada — Threat Asset Correlator
# Renato Cuellar

import streamlit as st
from src.assets.vista import render_inventario
from src.risk.vista import render_correlacion

st.set_page_config(
    page_title="Threat Asset Correlator",
    page_icon="🛡️",
    layout="wide"
)

pagina = st.sidebar.selectbox(
    "Módulo",
    options=["Inventario de Activos", "Correlación de Amenazas"]
)

if pagina == "Inventario de Activos":
    render_inventario()
elif pagina == "Correlación de Amenazas":
    render_correlacion()