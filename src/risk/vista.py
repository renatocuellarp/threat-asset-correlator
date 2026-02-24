# src/risk/vista.py
# Vista de correlación y matriz de riesgos
# Threat Asset Correlator — Renato Cuellar

import streamlit as st
import pandas as pd
from src.assets.repositorio import RepositorioActivos
from src.risk.correlador import Correlador


def render_correlacion():
    st.title("Correlación de Amenazas")

    repo = RepositorioActivos()
    activos = repo.cargar()

    if not activos:
        st.warning("No hay activos registrados. Agrega activos primero.")
        return

    # ── Selector de activo ──
    activo_nombres = {a.nombre: a for a in activos}
    seleccionado = st.selectbox(
        "Selecciona un activo para analizar",
        options=list(activo_nombres.keys())
    )

    activo = activo_nombres[seleccionado]

    col1, col2, col3 = st.columns(3)
    col1.metric("Tipo", activo.tipo.value)
    col2.metric("Criticidad", activo.criticidad.name)
    col3.metric("Propietario", activo.propietario)

    if activo.software:
        st.caption(f"Software: {', '.join(activo.software)}")

    st.divider()

    # ── Ejecutar correlación ──
    if st.button("🔍 Analizar amenazas", type="primary"):
        with st.spinner("Consultando NVD..."):
            correlador = Correlador()
            resultados = correlador.correlacionar_activo(activo)

        if not resultados:
            st.info("No se encontraron CVEs recientes para este activo.")
            return

        st.success(f"{len(resultados)} correlaciones encontradas")

        # ── Tabla de resultados ──
        df = pd.DataFrame([r.to_dict() for r in resultados])

        # Colorear nivel de riesgo
        def color_riesgo(val):
            colores = {
                "CRITICO": "background-color: #7f0000; color: white",
                "ALTO": "background-color: #c0392b; color: white",
                "MEDIO": "background-color: #e67e22; color: white",
                "BAJO": "background-color: #27ae60; color: white",
                "MUY BAJO": "background-color: #2ecc71; color: white",
            }
            return colores.get(val, "")

        styled = df[[
            "cve_id", "severidad_cve", "score_cvss",
            "probabilidad", "impacto", "score_total", "nivel_riesgo"
        ]].style.map(color_riesgo, subset=["nivel_riesgo"])

        st.dataframe(styled, use_container_width=True, hide_index=True)

        # ── Detalle por CVE ──
        st.subheader("Justificación técnica")
        for r in resultados[:5]:
            with st.expander(f"{r.cve.id} — {r.nivel_riesgo()} (Score {r.score_total})"):
                st.write(r.justificacion)
                st.caption(f"Publicado: {r.cve.fecha_publicacion}")
                st.caption(f"Descripción: {r.cve.descripcion}")