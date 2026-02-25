# src/risk/vista.py
# Vista de correlación y matriz de riesgos — Metodología corporativa de gestión de riesgos
# Threat Asset Correlator — Renato Cuellar

import streamlit as st
import pandas as pd
from datetime import datetime
from src.assets.repositorio import RepositorioActivos
from src.risk.correlador import Correlador, TipoRiesgo, nivel_riesgo_color
from src.risk.matriz import render_matriz
from src.exportacion.exportador import exportar_excel, exportar_pdf


def render_correlacion():
    st.markdown("""
        <style>
        .activo-card {
            background-color: #1a1d24;
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 8px;
            border-left: 4px solid #c0392b;
        }
        .activo-card h4 {
            margin: 0 0 4px 0;
            color: #aaa;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .activo-card p {
            margin: 0;
            font-size: 20px;
            font-weight: bold;
            color: #e0e0e0;
        }
        .software-tag {
            display: inline-block;
            background-color: #2a2d34;
            border-radius: 20px;
            padding: 3px 12px;
            margin: 3px;
            font-size: 12px;
            color: #aaa;
        }
        </style>
    """, unsafe_allow_html=True)

    st.title("🔍 Correlación de Amenazas")

    repo = RepositorioActivos()
    activos = repo.cargar()

    if not activos:
        st.warning("No hay activos registrados. Agrega activos primero.")
        return

    # ── Selector de activo y tipo de riesgo ──
    col1, col2 = st.columns(2)

    with col1:
        activo_nombres = {a.nombre: a for a in activos}
        seleccionado = st.selectbox(
            "Activo a analizar",
            options=list(activo_nombres.keys())
        )

    with col2:
        tipo_riesgo_opciones = {t.value: t for t in TipoRiesgo}
        tipo_seleccionado = st.selectbox(
            "Tipo de riesgo",
            options=list(tipo_riesgo_opciones.keys()),
            index=2
        )

    activo = activo_nombres[seleccionado]
    tipo_riesgo = tipo_riesgo_opciones[tipo_seleccionado]

    # ── Tarjetas del activo ──
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"""
            <div class='activo-card'>
                <h4>Tipo</h4>
                <p>{activo.tipo.value}</p>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div class='activo-card'>
                <h4>Criticidad</h4>
                <p>{activo.criticidad.name}</p>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
            <div class='activo-card'>
                <h4>Propietario</h4>
                <p>{activo.propietario}</p>
            </div>
        """, unsafe_allow_html=True)

    if activo.software:
        tags = "".join([f"<span class='software-tag'>{s}</span>" for s in activo.software])
        st.markdown(f"<div style='margin-top:8px'>{tags}</div>", unsafe_allow_html=True)

    st.divider()

    # ── Ejecutar correlación ──
    if st.button("🔍 Analizar amenazas", type="primary"):
        with st.spinner("Consultando NVD..."):
            correlador = Correlador()
            resultados = correlador.correlacionar_activo(activo, tipo_riesgo)

        if not resultados:
            st.info("No se encontraron CVEs recientes para este activo.")
            return

        st.success(f"{len(resultados)} correlaciones encontradas")

        # ── Resumen por nivel de riesgo ──
        st.subheader("Resumen")
        niveles = ["EXTREMO", "ALTO", "MODERADO", "BAJO"]
        cols = st.columns(4)
        conteos = {n: sum(1 for r in resultados if r.nivel_riesgo() == n) for n in niveles}

        for col, nivel in zip(cols, niveles):
            color = nivel_riesgo_color(nivel)
            col.markdown(
                f"<div style='background-color:{color}; padding:10px; "
                f"border-radius:8px; text-align:center; color:white;'>"
                f"<b>{nivel}</b><br><span style='font-size:24px'>{conteos[nivel]}</span>"
                f"</div>",
                unsafe_allow_html=True
            )

        st.divider()

        # ── Tabla de resultados ──
        st.subheader("Detalle de correlaciones")
        df = pd.DataFrame([r.to_dict() for r in resultados])

        def color_nivel(val):
            color = nivel_riesgo_color(val)
            return f"background-color: {color}; color: white"

        cols_mostrar = [
            "cve_id", "severidad_cve", "score_cvss",
            "probabilidad", "impacto", "score_total", "nivel_riesgo"
        ]

        df_mostrar = df[cols_mostrar].copy()
        df_mostrar["score_cvss"] = pd.to_numeric(
            df_mostrar["score_cvss"], errors="coerce"
        ).round(1)

        styled = df_mostrar.style.map(
            color_nivel, subset=["nivel_riesgo"]
        ).format({"score_cvss": "{:.1f}"})

        st.dataframe(styled, use_container_width=True, hide_index=True)

        # ── Justificación técnica ──
        st.subheader("Justificación técnica")
        for r in resultados[:5]:
            with st.expander(
                f"{r.cve.id} — {r.nivel_riesgo()} "
                f"(P:{r.probabilidad.value} × I:{r.impacto.value} = {r.score_total})"
            ):
                st.write(r.justificacion)
                st.caption(f"Publicado: {r.cve.fecha_publicacion}")
                st.caption(f"Descripción: {r.cve.descripcion}")

        # ── Matriz de calor ──
        st.divider()
        render_matriz(resultados)

        # ── Exportación ──
        st.divider()
        st.subheader("Exportar reporte")

        col1, col2 = st.columns(2)

        with col1:
            excel_bytes = exportar_excel(activo, resultados, tipo_riesgo)
            st.download_button(
                label="📥 Descargar Excel",
                data=excel_bytes,
                file_name=f"reporte_{activo.nombre.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )

        with col2:
            pdf_bytes = exportar_pdf(activo, resultados, tipo_riesgo)
            st.download_button(
                label="📄 Descargar PDF",
                data=pdf_bytes,
                file_name=f"reporte_{activo.nombre.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )