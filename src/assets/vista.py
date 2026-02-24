# src/assets/vista.py
# Interfaz Streamlit para gestión de activos
# Threat Asset Correlator — Renato Cuellar

import streamlit as st
from src.assets.modelo import Activo, TipoActivo, Criticidad
from src.assets.repositorio import RepositorioActivos
import pandas as pd


def render_inventario():
    st.title("Inventario de Activos")

    repo = RepositorioActivos()

    # ── Formulario para agregar activo ──
    with st.expander("➕ Agregar nuevo activo", expanded=False):
        with st.form("form_activo"):
            nombre = st.text_input("Nombre del activo")
            tipo = st.selectbox(
                "Tipo",
                options=[t.value for t in TipoActivo]
            )
            criticidad = st.selectbox(
                "Criticidad",
                options=[c.name for c in Criticidad],
                index=2  # MEDIA por defecto
            )
            propietario = st.text_input("Propietario")
            descripcion = st.text_area("Descripción", height=80)
            software_raw = st.text_input(
                "Software instalado (separado por comas)",
                placeholder="Apache 2.4.54, Ubuntu 22.04"
            )

            submitted = st.form_submit_button("Agregar activo")

            if submitted:
                if not nombre or not propietario:
                    st.error("Nombre y propietario son obligatorios.")
                else:
                    try:
                        software = [s.strip() for s in software_raw.split(",") if s.strip()]
                        activo = Activo(
                            nombre=nombre,
                            tipo=TipoActivo(tipo),
                            criticidad=Criticidad[criticidad],
                            propietario=propietario,
                            descripcion=descripcion,
                            software=software
                        )
                        repo.agregar(activo)
                        st.success(f"Activo '{nombre}' agregado correctamente.")
                        st.rerun()
                    except ValueError as e:
                        st.error(f"Error: {e}")

    # ── Filtros ──
    st.subheader("Activos registrados")
    activos = repo.cargar()

    if not activos:
        st.info("No hay activos registrados aún.")
        return

    col1, col2 = st.columns(2)
    with col1:
        filtro_tipo = st.selectbox(
            "Filtrar por tipo",
            options=["Todos"] + [t.value for t in TipoActivo]
        )
    with col2:
        filtro_criticidad = st.selectbox(
            "Criticidad mínima",
            options=["Todas"] + [c.name for c in Criticidad]
        )

    # Aplicar filtros
    if filtro_tipo != "Todos":
        activos = [a for a in activos if a.tipo.value == filtro_tipo]
    if filtro_criticidad != "Todas":
        minima = Criticidad[filtro_criticidad].value
        activos = [a for a in activos if a.criticidad.value >= minima]

    # ── Tabla ──
    if activos:
        df = pd.DataFrame([{
            "Nombre": a.nombre,
            "Tipo": a.tipo.value,
            "Criticidad": a.criticidad.name,
            "Propietario": a.propietario,
            "Software": ", ".join(a.software),
            "Registrado": a.fecha_registro
        } for a in activos])

        st.dataframe(df, use_container_width=True, hide_index=True)
        st.caption(f"{len(activos)} activo(s) encontrado(s)")
    else:
        st.info("No hay activos que coincidan con los filtros.")