# src/assets/vista.py
# Vista de inventario de activos
# Threat Asset Correlator — Renato Cuellar

import streamlit as st
from src.assets.modelo import Activo, TipoActivo, Criticidad
from src.assets.repositorio import RepositorioActivos


def render_activos():
    st.title("🗂️ Inventario de Activos")

    repo = RepositorioActivos()

    tab1, tab2 = st.tabs(["📋 Inventario", "➕ Agregar activo"])

    with tab1:
        activos = repo.cargar()

        if not activos:
            st.info("No hay activos registrados. Agrega uno en la pestaña 'Agregar activo'.")
            return

        col1, col2 = st.columns(2)
        with col1:
            filtro_tipo = st.selectbox(
                "Filtrar por tipo",
                options=["Todos"] + [t.value for t in TipoActivo]
            )
        with col2:
            filtro_crit = st.selectbox(
                "Criticidad mínima",
                options=["Todas"] + [c.name for c in Criticidad]
            )

        filtrados = activos
        if filtro_tipo != "Todos":
            filtrados = [a for a in filtrados if a.tipo.value == filtro_tipo]
        if filtro_crit != "Todas":
            nivel = Criticidad[filtro_crit].value
            filtrados = [a for a in filtrados if a.criticidad.value >= nivel]

        st.markdown(f"**{len(filtrados)} activo(s) encontrado(s)**")
        st.divider()

        for activo in filtrados:
            with st.expander(
                f"**{activo.nombre}** — {activo.tipo.value} | "
                f"Criticidad: {activo.criticidad.name} | "
                f"Propietario: {activo.propietario}"
            ):
                if st.session_state.get(f"editando_{activo.id}"):
                    _render_formulario_edicion(activo, repo)
                else:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**ID:** `{activo.id}`")
                        st.markdown(f"**Tipo:** {activo.tipo.value}")
                        st.markdown(f"**Criticidad:** {activo.criticidad.name}")
                        st.markdown(f"**Propietario:** {activo.propietario}")
                    with col2:
                        st.markdown(f"**Fecha registro:** {activo.fecha_registro}")
                        if activo.descripcion:
                            st.markdown(f"**Descripción:** {activo.descripcion}")
                        if activo.software:
                            st.markdown(f"**Software:** {', '.join(activo.software)}")

                    col_edit, col_del, _ = st.columns([1, 1, 4])
                    with col_edit:
                        if st.button("✏️ Editar", key=f"btn_edit_{activo.id}"):
                            st.session_state[f"editando_{activo.id}"] = True
                            st.rerun()
                    with col_del:
                        if st.button("🗑️ Eliminar", key=f"btn_del_{activo.id}"):
                            st.session_state[f"confirmar_del_{activo.id}"] = True
                            st.rerun()

                    if st.session_state.get(f"confirmar_del_{activo.id}"):
                        st.warning(f"¿Eliminar **{activo.nombre}**? Esta acción no se puede deshacer.")
                        if st.button("✅ Confirmar eliminación", key=f"confirm_si_{activo.id}"):
                            repo.eliminar(activo.id)
                            st.session_state.pop(f"confirmar_del_{activo.id}", None)
                            st.success(f"Activo '{activo.nombre}' eliminado.")
                            st.rerun()
                        if st.button("❌ Cancelar eliminación", key=f"confirm_no_{activo.id}"):
                            st.session_state.pop(f"confirmar_del_{activo.id}", None)
                            st.rerun()

    with tab2:
        with st.form("form_agregar_activo", clear_on_submit=True):
            st.subheader("Nuevo activo")

            col1, col2 = st.columns(2)
            with col1:
                nombre = st.text_input("Nombre del activo *")
                tipo = st.selectbox("Tipo *", options=[t.value for t in TipoActivo])
                propietario = st.text_input("Propietario *")
            with col2:
                criticidad = st.selectbox("Criticidad *", options=[c.name for c in Criticidad])
                descripcion = st.text_area("Descripción", height=80)

            software_raw = st.text_input(
                "Software instalado",
                placeholder="Apache 2.4.54, Ubuntu 22.04, OpenSSL 3.0 (separados por coma)"
            )

            submitted = st.form_submit_button("➕ Agregar activo", type="primary", use_container_width=True)

            if submitted:
                if not nombre or not propietario:
                    st.error("Nombre y propietario son obligatorios.")
                else:
                    software_lista = [s.strip() for s in software_raw.split(",") if s.strip()]
                    nuevo = Activo(
                        nombre=nombre,
                        tipo=TipoActivo(tipo),
                        criticidad=Criticidad[criticidad],
                        propietario=propietario,
                        descripcion=descripcion,
                        software=software_lista,
                    )
                    if repo.agregar(nuevo):
                        st.success(f"Activo '{nombre}' agregado correctamente.")
                    else:
                        st.error("Ya existe un activo con ese ID.")


def _render_formulario_edicion(activo: Activo, repo: RepositorioActivos):
    st.subheader("Editar activo")

    with st.form(f"form_editar_{activo.id}"):
        col1, col2 = st.columns(2)
        with col1:
            nombre = st.text_input("Nombre", value=activo.nombre)
            tipo = st.selectbox(
                "Tipo",
                options=[t.value for t in TipoActivo],
                index=[t.value for t in TipoActivo].index(activo.tipo.value)
            )
            propietario = st.text_input("Propietario", value=activo.propietario)
        with col2:
            criticidad = st.selectbox(
                "Criticidad",
                options=[c.name for c in Criticidad],
                index=[c.name for c in Criticidad].index(activo.criticidad.name)
            )
            descripcion = st.text_area("Descripción", value=activo.descripcion, height=80)

        software_raw = st.text_input(
            "Software instalado",
            value=", ".join(activo.software)
        )

        guardar = st.form_submit_button("💾 Guardar cambios", type="primary", use_container_width=True)
        cancelar = st.form_submit_button("❌ Cancelar", use_container_width=True)

    if guardar:
        software_lista = [s.strip() for s in software_raw.split(",") if s.strip()]
        activo_actualizado = Activo(
            id=activo.id,
            nombre=nombre,
            tipo=TipoActivo(tipo),
            criticidad=Criticidad[criticidad],
            propietario=propietario,
            descripcion=descripcion,
            software=software_lista,
            fecha_registro=activo.fecha_registro,
        )
        repo.actualizar(activo_actualizado)
        st.session_state.pop(f"editando_{activo.id}", None)
        st.success("Activo actualizado correctamente.")
        st.rerun()

    if cancelar:
        st.session_state.pop(f"editando_{activo.id}", None)
        st.rerun()