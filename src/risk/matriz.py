# src/risk/matriz.py
# Matriz de riesgos 5x5 dinámica — Metodología Ultraport
# Threat Asset Correlator — Renato Cuellar

import streamlit as st
import pandas as pd
import streamlit.components.v1 as components
from src.risk.correlador import (
    ResultadoCorrelacion, Probabilidad, NivelImpacto,
    nivel_riesgo_label, nivel_riesgo_color
)


# Estructura de la matriz según metodología Ultraport
# Filas: Probabilidad (Extrema→Escasa), Columnas: Impacto (Insignificante→Severo)
MATRIZ_NIVELES = {
    (Probabilidad.EXTREMA, NivelImpacto.INSIGNIFICANTE): 4,
    (Probabilidad.EXTREMA, NivelImpacto.MENOR): 8,
    (Probabilidad.EXTREMA, NivelImpacto.CRITICO): 12,
    (Probabilidad.EXTREMA, NivelImpacto.SEVERO): 16,

    (Probabilidad.ALTA, NivelImpacto.INSIGNIFICANTE): 3,
    (Probabilidad.ALTA, NivelImpacto.MENOR): 6,
    (Probabilidad.ALTA, NivelImpacto.CRITICO): 9,
    (Probabilidad.ALTA, NivelImpacto.SEVERO): 12,

    (Probabilidad.MEDIA, NivelImpacto.INSIGNIFICANTE): 2,
    (Probabilidad.MEDIA, NivelImpacto.MENOR): 4,
    (Probabilidad.MEDIA, NivelImpacto.CRITICO): 6,
    (Probabilidad.MEDIA, NivelImpacto.SEVERO): 8,

    (Probabilidad.ESCASA, NivelImpacto.INSIGNIFICANTE): 1,
    (Probabilidad.ESCASA, NivelImpacto.MENOR): 2,
    (Probabilidad.ESCASA, NivelImpacto.CRITICO): 3,
    (Probabilidad.ESCASA, NivelImpacto.SEVERO): 4,
}


def render_matriz(resultados: list[ResultadoCorrelacion]):
    st.subheader("Mapa de Calor — Metodología Ultraport")

    impactos = [
        NivelImpacto.INSIGNIFICANTE,
        NivelImpacto.MENOR,
        NivelImpacto.CRITICO,
        NivelImpacto.SEVERO,
    ]
    probabilidades = [
        Probabilidad.EXTREMA,
        Probabilidad.ALTA,
        Probabilidad.MEDIA,
        Probabilidad.ESCASA,
    ]

    # Agrupar CVEs por celda
    cves_por_celda: dict[tuple, list] = {}
    for r in resultados:
        key = (r.probabilidad, r.impacto)
        if key not in cves_por_celda:
            cves_por_celda[key] = []
        cves_por_celda[key].append(r.cve.id)

    # Construir tabla HTML
    html = """
    <style>
        .matriz-table {
            border-collapse: collapse;
            width: 100%;
            font-family: monospace;
        }
        .matriz-table th {
            padding: 10px;
            text-align: center;
            font-size: 12px;
            color: #aaa;
        }
        .matriz-table td {
            border: 1px solid #333;
            padding: 10px;
            text-align: center;
            min-width: 120px;
            vertical-align: top;
            font-size: 11px;
        }
        .celda-label {
            font-size: 16px;
            font-weight: bold;
            color: white;
        }
        .celda-score {
            font-size: 11px;
            color: rgba(255,255,255,0.7);
            margin-top: 4px;
        }
        .celda-cves {
            font-size: 10px;
            color: rgba(255,255,255,0.9);
            margin-top: 6px;
        }
        .prob-label {
            font-size: 11px;
            font-weight: bold;
            color: #ccc;
            text-align: right;
            padding-right: 10px;
        }
    </style>
    <table class="matriz-table">
        <tr>
            <th></th>
    """

    # Headers de impacto
    for impacto in impactos:
        html += f"<th>{impacto.name}<br><small>({impacto.value})</small></th>"
    html += "</tr>"

    # Filas de probabilidad
    for prob in probabilidades:
        html += f"<tr><td class='prob-label'>{prob.name}<br><small>({prob.value})</small></td>"

        for impacto in impactos:
            score = MATRIZ_NIVELES[(prob, impacto)]
            nivel = nivel_riesgo_label(score)
            color = nivel_riesgo_color(nivel)
            cves = cves_por_celda.get((prob, impacto), [])

            cves_html = ""
            if cves:
                cves_html = "<div class='celda-cves'>" + "<br>".join(cves[:3])
                if len(cves) > 3:
                    cves_html += f"<br>+{len(cves)-3} más"
                cves_html += "</div>"

            html += f"""
            <td style='background-color:{color}'>
                <div class='celda-label'>{nivel}</div>
                <div class='celda-score'>Score: {score}</div>
                {cves_html}
            </td>
            """

        html += "</tr>"

    html += "</table>"

    st.components.v1.html(html, height=350, scrolling=True)

    # Leyenda
    st.markdown("---")
    cols = st.columns(4)
    for col, nivel in zip(cols, ["BAJO", "MODERADO", "ALTO", "EXTREMO"]):
        color = nivel_riesgo_color(nivel)
        col.markdown(
            f"<div style='background-color:{color}; padding:6px; "
            f"border-radius:4px; text-align:center; color:white; font-size:12px'>"
            f"{nivel}</div>",
            unsafe_allow_html=True
        )