# src/risk/correlador.py
# Motor de correlación activo-amenaza — Metodología corporativa de gestión de riesgos
# Threat Asset Correlator — Renato Cuellar

from dataclasses import dataclass
from enum import Enum
from src.assets.modelo import Activo, Criticidad
from src.intel.nvd_connector import CVE, NVDConnector


class TipoRiesgo(Enum):
    SALUD_SEGURIDAD = "Salud, Seguridad y Medio Ambiente"
    FINANCIERO = "Financiero Contable"
    EXCELENCIA_OPERACIONAL = "Excelencia Operacional"
    REPUTACIONAL = "Reputacional"
    LEGAL = "Legal y Cumplimiento"
    MEDIOS = "Atención a los Medios"


class Probabilidad(Enum):
    ESCASA = 1
    MEDIA = 2
    ALTA = 3
    EXTREMA = 4


class NivelImpacto(Enum):
    INSIGNIFICANTE = 1
    MENOR = 2
    CRITICO = 3
    SEVERO = 4


def nivel_riesgo_label(score: int) -> str:
    if score in (1, 2, 3):
        return "BAJO"
    elif score in (4, 6):
        return "MODERADO"
    elif score in (8, 9):
        return "ALTO"
    elif score in (12, 16):
        return "EXTREMO"
    else:
        if score <= 3:
            return "BAJO"
        elif score <= 6:
            return "MODERADO"
        elif score <= 9:
            return "ALTO"
        else:
            return "EXTREMO"


def nivel_riesgo_color(nivel: str) -> str:
    colores = {
        "BAJO": "#27ae60",
        "MODERADO": "#e67e22",
        "ALTO": "#c0392b",
        "EXTREMO": "#7f0000",
    }
    return colores.get(nivel, "#888888")


@dataclass
class ResultadoCorrelacion:
    activo: Activo
    cve: CVE
    tipo_riesgo: TipoRiesgo
    probabilidad: Probabilidad
    impacto: NivelImpacto
    justificacion: str

    @property
    def score_total(self) -> int:
        return self.probabilidad.value * self.impacto.value

    def nivel_riesgo(self) -> str:
        return nivel_riesgo_label(self.score_total)

    def to_dict(self) -> dict:
        return {
            "activo": self.activo.nombre,
            "criticidad_activo": self.activo.criticidad.name,
            "tipo_riesgo": self.tipo_riesgo.value,
            "cve_id": self.cve.id,
            "severidad_cve": self.cve.severidad,
            "score_cvss": self.cve.score_cvss,
            "probabilidad": self.probabilidad.name,
            "probabilidad_valor": self.probabilidad.value,
            "impacto": self.impacto.name,
            "impacto_valor": self.impacto.value,
            "score_total": self.score_total,
            "nivel_riesgo": self.nivel_riesgo(),
            "justificacion": self.justificacion,
        }


class Correlador:
    def __init__(self):
        self.nvd = NVDConnector()

    def correlacionar_activo(
        self,
        activo: Activo,
        tipo_riesgo: TipoRiesgo = TipoRiesgo.EXCELENCIA_OPERACIONAL
    ) -> list[ResultadoCorrelacion]:
        resultados = []

        for software in activo.software:
            cves = self.nvd.buscar_por_activo(software)
            for cve in cves:
                # Excluir CVEs sin score CVSS conocido
                if cve.score_cvss == 0.0:
                    continue

                probabilidad = self._calcular_probabilidad(cve)
                impacto = self._calcular_impacto(activo, cve, tipo_riesgo)
                justificacion = self._generar_justificacion(
                    activo, cve, probabilidad, impacto, tipo_riesgo
                )

                resultados.append(ResultadoCorrelacion(
                    activo=activo,
                    cve=cve,
                    tipo_riesgo=tipo_riesgo,
                    probabilidad=probabilidad,
                    impacto=impacto,
                    justificacion=justificacion,
                ))

        return sorted(resultados, key=lambda r: r.score_total, reverse=True)

    def _calcular_probabilidad(self, cve: CVE) -> Probabilidad:
        if cve.score_cvss >= 9.0:
            return Probabilidad.EXTREMA
        elif cve.score_cvss >= 7.0:
            return Probabilidad.ALTA
        elif cve.score_cvss >= 4.0:
            return Probabilidad.MEDIA
        else:
            return Probabilidad.ESCASA

    def _calcular_impacto(
        self,
        activo: Activo,
        cve: CVE,
        tipo_riesgo: TipoRiesgo
    ) -> NivelImpacto:
        mapa_criticidad = {
            Criticidad.MUY_BAJA: NivelImpacto.INSIGNIFICANTE,
            Criticidad.BAJA: NivelImpacto.INSIGNIFICANTE,
            Criticidad.MEDIA: NivelImpacto.MENOR,
            Criticidad.ALTA: NivelImpacto.CRITICO,
            Criticidad.CRITICA: NivelImpacto.SEVERO,
        }
        impacto = mapa_criticidad[activo.criticidad]

        if cve.severidad == "CRITICAL" and impacto.value < 4:
            impacto = NivelImpacto(min(4, impacto.value + 1))

        return impacto

    def _generar_justificacion(
        self,
        activo: Activo,
        cve: CVE,
        probabilidad: Probabilidad,
        impacto: NivelImpacto,
        tipo_riesgo: TipoRiesgo
    ) -> str:
        return (
            f"Tipo de riesgo: {tipo_riesgo.value}. "
            f"Activo '{activo.nombre}' con criticidad {activo.criticidad.name} "
            f"expuesto a {cve.id} (CVSS {cve.score_cvss}, {cve.severidad}). "
            f"Probabilidad {probabilidad.name} ({probabilidad.value}/4) "
            f"basada en score CVSS. "
            f"Impacto {impacto.name} ({impacto.value}/4) "
            f"basado en criticidad del activo según metodología corporativa."
        )