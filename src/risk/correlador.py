# src/risk/correlador.py
# Motor de correlación activo-amenaza
# Threat Asset Correlator — Renato Cuellar

from dataclasses import dataclass
from src.assets.modelo import Activo, Criticidad
from src.intel.nvd_connector import CVE, NVDConnector


@dataclass
class ResultadoCorrelacion:
    activo: Activo
    cve: CVE
    probabilidad: int   # 1-5
    impacto: int        # 1-5
    score_total: int    # probabilidad * impacto
    justificacion: str

    def nivel_riesgo(self) -> str:
        if self.score_total >= 20:
            return "CRITICO"
        elif self.score_total >= 15:
            return "ALTO"
        elif self.score_total >= 10:
            return "MEDIO"
        elif self.score_total >= 5:
            return "BAJO"
        else:
            return "MUY BAJO"

    def to_dict(self) -> dict:
        return {
            "activo": self.activo.nombre,
            "criticidad_activo": self.activo.criticidad.name,
            "cve_id": self.cve.id,
            "severidad_cve": self.cve.severidad,
            "score_cvss": self.cve.score_cvss,
            "probabilidad": self.probabilidad,
            "impacto": self.impacto,
            "score_total": self.score_total,
            "nivel_riesgo": self.nivel_riesgo(),
            "justificacion": self.justificacion,
        }


class Correlador:
    def __init__(self):
        self.nvd = NVDConnector()

    def correlacionar_activo(self, activo: Activo) -> list[ResultadoCorrelacion]:
        resultados = []

        for software in activo.software:
            cves = self.nvd.buscar_por_activo(software)
            for cve in cves:
                probabilidad = self._calcular_probabilidad(cve)
                impacto = self._calcular_impacto(activo, cve)
                score = probabilidad * impacto
                justificacion = self._generar_justificacion(activo, cve, probabilidad, impacto)

                resultados.append(ResultadoCorrelacion(
                    activo=activo,
                    cve=cve,
                    probabilidad=probabilidad,
                    impacto=impacto,
                    score_total=score,
                    justificacion=justificacion,
                ))

        # Ordenar por score descendente
        return sorted(resultados, key=lambda r: r.score_total, reverse=True)

    def _calcular_probabilidad(self, cve: CVE) -> int:
        # Basado en score CVSS
        if cve.score_cvss >= 9.0:
            return 5
        elif cve.score_cvss >= 7.0:
            return 4
        elif cve.score_cvss >= 5.0:
            return 3
        elif cve.score_cvss >= 3.0:
            return 2
        else:
            return 1

    def _calcular_impacto(self, activo: Activo, cve: CVE) -> int:
        # Impacto base = criticidad del activo
        impacto = activo.criticidad.value

        # Ajuste por severidad del CVE
        if cve.severidad == "CRITICAL":
            impacto = min(5, impacto + 1)
        elif cve.severidad in ("MEDIA", "MEDIUM") and impacto > 1:
            impacto = max(1, impacto - 1)

        return impacto

    def _generar_justificacion(
        self, activo: Activo, cve: CVE, probabilidad: int, impacto: int
    ) -> str:
        return (
            f"Activo '{activo.nombre}' con criticidad {activo.criticidad.name} "
            f"expuesto a {cve.id} (CVSS {cve.score_cvss}, {cve.severidad}). "
            f"Probabilidad {probabilidad}/5 basada en score CVSS. "
            f"Impacto {impacto}/5 basado en criticidad del activo."
        )