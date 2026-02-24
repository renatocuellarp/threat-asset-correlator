# src/intel/nvd_connector.py
# Conector a NVD/CVE — National Vulnerability Database
# Threat Asset Correlator — Renato Cuellar

import requests
import time
from datetime import datetime, timedelta
from dataclasses import dataclass


@dataclass
class CVE:
    id: str
    descripcion: str
    severidad: str
    score_cvss: float
    fecha_publicacion: str
    software_afectado: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "descripcion": self.descripcion,
            "severidad": self.severidad,
            "score_cvss": self.score_cvss,
            "fecha_publicacion": self.fecha_publicacion,
            "software_afectado": self.software_afectado,
        }


class NVDConnector:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.headers = {"apiKey": api_key} if api_key else {}

    def buscar_por_keyword(
        self, keyword: str, max_resultados: int = 10, dias_atras: int = 119
    ) -> list[CVE]:
        fecha_fin = datetime.utcnow()
        fecha_inicio = fecha_fin - timedelta(days=dias_atras)

        try:
            url = (
                f"{self.BASE_URL}"
                f"?keywordSearch={keyword}"
                f"&resultsPerPage={max_resultados}"
                f"&pubStartDate={fecha_inicio.strftime('%Y-%m-%dT00:00:00.000')}"
                f"&pubEndDate={fecha_fin.strftime('%Y-%m-%dT23:59:59.999')}"
            )
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return self._parsear_respuesta(data, keyword)

        except requests.exceptions.Timeout:
            print(f"[NVD] Timeout consultando: {keyword}")
            return []
        except requests.exceptions.RequestException as e:
            print(f"[NVD] Error de conexión: {e}")
            return []

    def buscar_por_activo(self, nombre_software: str, dias_atras: int = 119) -> list[CVE]:
        keyword = nombre_software.split(" ")[0]
        time.sleep(0.6)  # Respetar rate limit NVD (sin API key: 5 req/30s)
        return self.buscar_por_keyword(keyword, dias_atras=dias_atras)

    def _parsear_respuesta(self, data: dict, software: str) -> list[CVE]:
        cves = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})

            descripciones = cve_data.get("descriptions", [])
            descripcion = next(
                (d["value"] for d in descripciones if d["lang"] == "en"),
                "Sin descripción"
            )

            severidad = "DESCONOCIDA"
            score = 0.0
            metricas = cve_data.get("metrics", {})

            if "cvssMetricV31" in metricas:
                m = metricas["cvssMetricV31"][0]["cvssData"]
                score = m.get("baseScore", 0.0)
                severidad = m.get("baseSeverity", "DESCONOCIDA")
            elif "cvssMetricV2" in metricas:
                m = metricas["cvssMetricV2"][0]["cvssData"]
                score = m.get("baseScore", 0.0)
                severidad = "MEDIA" if score >= 4.0 else "BAJA"

            cves.append(CVE(
                id=cve_data.get("id", ""),
                descripcion=descripcion[:300],
                severidad=severidad,
                score_cvss=score,
                fecha_publicacion=cve_data.get("published", "")[:10],
                software_afectado=software,
            ))

        return cves