# src/intel/mitre_connector.py
# Conector MITRE ATT&CK — lectura desde caché local JSON
# Threat Asset Correlator — Renato Cuellar

import json
import os
from dataclasses import dataclass, field


RUTA_ENTERPRISE = "data/mitre_enterprise.json"
RUTA_ICS = "data/mitre_ics.json"


@dataclass
class TecnicaATTACK:
    id: str
    nombre: str
    descripcion: str
    tacticas: list[str] = field(default_factory=list)
    plataformas: list[str] = field(default_factory=list)
    url: str = ""


class MITREConnector:
    def __init__(self):
        self._cache: dict[str, list[TecnicaATTACK]] = {}

    def _cargar_coleccion(self, ruta: str) -> list[TecnicaATTACK]:
        if ruta in self._cache:
            return self._cache[ruta]

        if not os.path.exists(ruta):
            return []

        with open(ruta, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        objetos = bundle.get("objects", [])
        tecnicas = []

        for obj in objetos:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False):
                continue
            if obj.get("revoked", False):
                continue

            tacticas = [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
            ]

            plataformas = obj.get("x_mitre_platforms", [])

            mitre_id = ""
            url = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break

            descripcion = obj.get("description", "")
            if len(descripcion) > 300:
                descripcion = descripcion[:300] + "..."

            tecnicas.append(TecnicaATTACK(
                id=mitre_id,
                nombre=obj.get("name", ""),
                descripcion=descripcion,
                tacticas=tacticas,
                plataformas=plataformas,
                url=url,
            ))

        self._cache[ruta] = tecnicas
        return tecnicas

    def buscar_por_keyword(
        self,
        keyword: str,
        coleccion: str = "enterprise"
    ) -> list[TecnicaATTACK]:
        ruta = RUTA_ICS if coleccion == "ics" else RUTA_ENTERPRISE
        tecnicas = self._cargar_coleccion(ruta)
        keyword_lower = keyword.lower()

        return [
            t for t in tecnicas
            if keyword_lower in t.nombre.lower()
            or keyword_lower in t.descripcion.lower()
        ]

    def buscar_por_software(
        self,
        software: str,
        coleccion: str = "enterprise"
    ) -> list[TecnicaATTACK]:
        keyword = software.split()[0].lower()
        return self.buscar_por_keyword(keyword, coleccion)