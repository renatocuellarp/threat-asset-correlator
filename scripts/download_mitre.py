# scripts/download_mitre.py
# Descarga el bundle MITRE ATT&CK y lo guarda localmente
# Ejecutar una vez: python3 scripts/download_mitre.py
# Threat Asset Correlator — Renato Cuellar

import json
import os
import time
from taxii2client.v21 import Server

TAXII_URL = "https://attack-taxii.mitre.org/taxii2/"
ENTERPRISE_ID = "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
ICS_ID = "x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09"
DATA_DIR = "data"


def descargar_coleccion(coleccion, nombre: str, ruta: str):
    print(f"Descargando {nombre}...")
    bundle = coleccion.get_objects()
    objetos = bundle.get("objects", [])
    tecnicas = [o for o in objetos if o.get("type") == "attack-pattern"]

    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)

    print(f"  ✅ Guardado en {ruta}")
    print(f"  Total objetos: {len(objetos)} | Técnicas: {len(tecnicas)}")


def main():
    os.makedirs(DATA_DIR, exist_ok=True)

    print("Conectando a MITRE TAXII 2.1...")
    server = Server(TAXII_URL)
    api_root = server.api_roots[0]
    print(f"Conectado: {api_root.title}\n")

    colecciones = {c.id: c for c in api_root.collections}

    # Enterprise ATT&CK
    ruta_enterprise = os.path.join(DATA_DIR, "mitre_enterprise.json")
    if os.path.exists(ruta_enterprise):
        print(f"Enterprise ATT&CK ya existe en {ruta_enterprise}, omitiendo.")
    else:
        descargar_coleccion(
            colecciones[ENTERPRISE_ID],
            "Enterprise ATT&CK",
            ruta_enterprise
        )
        print("Esperando 10 segundos antes de la siguiente descarga...")
        time.sleep(10)

    # ICS ATT&CK
    ruta_ics = os.path.join(DATA_DIR, "mitre_ics.json")
    if os.path.exists(ruta_ics):
        print(f"ICS ATT&CK ya existe en {ruta_ics}, omitiendo.")
    else:
        descargar_coleccion(
            colecciones[ICS_ID],
            "ICS ATT&CK",
            ruta_ics
        )

    print("\nDescarga completada.")


if __name__ == "__main__":
    main()