# src/assets/repositorio.py
# Repositorio de activos — lectura y escritura en JSON
# Threat Asset Correlator — Renato Cuellar

import json
import os
from src.assets.modelo import Activo, TipoActivo, Criticidad


class RepositorioActivos:
    def __init__(self, ruta_archivo: str = "data/activos.json"):
        self.ruta_archivo = ruta_archivo
        self._asegurar_directorio()

    def _asegurar_directorio(self):
        directorio = os.path.dirname(self.ruta_archivo)
        if directorio and not os.path.exists(directorio):
            os.makedirs(directorio)

    def guardar(self, activos: list[Activo]) -> None:
        datos = [a.to_dict() for a in activos]
        with open(self.ruta_archivo, "w", encoding="utf-8") as f:
            json.dump(datos, f, ensure_ascii=False, indent=2)

    def cargar(self) -> list[Activo]:
        if not os.path.exists(self.ruta_archivo):
            return []
        with open(self.ruta_archivo, "r", encoding="utf-8") as f:
            datos = json.load(f)
        return [self._dict_a_activo(d) for d in datos]

    def agregar(self, activo: Activo) -> None:
        activos = self.cargar()
        # Evitar duplicados por ID
        if any(a.id == activo.id for a in activos):
            raise ValueError(f"Ya existe un activo con ID: {activo.id}")
        activos.append(activo)
        self.guardar(activos)

    def buscar_por_tipo(self, tipo: TipoActivo) -> list[Activo]:
        return [a for a in self.cargar() if a.tipo == tipo]

    def buscar_por_criticidad_minima(self, criticidad: Criticidad) -> list[Activo]:
        return [a for a in self.cargar() if a.criticidad.value >= criticidad.value]

    def _dict_a_activo(self, d: dict) -> Activo:
        return Activo(
            id=d["id"],
            nombre=d["nombre"],
            tipo=TipoActivo(d["tipo"]),
            criticidad=Criticidad(d["criticidad"]),
            propietario=d["propietario"],
            descripcion=d.get("descripcion", ""),
            software=d.get("software", []),
            fecha_registro=d["fecha_registro"],
        )