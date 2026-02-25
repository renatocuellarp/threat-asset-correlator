# src/assets/repositorio.py
# Repositorio de activos con persistencia JSON
# Threat Asset Correlator — Renato Cuellar

import json
import os
from src.assets.modelo import Activo, TipoActivo, Criticidad


RUTA_DATOS = "data/activos.json"


class RepositorioActivos:
    def __init__(self, ruta: str = RUTA_DATOS):
        self.ruta = ruta
        os.makedirs(os.path.dirname(ruta), exist_ok=True)

    def cargar(self) -> list[Activo]:
        if not os.path.exists(self.ruta):
            return []
        with open(self.ruta, "r", encoding="utf-8") as f:
            datos = json.load(f)
        return [self._deserializar(d) for d in datos]

    def guardar(self, activos: list[Activo]) -> None:
        with open(self.ruta, "w", encoding="utf-8") as f:
            json.dump([self._serializar(a) for a in activos], f, indent=2, ensure_ascii=False)

    def agregar(self, activo: Activo) -> bool:
        activos = self.cargar()
        if any(a.id == activo.id for a in activos):
            return False
        activos.append(activo)
        self.guardar(activos)
        return True

    def actualizar(self, activo_actualizado: Activo) -> bool:
        activos = self.cargar()
        for i, a in enumerate(activos):
            if a.id == activo_actualizado.id:
                activos[i] = activo_actualizado
                self.guardar(activos)
                return True
        return False

    def eliminar(self, activo_id: str) -> bool:
        activos = self.cargar()
        nuevos = [a for a in activos if a.id != activo_id]
        if len(nuevos) == len(activos):
            return False
        self.guardar(nuevos)
        return True

    def buscar_por_id(self, activo_id: str) -> Activo | None:
        for a in self.cargar():
            if a.id == activo_id:
                return a
        return None

    def buscar_por_tipo(self, tipo: TipoActivo) -> list[Activo]:
        return [a for a in self.cargar() if a.tipo == tipo]

    def buscar_por_criticidad_minima(self, criticidad: Criticidad) -> list[Activo]:
        return [a for a in self.cargar() if a.criticidad.value >= criticidad.value]

    def _serializar(self, activo: Activo) -> dict:
        return {
            "id": activo.id,
            "nombre": activo.nombre,
            "tipo": activo.tipo.value,
            "criticidad": activo.criticidad.value,
            "propietario": activo.propietario,
            "descripcion": activo.descripcion,
            "software": activo.software,
            "fecha_registro": activo.fecha_registro,
        }

    def _deserializar(self, datos: dict) -> Activo:
        return Activo(
            id=datos["id"],
            nombre=datos["nombre"],
            tipo=TipoActivo(datos["tipo"]),
            criticidad=Criticidad(datos["criticidad"]),
            propietario=datos["propietario"],
            descripcion=datos.get("descripcion", ""),
            software=datos.get("software", []),
            fecha_registro=datos.get("fecha_registro", ""),
        )