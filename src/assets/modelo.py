# src/assets/modelo.py
# Modelo de datos para inventario de activos
# Threat Asset Correlator — Renato Cuellar

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class TipoActivo(Enum):
    SERVIDOR = "servidor"
    RED = "red"
    APLICACION = "aplicacion"
    ENDPOINT = "endpoint"
    BASE_DATOS = "base_datos"
    OTRO = "otro"


class Criticidad(Enum):
    MUY_BAJA = 1
    BAJA = 2
    MEDIA = 3
    ALTA = 4
    CRITICA = 5


@dataclass
class Activo:
    nombre: str
    tipo: TipoActivo
    criticidad: Criticidad
    propietario: str
    descripcion: str = ""
    software: list[str] = field(default_factory=list)
    id: str = ""
    fecha_registro: str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d")
    )

    def __post_init__(self):
        if not self.id:
            # ID simple basado en nombre y fecha
            self.id = f"{self.nombre.lower().replace(' ', '-')}-{self.fecha_registro}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "nombre": self.nombre,
            "tipo": self.tipo.value,
            "criticidad": self.criticidad.value,
            "propietario": self.propietario,
            "descripcion": self.descripcion,
            "software": self.software,
            "fecha_registro": self.fecha_registro,
        }