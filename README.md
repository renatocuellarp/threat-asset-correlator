# Threat Asset Correlator

**Plataforma de inteligencia de amenazas con correlación dinámica de activos**  
*Estado actual: Diseño y arquitectura — en desarrollo activo*

---

## El problema

Los sistemas de gestión de riesgos tradicionales tratan los activos y 
las amenazas como listas separadas. El resultado es una matriz de riesgos 
estática que envejece rápido y no refleja el panorama real de amenazas.

Este proyecto integra inteligencia de amenazas en tiempo real con el 
inventario de activos de la organización, generando una matriz de riesgos 
dinámica con trazabilidad técnica por cada celda.

Diseñado para operadores de infraestructura crítica en Chile bajo 
Ley 21.663, con salidas compatibles con ISO 27001:2022 y requerimientos ANCI.

---

## Arquitectura
```
Fuentes externas          Procesamiento              Salida
─────────────────         ──────────────             ──────
OTX AlienVault   ──┐
NVD / CVE        ──┼──► Motor de          ──► Matriz 5x5 dinámica
MITRE ATT&CK     ──┘    correlación       ──► Dashboard de riesgo
                              ▲            ──► Exportación ISO/ANCI
                              │
                    Inventario de activos
                    (criticidad + tipo)
```

## Módulos

**assets/** — Inventario de activos con clasificación por criticidad y tipo  
**intel/** — Conectores a OTX AlienVault, NVD/CVE y MITRE ATT&CK vía TAXII  
**risk/** — Motor de correlación y generación de matriz dinámica  

---

## Stack

Python · Streamlit · SQLite (prototipo) · APIs REST · TAXII 2.1

---

## Estado del proyecto

| Fase | Descripción | Estado |
|---|---|---|
| 1 — Diseño | Arquitectura, modelo de datos, decisiones técnicas | ✅ Completado |
| 2 — Assets | Módulo de inventario con clasificación | ✅ Completado |
| 3 — Intel | Integraciones OTX y NVD | 🔨 En curso |
| 4 — Correlación | Motor de scoring y matriz dinámica | ✅ Completado |
| 5 — UI | Dashboard Streamlit | ✅ Completado |
| 6 — Exportación | Salidas ISO 27001 / ANCI | ⏳ Pendiente |
| 7 — Producción | Importaciones, BD, autenticación corporativa | 📋 Planificado |

---

## Contexto regulatorio

Desarrollado con foco en el marco normativo chileno:
- **Ley 21.663** — Marco de ciberseguridad para operadores de 
  infraestructura crítica
- **ISO 27001:2022** — Sistema de gestión de seguridad de la información
- **ANCI** — Agencia Nacional de Ciberseguridad de Chile

---

## Notas de desarrollo

Este repositorio documenta el proceso completo de construcción, 
incluyendo decisiones de diseño, problemas encontrados y cambios 
de dirección. No solo el resultado final.

---

## Autor

Renato Cuellar · https://www.linkedin.com/in/renato-cuellar-pavez/ · Chile
