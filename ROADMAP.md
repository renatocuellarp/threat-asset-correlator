# Roadmap — Threat Asset Correlator

*Horizonte: 12 meses | Dedicación: 6-10 horas semanales*  
*Actualizado: febrero 2026*

---

## Fase 1 — Diseño y arquitectura
**Meta:** Tener el sistema diseñado antes de escribir código  
**Estado:** 🔨 En curso

- [x] Definir problema y alcance
- [x] Diseñar arquitectura general
- [x] Documentar modelo de datos borrador
- [ ] Definir estructura de la base de datos SQLite
- [ ] Documentar formato de salida ISO 27001 / ANCI

---

## Fase 2 — Módulo de activos
**Meta:** Inventario funcional con clasificación y criticidad  
**Estado:** ⏳ Pendiente

- [ ] Modelo de datos de activos
- [ ] Carga manual (CSV / formulario)
- [ ] Clasificación por tipo y criticidad
- [ ] Visualización básica en Streamlit

---

## Fase 3 — Integraciones de inteligencia
**Meta:** Conectores funcionando con datos reales  
**Estado:** ⏳ Pendiente

- [ ] Conector NVD/CVE con filtro por producto/versión
- [ ] Conector OTX AlienVault (IoCs)
- [ ] Conector MITRE ATT&CK vía TAXII 2.1
- [ ] Normalización de datos entre fuentes

---

## Fase 4 — Motor de correlación
**Meta:** Scoring automático con trazabilidad técnica  
**Estado:** ⏳ Pendiente

- [ ] Algoritmo de correlación activo-amenaza
- [ ] Cálculo de probabilidad e impacto
- [ ] Justificación técnica por celda de matriz
- [ ] Matriz 5x5 dinámica

---

## Fase 5 — Dashboard
**Meta:** Interfaz usable para profesional de ciberseguridad  
**Estado:** ⏳ Pendiente

- [ ] Vista de matriz de riesgos interactiva
- [ ] Detalle por activo y por amenaza
- [ ] Filtros por criticidad y fuente
- [ ] Indicadores de tendencia

---

## Fase 6 — Exportación
**Meta:** Salidas compatibles con marcos regulatorios  
**Estado:** ⏳ Pendiente

- [ ] Exportación compatible con ISO 27001
- [ ] Formato de reporte para ANCI
- [ ] Versión ejecutiva de una página

---

## Notas

El roadmap se actualiza conforme avanza el proyecto. Las fases no son
estrictamente secuenciales — puede haber trabajo en paralelo entre
módulos cuando tenga sentido.

Los tiempos no están fijados deliberadamente: este proyecto se construye
con honestidad sobre el ritmo real de trabajo.
