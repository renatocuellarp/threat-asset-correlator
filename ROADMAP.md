# Roadmap — Threat Asset Correlator

*Horizonte: 12 meses | Dedicación: 6-10 horas semanales*  
*Actualizado: febrero 2026*

---

## Fase 1 — Diseño y arquitectura
**Meta:** Tener el sistema diseñado antes de escribir código  
**Estado:** ✅ Completado

- [x] Definir problema y alcance
- [x] Diseñar arquitectura general
- [x] Documentar modelo de datos
- [x] Documentar formato de salida compatible con metodología corporativa

---

## Fase 2 — Módulo de activos
**Meta:** Inventario funcional con clasificación y criticidad  
**Estado:** ✅ Completado

- [x] Modelo de datos de activos
- [x] Carga manual via formulario
- [x] Clasificación por tipo y criticidad
- [x] Visualización en Streamlit con filtros
- [x] Edición de activos existentes
- [x] Eliminación de activos con confirmación

---

## Fase 3 — Integraciones de inteligencia
**Meta:** Conectores funcionando con datos reales  
***Estado:** 🔨 En curso

- [x] Conector NVD/CVE con filtro por fecha (119 días)
- [x] Normalización de datos
- [ ] Conector OTX AlienVault (IoCs)
- [ ] Conector MITRE ATT&CK vía TAXII 2.1 — descarga local con caché JSON

---

## Fase 4 — Motor de correlación
**Meta:** Scoring automático con trazabilidad técnica  
**Estado:** ✅ Completado

- [x] Algoritmo de correlación activo-amenaza
- [x] Metodología corporativa de gestión de riesgos integrada
- [x] Escala de probabilidad e impacto de 4 niveles
- [x] Justificación técnica por celda de matriz
- [x] Mapa de calor dinámico con CVEs ubicados por celda
- [x] Exportación Excel — 3 hojas: resumen, correlaciones, justificación técnica
- [x] Exportación PDF — reporte estructurado con tablas y colores por nivel

---

## Fase 5 — Dashboard
**Meta:** Interfaz usable para profesional de ciberseguridad  
**Estado:** ✅ Completado

- [x] Vista de correlación con tabla coloreada por nivel de riesgo
- [x] Resumen visual por nivel (EXTREMO / ALTO / MODERADO / BAJO)
- [x] Detalle y justificación técnica por CVE
- [x] Tema oscuro con identidad visual consistente
- [x] Tarjetas de activo con etiquetas de software

---

## Fase 6 — Exportación
**Meta:** Salidas compatibles con marcos regulatorios  
**Estado:** ⏳ Pendiente

- [ ] Exportación compatible con ISO 27001
- [ ] Formato de reporte para ANCI
- [ ] Versión ejecutiva de una página

---

## Fase 7 — Mejoras para producción
**Meta:** Hacer la herramienta viable en entorno corporativo real  
**Estado:** 📋 Planificado

- [ ] Importación de activos desde CSV (integración con herramienta de inventario)
- [ ] Importación de activos y riesgos desde Excel
- [ ] Migración de base de datos JSON → SQLite o PostgreSQL
- [ ] Autenticación corporativa via Microsoft Entra ID (Azure AD) con MSAL
- [ ] Control de acceso por grupos de Azure AD
- [ ] Conector OTX AlienVault
- [ ] Conector MITRE ATT&CK vía TAXII 2.1

---

## Notas

El roadmap se actualiza conforme avanza el proyecto. Las fases no son
estrictamente secuenciales — puede haber trabajo en paralelo entre
módulos cuando tenga sentido.

Los tiempos no están fijados deliberadamente: este proyecto se construye
con honestidad sobre el ritmo real de trabajo.