# Arquitectura — Threat Asset Correlator

*Documento vivo — se actualiza conforme avanza el desarrollo*  
*Última revisión: febrero 2025*

---

## Problema que resuelve

Una matriz de riesgos ISO 27001 tradicional se construye manualmente,
se desactualiza rápido y no tiene trazabilidad técnica. Cuando un
directivo pregunta "¿por qué este riesgo está en nivel alto?", la
respuesta suele ser una opinión, no evidencia.

Este sistema responde esa pregunta con datos: cada celda de la matriz
tiene detrás las vulnerabilidades, indicadores de compromiso y técnicas
ATT&CK que justifican el scoring.

---

## Decisiones de diseño

**¿Por qué Python + Streamlit?**  
Prototipado rápido con interfaz usable sin necesidad de frontend
separado. El objetivo inicial es validar la lógica de correlación,
no construir un producto final.

**¿Por qué SQLite en el prototipo?**  
Cero infraestructura, portable, suficiente para el volumen de datos
esperado en una organización mediana. Si el proyecto escala, migrar
a PostgreSQL es directo.

**¿Por qué tres fuentes de inteligencia?**  
- OTX AlienVault: IoCs en tiempo real, API gratuita con buena cobertura
- NVD/CVE: vulnerabilidades por producto/versión, esencial para 
  correlación con inventario de activos
- MITRE ATT&CK vía TAXII: técnicas y tácticas, contexto de cómo 
  se materializan las amenazas

---

## Modelo de datos (borrador)
```
Activo
├── id
├── nombre
├── tipo (servidor / red / aplicación / endpoint)
├── criticidad (1-5)
├── propietario
└── versiones_software[]

Amenaza
├── id
├── fuente (OTX / NVD / ATT&CK)
├── tipo (CVE / IoC / técnica)
├── severidad
├── fecha_publicacion
└── activos_afectados[]

CorrelacionRiesgo
├── activo_id
├── amenaza_id
├── probabilidad (1-5)
├── impacto (1-5)
├── score_total
├── justificacion_tecnica
└── fecha_calculo
```

---

## Flujo principal

1. El sistema obtiene el inventario de activos (manual o via import)
2. Para cada activo, consulta las tres fuentes de inteligencia
3. El motor de correlación calcula probabilidad e impacto con base 
   en criticidad del activo + severidad de la amenaza
4. Se genera la matriz 5x5 con trazabilidad por celda
5. El usuario puede exportar en formato compatible con ISO 27001 / ANCI

---

## Limitaciones conocidas

- El scoring automático es una aproximación — requiere revisión humana
- Las fuentes gratuitas tienen límites de rate en sus APIs
- La correlación activo-amenaza depende de la calidad del inventario
- No reemplaza un análisis de riesgo formal, lo complementa

---

## Lo que este sistema no es

No es un SIEM. No hace detección en tiempo real. No reemplaza un SOC.
Es una herramienta de apoyo a la gestión de riesgos, no de operaciones
de seguridad.
