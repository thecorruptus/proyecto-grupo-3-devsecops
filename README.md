# Evaluación 02: DevSecOps, Ética, ISO/IEC 27034 y OWASP Top 10
## Caso 3: EduTech — Plataforma de Exámenes y Calificaciones (CampusVirtual API)

### Información del Equipo de Consultoría
* **Institución:** INACAP
* **Asignatura:** Seguridad Aplicada / DevSecOps
* **Grupo:** Grupo 3 (2 Integrantes)

| Nombre Integrante | Rol en el Proyecto | Usuario GitHub |
| :--- | :--- | :--- |
| Mathias Correa | Lead DevSecOps / Auditoría y Mitigaciones | @thecorruptus |
| carlos acosta  | Oficial de Seguridad y Gobernanza ISO 27034 | @carlos-uiuqo9 |

---

## 1. Descripción del Proyecto
Este proyecto simula un escenario de consultoría de seguridad sobre la plataforma **CampusVirtual API** (EduTech), la cual presentaba múltiples fallos críticos derivados de un desarrollo apresurado.

Se aplicó una metodología integral dividida en:
1. **Gobernanza y Ética (ISO/IEC 27034):** Manifiesto ético, Marco Normativo Organizacional (ONF) y Controles de Seguridad de la Aplicación (ASC).
2. **Fase 1 - Auditoría Insegura:** Despliegue de API vulnerable en Node.js, ejecución de pentesting automatizado con `curl` y recolección de evidencias crudas (.txt).
3. **Fase 2 - Refactorización Defensiva:** Reescritura bajo el principio Zero Trust Input, control de roles estricto (RBAC), hashing Bcrypt, sanitización XSS, prevención de SSRF y logging centralizado con Winston.

---

## 2. Matriz de Controles OWASP Top 10 vs. Mitigación (Caso 3)

| Riesgo OWASP | Vulnerabilidad Inicial (Fase 1) | Mitigación Implementada (Fase 2) | Código Defensivo |
| :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | Modificación de notas mediante parámetro `role=admin` en el body. | Roles validados exclusivamente desde el JWT verificado en backend. | HTTP 401 / 403 |
| **A02: Cryptographic Failures** | JWT firmado con secreto trivial (`secret123`) sin expiración. | Secreto de alta entropía con caducidad estricta (`expiresIn: 15m`). | HTTP 200 (Token robusto) |
| **A03: Injection** | SQL Injection en parámetro de búsqueda por `rut`. | Prepared Statements con placeholders (`?`) y validación Regex de RUT. | HTTP 400 Bad Request |
| **A04: Insecure Design** | Aceptación de exámenes fuera del plazo límite. | Verificación de tiempo centralizada en backend (`currentTime > exam.end_time`). | HTTP 400 Bad Request |
| **A05: Security Misconfiguration** | Exposición de `/debug/config` con variables de entorno y cabeceras Express. | Endpoint eliminado permanentemente y hardening con `helmet`. | HTTP 404 Not Found |
| **A06: Vulnerable Components** | Servidor embebido con dependencias desactualizadas. | Actualización a Express estable y auditoría de paquetes con `npm audit`. | N/A |
| **A07: Identification Failures** | Contraseñas docentes almacenadas en MD5 sin sal. | Hashing robusto con `bcrypt` (factor de costo 10 y sal aleatoria). | HTTP 200 (Login seguro) |
| **A08: Software/Data Integrity** | Comentarios en foros vulnerables a Cross-Site Scripting (XSS). | Sanitización estricta de cadenas HTML mediante librería `xss`. | HTTP 201 (HTML neutralizado) |
| **A09: Security Logging Failures** | Sin registros ante intentos de apertura anticipada de exámenes. | Logging estructurado y persistente en `security-audit.log` con `winston`. | Evento en log verificado |
| **A10: SSRF** | Importación de exámenes desde URLs arbitrarias hacia red interna. | Lista blanca de dominios, protocolo HTTPS obligatorio y bloqueo de IPs privadas. | HTTP 400 / 403 |

---

## 3. Estructura del Repositorio (Docs-as-Code)
```text
proyecto-grupo-3-devsecops/
├── gobierno-seguridad/
│   ├── manifiesto_etico.md
│   ├── onf_marco_normativo.md
│   └── asc_perfil_controles.md
├── src/
│   ├── vulnerable/
│   │   ├── package.json
│   │   └── server.js
│   └── seguro/
│       ├── package.json
│       ├── server.js
│       └── security-audit.log
├── auditoria/
│   ├── fase1/
│   │   ├── script_auditoria_fase1.sh
│   │   └── evidencias/ (*.txt)
│   └── fase2/
│       ├── script_auditoria_fase2.sh
│       └── evidencias/ (*.txt)
├── .gitignore
└── README.md