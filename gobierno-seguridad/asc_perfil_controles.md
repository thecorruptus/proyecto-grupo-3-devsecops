# Perfil de Controles de Seguridad de la Aplicación (ASC)
**Estándar:** ISO/IEC 27034 (Application Security Controls) & OWASP Top 10  
**Objetivo:** Especificación técnica de controles defensivos aplicados a CampusVirtual API  

---

## Matriz de Controles ASC para CampusVirtual (Caso 3)

### ASC-01: Control de Acceso Basado en Roles (RBAC)
* **Riesgo Mitigado:** OWASP A01 (Broken Access Control) - Escalada de privilegios mediante `role=admin` en solicitudes POST.
* **Especificación:** El backend no debe confiar jamás en parámetros provenientes del cuerpo de la petición (`req.body`) o URLs para inferir roles. El rol se extrae exclusivamente del payload del JWT verificado con la clave secreta del servidor. Se rechaza cualquier modificación de notas ejecutada por usuarios con rol `student`.

### ASC-02: Robustez Criptográfica de Tokens
* **Riesgo Mitigado:** OWASP A02 (Cryptographic Failures) - JWT firmado con secreto trivial y sin caducidad.
* **Especificación:** El secreto de firma de JWT debe tener alta entropía (mínimo 256 bits) y gestionarse mediante variables de entorno seguras. La vigencia del token se limita estrictamente a 15 minutos (`expiresIn: '15m'`), requiriendo reautenticación o refresh tokens.

### ASC-03: Parametrización y Validación Estricta de Entradas
* **Riesgo Mitigado:** OWASP A03 (Injection) - Inyección SQL en filtro por parámetro `rut`.
* **Especificación:** Queda prohibida la concatenación de variables en sentencias SQL. Se implementan Prepared Statements con placeholders (`?`). Adicionalmente, el formato del RUT es validado con expresiones regulares (`^[0-9]+-[0-9kK]{1}$`) antes de llegar al motor de base de datos.

### ASC-04: Validación de Lógica Temporal de Negocio
* **Riesgo Mitigado:** OWASP A04 (Insecure Design) - Aceptación de exámenes fuera de horario.
* **Especificación:** El sistema evalúa en el servidor la condición de tiempo: si `currentTime > exam.end_time`, el sistema rechaza la recepción de respuestas con código HTTP 400.

### ASC-05: Eliminación de Superficie de Ataque y Hardening
* **Riesgo Mitigado:** OWASP A05 (Security Misconfiguration) - Exposición de `/debug/config` con variables de entorno.
* **Especificación:** Deshabilitación permanente de endpoints de depuración en entornos productivos. Implementación de middleware `helmet` para eliminar cabeceras descriptivas del servidor (como `X-Powered-By`) y activar protecciones de cabeceras HTTP.

### ASC-06: Gestión y Actualización Continua de Componentes
* **Riesgo Mitigado:** OWASP A06 (Vulnerable and Outdated Components) - Dependencias obsoletas con DoS.
* **Especificación:** Verificación y actualización de módulos mediante `npm audit`. Mantenimiento del stack en versiones estables y soportadas (LTS).

### ASC-07: Hashing Robusto de Credenciales
* **Riesgo Mitigado:** OWASP A07 (Identification and Authentication Failures) - Contraseñas con MD5 sin sal.
* **Especificación:** Reemplazo de MD5 por `bcrypt` implementando un factor de costo no inferior a 10 rondas de salado aleatorio (`bcrypt.hash(password, 10)`).

### ASC-08: Sanitización de Salida y Prevención de XSS
* **Riesgo Mitigado:** OWASP A08 (Software and Data Integrity Failures) - Inyección de scripts en foros estudiantiles.
* **Especificación:** Sanitización obligatoria de todo contenido suministrado por usuarios mediante la librería `xss` o codificación de entidades HTML previo a su almacenamiento y renderizado.

### ASC-09: Trazabilidad y Detección de Anomalías
* **Riesgo Mitigado:** OWASP A09 (Security Logging and Monitoring Failures) - Ausencia de registros ante accesos prematuros a evaluaciones.
* **Especificación:** Implementación del logger institucional `winston` para escribir registros persistentes en archivo (`security-audit.log`) con timestamp, IP de origen, identificador de usuario y tipo de evento ante intentos de acceso fuera de plazo.

### ASC-10: Mitigación de Solicitudes Forjadas del Lado del Servidor (SSRF)
* **Riesgo Mitigado:** OWASP A10 (Server-Side Request Forgery) - Importación de exámenes desde URLs arbitrarias.
* **Especificación:** Aplicación de lista blanca de dominios permitidos, restricción estricta al protocolo `https:`, y resolución DNS previa para denegar peticiones dirigidas a rangos de IP privadas (RFC 1918) o servicios de metadatos en la nube (`169.254.169.254`).