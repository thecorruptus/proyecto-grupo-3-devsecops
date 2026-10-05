# Requerimientos de Seguridad de la Aplicación (ASR) - ISO/IEC 27034
**Proyecto:** CampusVirtual API (Caso 3 - EduTech)  
**Marco Normativo:** ISO/IEC 27034 Application Security Life Cycle  

---

## 1. Definición de ASR (Application Security Requirements)
Los ASR representan los requerimientos funcionales y no funcionales de seguridad técnica derivados del análisis de riesgos del negocio educativo para garantizar la confidencialidad, integridad y disponibilidad del sistema.

---

## 2. Requerimientos de Seguridad Especificados para el Caso 3

### ASR-01: Control de Acceso y Gestión de Privilegios
* **Requerimiento:** El sistema debe restringir las operaciones administrativas y de modificación de notas exclusivamente a usuarios con rol `admin` verificado en backend.
* **Criterio de Aceptación:** Cualquier solicitud que intente inyectar `role=admin` en el cuerpo de la petición sin un token legítimo debe ser rechazada con código HTTP 401 o 403.

### ASR-02: Integridad Criptográfica de Sesiones
* **Requerimiento:** Los tokens JWT deben firmarse con algoritmo HMAC-SHA256 utilizando secretos de alta entropía y tener un tiempo de vida útil limitado.
* **Criterio de Aceptación:** Expiración máxima obligatoria de 15 minutos en tokens estudiantiles y 60 minutos en docentes.

### ASR-03: Inmunidad ante Inyecciones (SQLi)
* **Requerimiento:** Ningún parámetro suministrado por el usuario debe concatenarse directamente en sentencias a la base de datos.
* **Criterio de Aceptación:** Uso de Prepared Statements parametrizados y validación previa del formato de RUT mediante expresión regular (`/^[0-9]{7,8}-[0-9kK]{1}$/`). Entradas anómalas deben responder con HTTP 400 Bad Request.

### ASR-04: Lógica de Negocio y Control Temporal
* **Requerimiento:** El sistema debe verificar en el servidor la validez de la ventana horaria de entrega de evaluaciones antes de procesar respuestas.
* **Criterio de Aceptación:** Si `currentTime > exam.end_time`, la entrega se rechaza automáticamente con HTTP 400.

### ASR-05: Reducción de Superficie de Exposición
* **Requerimiento:** Queda prohibida la exposición de rutas de diagnóstico con credenciales o configuraciones internas en producción.
* **Criterio de Aceptación:** La ruta `/debug/config` debe responder HTTP 404 y se eliminan cabeceras descriptivas como `X-Powered-By`.

### ASR-06: Gestión Segura de Credenciales Docentes
* **Requerimiento:** Las contraseñas en reposo deben protegerse con funciones de derivación de claves computacionalmente costosas.
* **Criterio de Aceptación:** Uso obligatorio de `bcrypt` con factor de trabajo (salt rounds) no menor a 10. Prohibido el uso de MD5 o SHA-1 sin sal.

### ASR-07: Sanitización de Salida contra XSS
* **Requerimiento:** Todos los datos provistos en foros o áreas públicas deben ser sanitizados previo a su persistencia.
* **Criterio de Aceptación:** Neutralización total de etiquetas `<script>` o eventos DOM maliciosos mediante codificación de entidades o filtrado estricto.

### ASR-08: Trazabilidad y Logging Forense
* **Requerimiento:** Se debe registrar de forma persistente cualquier anomalía o intento de acceso prematuro o no autorizado a evaluaciones.
* **Criterio de Aceptación:** Generación de eventos JSON estructurados en archivo persistente (`security-audit.log`) con IP, RUT, hora y descripción del evento.

### ASR-09: Aislamiento Perimetral y Mitigación de SSRF
* **Requerimiento:** Las funcionalidades de importación mediante URL externa no deben acceder a rangos de IP privadas, loopback ni servicios de metadatos de nube.
* **Criterio de Aceptación:** Solo se aceptan URLs con esquema `https:` pertenecientes a dominios aprobados en lista blanca institucional (`cdn.campusvirtual.cl`, `evaluaciones.inacap.cl`).