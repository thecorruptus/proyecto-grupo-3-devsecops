# Manifiesto Ético del Equipo DevSecOps
**Proyecto:** Blindaje y Aseguramiento de CampusVirtual API (Caso 3 - EduTech)  
**Estándar de Referencia:** Código de Ética ACM / IEEE y Principios de Responsabilidad Profesional  
**Equipo Consultor:** Grupo 3 DevSecOps  

---

## 1. Declaración de Responsabilidad Profesional
Como ingenieros y consultores de software, reconocemos que el desarrollo apresurado y la omisión deliberada de controles de seguridad constituyen una falta grave a la ética profesional. En una plataforma universitaria como **CampusVirtual**, el código fuente no solo gestiona datos digitales; custodia la trayectoria académica, el mérito estudiantil, el acceso a becas y la privacidad individual de miles de personas.

Entendemos que:
* **La omisión de validaciones no es un descuido técnico menor:** Es una negligencia que expone la fe pública de la institución académica.
* **La seguridad no es un parche posterior:** La seguridad debe concebirse desde el diseño de la arquitectura (Security by Design).

---

## 2. Principios Éticos Fundamentales Aplicados al Caso

### 2.1. Integridad y Veracidad Académica
* El sistema debe garantizar que las calificaciones obtenidas reflejen estrictamente el desempeño del alumno. Cualquier brecha que permita la alteración de notas (como la escalada de privilegios mediante manipulación de parámetros) destruye la confianza entre la institución y la comunidad.
* Toda transacción que modifique una evaluación o calificación debe ser trazable, inmutable y verificable.

### 2.2. Confidencialidad y Derecho a la Privacidad
* Los datos de profesores y estudiantes (identificadores nacionales como el RUT, credenciales de acceso e historiales) son información sensible.
* Almacenar contraseñas con algoritmos obsoletos (MD5) o exponer secretos del servidor en rutas de depuración vulnera directamente el derecho a la protección de datos personales.

### 2.3. Transparencia y Rendición de Cuentas (Accountability)
* Los incidentes de seguridad o accesos anómalos no pueden ser ignorados por conveniencia de rendimiento o rapidez de entrega.
* El equipo asume la obligación de registrar intentos de fraude o acceso fuera de horario para permitir auditorías forenses claras.

---

## 3. Compromiso de Mitigación y Buenas Prácticas
Nos comprometemos solemnemente a:
1. **No liberar código a producción** que no haya superado un análisis estricto de vulnerabilidades bajo los estándares de OWASP Top 10.
2. **Aplicar el principio de menor privilegio** en cada componente y capa del sistema.
3. **Priorizar la protección de los usuarios finales** por encima de los atajos de desarrollo o las presiones de tiempo.

---
### Firmado por el Equipo de Consultoría DevSecOps - Grupo 3:
* **Mathias Correa** — Lead DevSecOps / Auditoría y Mitigaciones
* **carlos acosta** — Oficial de Seguridad y Gobernanza ISO 27034  