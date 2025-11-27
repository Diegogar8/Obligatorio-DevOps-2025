# Obligatorio Programación para DevOps Linux

Este repositorio contiene los ejercicios del obligatorio de Programación para DevOps Linux.

---

# Ejercicio 1 - Script de Creación de Usuarios

Este script permite crear múltiples usuarios en Linux desde un archivo de configuración.

## Requisitos

- Sistema operativo Linux
- Permisos de root (sudo)
- Bash shell

## Uso

```bash
sudo ./ej1_crea_usuarios.sh [-i] [-c contraseña] Archivo_con_los_usuarios_a_crear
```

### Opciones

- `-i`: Muestra información sobre la creación de cada usuario (opcional)
- `-c contraseña`: Asigna la contraseña especificada a todos los usuarios creados (opcional)
- `Archivo_con_los_usuarios_a_crear`: Archivo con la información de usuarios (obligatorio)

## Formato del Archivo de Usuarios

El archivo debe contener un usuario por línea con el siguiente formato (campos separados por `:`):

```
usuario:comentario:directorio_home:crear_home(SI/NO):shell
```

### Campos

- **usuario**: Nombre del usuario a crear (obligatorio)
- **comentario**: Comentario/descripción del usuario (puede estar vacío)
- **directorio_home**: Directorio home del usuario (puede estar vacío para usar el predeterminado)
- **crear_home**: `SI` o `NO` para crear o no el directorio home si no existe (puede estar vacío)
- **shell**: Shell por defecto (ej: /bin/bash, /bin/sh) (puede estar vacío para usar el predeterminado)

**Nota:** Si algún campo está vacío, el script usará los valores por defecto del comando `useradd`.

### Ejemplo de archivo

```
pepe:Este es mi amigo pepe:/home/jose:SI:/bin/bash
papanatas:Este es un usuario trucho:/trucho:NO:/bin/sh
elmaligno::::/bin/el_maligno
```

## Ejemplos de Uso

### Crear usuarios sin contraseña (modo silencioso)

```bash
sudo ./ej1_crea_usuarios.sh Usuarios
```

### Crear usuarios con contraseña

```bash
sudo ./ej1_crea_usuarios.sh -c MiPassword123 Usuarios
```

### Crear usuarios mostrando información detallada

```bash
sudo ./ej1_crea_usuarios.sh -i Usuarios
```

### Crear usuarios con contraseña y mostrar información

```bash
sudo ./ej1_crea_usuarios.sh -i -c MiPassword123 Usuarios
```

## Características

- ✅ Crea usuarios desde un archivo de configuración
- ✅ Permite especificar comentario, directorio home, crear home y shell
- ✅ Opción `-i` para mostrar información detallada de cada creación
- ✅ Opción `-c` para asignar la misma contraseña a todos los usuarios
- ✅ Valida que el script se ejecute como root
- ✅ Ignora usuarios que ya existen
- ✅ Ignora líneas vacías y comentarios (líneas que empiezan con `#`)
- ✅ Valida el formato del archivo (debe tener exactamente 5 campos separados por `:`)
- ✅ Manejo de errores con códigos de retorno específicos

## Salida del Script

### Con la opción `-i`

El script muestra:
- Estado de cada usuario procesado:
  - `Usuario 'nombre' (línea X): Creado exitosamente`
  - `Usuario 'nombre' (línea X): Ya existe, se omite`
  - `Usuario 'nombre' (línea X): ERROR - [descripción del error]`
- Resumen final:
  - `Total de usuarios creados exitosamente: X`

### Sin la opción `-i`

El script ejecuta silenciosamente, solo mostrando errores en stderr.

## Códigos de Retorno

El script utiliza códigos de retorno específicos para diferentes tipos de errores:

- `1`: Archivo no existe
- `2`: Archivo no es un archivo regular
- `3`: Sin permisos de lectura para el archivo
- `4`: Error de sintaxis en el archivo (línea sin exactamente 5 campos)
- `5`: Parámetro incorrecto (modificador inválido o `-c` sin contraseña)
- `6`: Número incorrecto de parámetros (falta el archivo o hay archivos duplicados)
- `7`: Otros errores (no se ejecuta como root, errores al crear usuarios, etc.)
- `0`: Éxito (todos los usuarios se procesaron correctamente)

## Validaciones

El script realiza las siguientes validaciones:

1. **Permisos**: Verifica que se ejecute como root
2. **Archivo**: Verifica que el archivo existe, es regular y tiene permisos de lectura
3. **Formato**: Valida que cada línea tenga exactamente 5 campos separados por `:`
4. **Usuario**: Verifica que el nombre de usuario no esté vacío
5. **Shell**: Verifica que el shell especificado exista (si se proporciona)

## Notas

- El script debe ejecutarse con permisos de root (usar `sudo`)
- Los usuarios que ya existen se omiten automáticamente
- Si se proporciona una contraseña con `-c`, se aplica a todos los usuarios creados
- Las líneas vacías y comentarios (que empiezan con `#`) se ignoran
- Si un campo está vacío, se usa el valor por defecto de `useradd`
- Los mensajes de error se envían a stderr
- El script termina con código de error si encuentra problemas de sintaxis o al crear usuarios

## Ejemplo Completo

Archivo `Usuarios`:
```
pepe:Este es mi amigo pepe:/home/jose:SI:/bin/bash
papanatas:Este es un usuario trucho:/trucho:NO:/bin/sh
elmaligno::::/bin/el_maligno
```

Ejecución:
```bash
sudo ./ej1_crea_usuarios.sh -i -c Password123 Usuarios
```

Salida esperada:
```
Usuario 'pepe' (línea 1): Creado exitosamente
Usuario 'papanatas' (línea 2): Creado exitosamente
Usuario 'elmaligno' (línea 3): Creado exitosamente

Total de usuarios creados exitosamente: 3
```

---

# Ejercicio 2 - Script de Despliegue de Aplicación de Recursos Humanos

Este script automatiza el despliegue de una aplicación de recursos humanos en AWS que maneja información sensible (nombres, emails y salarios de empleados actuales).

## Descripción del Proyecto

El script `ej2_despliegue_rh.py` automatiza la creación de la infraestructura necesaria para desplegar una aplicación de recursos humanos en AWS, incluyendo:

- **Instancia EC2**: Servidor web para la aplicación
- **Base de datos RDS**: Almacenamiento seguro de datos de empleados
- **Bucket S3**: Almacenamiento de backups encriptados
- **Security Groups**: Reglas de firewall restrictivas

## Requisitos

### Software
- Python 3.7 o superior
- boto3 (biblioteca de AWS SDK para Python)
- Credenciales de AWS configuradas

### Variables de Entorno

El script requiere las siguientes variables de entorno:

```bash
export RDS_ADMIN_PASSWORD='tu_password_seguro'
export AWS_ACCESS_KEY_ID='tu_access_key'
export AWS_SECRET_ACCESS_KEY='tu_secret_key'
```

### Instalación de Dependencias

```bash
pip install -r requirements.txt
```

O directamente:
```bash
pip install boto3
```

### Configuración Paso a Paso

#### Paso 1: Instalar Python y pip (si no están instalados)

En Linux/WSL:
```bash
sudo apt update
sudo apt install -y python3 python3-pip
```

Verificar instalación:
```bash
python3 --version
python3 -m pip --version
```

#### Paso 2: Instalar boto3

```bash
python3 -m pip install --user boto3
```

O desde requirements.txt:
```bash
python3 -m pip install --user -r requirements.txt
```

Verificar instalación:
```bash
python3 -c "import boto3; print('boto3 instalado:', boto3.__version__)"
```

#### Paso 3: Configurar credenciales de AWS

**Opción A: Variables de entorno (Recomendado)**

```bash
export AWS_ACCESS_KEY_ID='tu_access_key_id'
export AWS_SECRET_ACCESS_KEY='tu_secret_access_key'
export RDS_ADMIN_PASSWORD='tu_password_seguro'
```

**Para hacerlo permanente en Linux/WSL:**
```bash
echo 'export AWS_ACCESS_KEY_ID="tu_access_key_id"' >> ~/.bashrc
echo 'export AWS_SECRET_ACCESS_KEY="tu_secret_access_key"' >> ~/.bashrc
echo 'export RDS_ADMIN_PASSWORD="tu_password_seguro"' >> ~/.bashrc
source ~/.bashrc
```

**Opción B: Archivo de credenciales de AWS**

Crear `~/.aws/credentials`:
```bash
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = tu_access_key_id
aws_secret_access_key = tu_secret_access_key
EOF
```

Y opcionalmente `~/.aws/config`:
```bash
cat > ~/.aws/config << EOF
[default]
region = us-east-1
EOF
```

**⚠️ IMPORTANTE**: El script valida explícitamente las variables de entorno `AWS_ACCESS_KEY_ID` y `AWS_SECRET_ACCESS_KEY`, por lo que deben estar exportadas incluso si usas archivos de credenciales.

#### Paso 4: Verificar configuración

Verificar que las variables estén configuradas:
```bash
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
echo $RDS_ADMIN_PASSWORD
```

#### Paso 5: Configurar permisos IAM en AWS

Tu usuario/rol de AWS debe tener permisos para:
- **EC2**: `ec2:CreateSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:RunInstances`, `ec2:CreateTags`, `ec2:DescribeInstances`, `ec2:ModifyInstanceAttribute`
- **RDS**: `rds:CreateDBInstance`, `rds:DescribeDBInstances`, `rds:AddTagsToResource`
- **S3**: `s3:CreateBucket`, `s3:PutBucketEncryption`, `s3:PutBucketVersioning`, `s3:PutBucketTagging`, `s3:PutPublicAccessBlock`
- **IAM** (opcional): `iam:PassRole` si usas IAM Instance Profile

#### Paso 6: (Opcional) Personalizar configuración

```bash
cp config.example.json config.json
# Edita config.json con tus valores preferidos
```

**⚠️ IMPORTANTE**: El archivo `config.json` está en `.gitignore` para proteger información sensible. No lo subas al repositorio.

## Medidas de Seguridad Implementadas

El script implementa múltiples capas de seguridad para proteger la información sensible:

### 1. **Variables de Entorno para Credenciales**
   - Las contraseñas y claves de acceso nunca se almacenan en el código
   - Se validan al inicio del script

### 2. **Encriptación en Reposo**
   - Base de datos RDS con encriptación habilitada usando KMS
   - Bucket S3 con encriptación AES256

### 3. **Encriptación en Tránsito**
   - Security Group configurado para HTTPS (puerto 443)
   - Base de datos RDS sin acceso público

### 4. **Security Groups Restrictivos**
   - Solo permite tráfico HTTPS y SSH
   - En producción, se recomienda restringir a IPs específicas

### 5. **Backups Seguros**
   - Bucket S3 con versionado habilitado
   - Encriptación automática de backups
   - Acceso público bloqueado

### 6. **IAM Roles**
   - Uso de IAM Instance Profile con permisos mínimos necesarios
   - No se almacenan credenciales en la instancia

### 7. **Auditoría y Trazabilidad**
   - Todos los recursos se etiquetan para identificación
   - Logs de creación de recursos

## Modo de Uso

### Uso Básico (Configuración por Defecto)

```bash
python ej2_despliegue_rh.py
```

### Uso con Archivo de Configuración Personalizado

1. Copia el archivo de ejemplo:
```bash
cp config.example.json config.json
```

2. Edita `config.json` con tus valores:
```json
{
  "region": "us-east-1",
  "ami_id": "ami-06b21ccaeff8cd686",
  "instance_type": "t2.micro",
  "db_instance_class": "db.t3.micro",
  "db_allocated_storage": 20,
  "app_name": "app-rh-devops",
  "environment": "production"
}
```

3. Ejecuta el script:
```bash
python ej2_despliegue_rh.py --config config.json
```

### Ver Ayuda

```bash
python ej2_despliegue_rh.py --help
```

## Archivo de Configuración

El archivo de configuración (`config.json`) permite personalizar:

- **region**: Región de AWS donde desplegar (ej: `us-east-1`)
- **ami_id**: ID de la AMI a usar para la instancia EC2
- **instance_type**: Tipo de instancia EC2 (ej: `t2.micro`)
- **db_instance_class**: Clase de instancia RDS (ej: `db.t3.micro`)
- **db_allocated_storage**: Almacenamiento asignado a RDS en GB
- **app_name**: Nombre de la aplicación (usado para nombrar recursos)
- **environment**: Ambiente de despliegue (ej: `production`, `staging`)

**⚠️ IMPORTANTE**: El archivo `config.json` está en `.gitignore` para evitar subir configuraciones sensibles. Usa `config.example.json` como plantilla.

## Recursos Creados

El script crea los siguientes recursos en AWS:

1. **Security Group** (`{app_name}-sg`)
   - Reglas para HTTPS (443) y SSH (22)
   - Etiquetado para identificación

2. **Bucket S3** (`{app_name}-backups-{timestamp}`)
   - Encriptación AES256 habilitada
   - Versionado habilitado
   - Acceso público bloqueado

3. **Instancia EC2** (`{app_name}-web`)
   - Servidor web con Apache
   - Asociado al Security Group
   - IAM Instance Profile configurado
   - Script de inicialización automático

4. **Base de Datos RDS** (`{app_name}-db`)
   - MySQL 8.0
   - Encriptación en reposo habilitada
   - Acceso público deshabilitado
   - Retención de backups: 7 días

## Salida del Script

El script muestra el progreso del despliegue:

```
============================================================
INICIANDO DESPLIEGUE DE APLICACIÓN DE RECURSOS HUMANOS
============================================================
Región: us-east-1
Ambiente: production
Aplicación: app-rh-devops
============================================================

[1/4] Creando Security Group...
✓ Security Group creado: sg-xxxxxxxxxxxxx
✓ Reglas de seguridad configuradas para sg-xxxxxxxxxxxxx

[2/4] Creando bucket S3 para backups...
✓ Bucket S3 creado con encriptación: app-rh-devops-backups-1234567890

[3/4] Creando instancia EC2...
✓ Instancia EC2 creada: i-xxxxxxxxxxxxx
Esperando a que la instancia esté lista...
✓ Instancia i-xxxxxxxxxxxxx está en estado 'running'

[4/4] Creando base de datos RDS...
✓ Instancia RDS creada: app-rh-devops-db
  - Encriptación en reposo: Habilitada
  - Acceso público: Deshabilitado
  - Retención de backups: 7 días

============================================================
DESPLIEGUE COMPLETADO EXITOSAMENTE
============================================================

Recursos creados:
  - security_group: sg-xxxxxxxxxxxxx
  - s3_bucket: app-rh-devops-backups-1234567890
  - ec2_instance: i-xxxxxxxxxxxxx
  - rds_instance: app-rh-devops-db

⚠ IMPORTANTE - MEDIDAS DE SEGURIDAD:
  1. Cambiar las contraseñas por defecto
  2. Configurar certificados SSL para HTTPS
  3. Restringir Security Groups a IPs específicas en producción
  4. Habilitar CloudTrail para auditoría
  5. Configurar backups automáticos
  6. Revisar y ajustar políticas IAM
  7. No subir credenciales al repositorio Git
```

## Recomendaciones de Seguridad Adicionales

Después del despliegue, se recomienda:

1. **Configurar Certificados SSL**
   - Usar AWS Certificate Manager para certificados SSL
   - Configurar HTTPS en el servidor web

2. **Restringir Security Groups**
   - Limitar acceso SSH a IPs específicas
   - Limitar acceso HTTPS a rangos de IP conocidos

3. **Habilitar CloudTrail**
   - Activar logging de todas las acciones de AWS
   - Configurar alertas para actividades sospechosas

4. **Configurar Backups Automáticos**
   - Programar backups regulares de la base de datos
   - Almacenar backups en S3 con retención apropiada

5. **Revisar Políticas IAM**
   - Aplicar principio de menor privilegio
   - Revisar y ajustar permisos según necesidades

6. **Monitoreo y Alertas**
   - Configurar CloudWatch para monitoreo
   - Establecer alertas para eventos críticos

7. **Gestión de Secretos**
   - Usar AWS Secrets Manager para credenciales
   - Rotar contraseñas regularmente

## Control de Versiones con GitHub

Este proyecto está diseñado para ser versionado en GitHub con las siguientes prácticas:

### Estructura de Commits

- Commits descriptivos y frecuentes
- Mensajes de commit claros que explican los cambios
- Un commit por cambio lógico

### Uso de Branches

- `main` o `master`: Código estable y desplegado
- `develop`: Desarrollo activo
- `feature/*`: Nuevas funcionalidades
- `fix/*`: Correcciones de bugs

### Archivos Protegidos

El archivo `.gitignore` protege:
- Archivos de configuración con credenciales (`config.json`)
- Claves y certificados (`.key`, `.pem`, etc.)
- Variables de entorno (`.env`)
- Archivos temporales y caches

### Ejemplo de Flujo de Trabajo

```bash
# Crear branch para nueva funcionalidad
git checkout -b feature/mejora-seguridad

# Hacer cambios
# ... editar archivos ...

# Commit con mensaje descriptivo
git add .
git commit -m "Agregar validación de variables de entorno"

# Push al repositorio
git push origin feature/mejora-seguridad

# Crear Pull Request en GitHub
```

## Solución de Problemas

### Error: Variables de entorno no definidas

```
Error: Las siguientes variables de entorno deben estar definidas:
  - RDS_ADMIN_PASSWORD (Contraseña del administrador de RDS)
```

**Solución**: Define las variables de entorno antes de ejecutar el script:
```bash
export RDS_ADMIN_PASSWORD='tu_password'
export AWS_ACCESS_KEY_ID='tu_key'
export AWS_SECRET_ACCESS_KEY='tu_secret'
```

### Solución de Problemas Comunes

**Error: "boto3 no está instalado"**
```bash
python3 -m pip install --user boto3
```

**Error: "pip no está instalado"**
```bash
sudo apt install python3-pip
```

**Error: "NoCredentialsError" o "Access Denied"**
- Verifica que las credenciales de AWS sean correctas
- Verifica que el usuario IAM tenga los permisos necesarios
- Revisa que la región esté configurada correctamente

**Error: "Region not found"**
Verifica que la región en `config.json` o por defecto sea válida. Regiones comunes: `us-east-1`, `us-west-2`, `eu-west-1`

**Error: "AMI not found"**
El AMI `ami-06b21ccaeff8cd686` puede no estar disponible en tu región. Busca un AMI válido en la consola de AWS y actualiza `config.json`.

### Error: Security Group ya existe

El script detecta si el Security Group ya existe y continúa. Si necesitas recrearlo, elimínalo manualmente desde la consola de AWS.

### Error: Instancia RDS ya existe

Similar al Security Group, el script detecta instancias RDS existentes. Para recrear, elimina la instancia existente primero.

### Error: Permisos insuficientes

Asegúrate de que las credenciales de AWS tengan permisos para:
- Crear y gestionar instancias EC2
- Crear y gestionar instancias RDS
- Crear y gestionar buckets S3
- Crear y gestionar Security Groups
- Asociar IAM Instance Profiles

## Estructura del Proyecto

```
.
├── ej1_crea_usuarios.sh                    # Script del ejercicio 1
├── ej2_despliegue_rh.py                    # Script principal de despliegue (ejercicio 2)
├── config.example.json                     # Plantilla de configuración
├── requirements.txt                        # Dependencias de Python
├── .gitignore                              # Archivos a ignorar en Git
├── README.md                                # Este archivo
├── Usuarios                                 # Archivo de ejemplo para ejercicio 1
├── LICENSE                                  # Licencia del proyecto
└── Obligatorio Programación para DevOps Linux 09-10-2025.pdf  # PDF del obligatorio
```

## Códigos de Retorno

- `0`: Despliegue exitoso
- `1`: Error en la configuración o variables de entorno
- `2`: Error al crear recursos en AWS

## Notas Importantes

- ⚠️ **NUNCA** subas credenciales o archivos `config.json` al repositorio
- ⚠️ El script crea recursos que generan costos en AWS
- ⚠️ Asegúrate de eliminar los recursos cuando no los necesites
- ⚠️ En producción, restringe los Security Groups a IPs específicas
- ⚠️ Cambia todas las contraseñas por defecto después del despliegue

## Desarrollo y Consideraciones de Diseño

El script fue desarrollado siguiendo buenas prácticas de seguridad y automatización. Durante el desarrollo se consideraron los siguientes aspectos:

### Decisiones de Diseño

- **Modularidad**: El código está organizado en una clase principal (`DespliegueRH`) que encapsula toda la lógica de despliegue, facilitando el mantenimiento y la extensibilidad
- **Validación temprana**: Se validan las variables de entorno y configuración antes de intentar crear recursos, evitando fallos a mitad del despliegue
- **Manejo de errores**: Implementación robusta de manejo de excepciones con mensajes claros que ayudan a identificar problemas rápidamente
- **Reutilización de recursos**: El script detecta recursos existentes (Security Groups, instancias RDS) y los reutiliza en lugar de fallar, permitiendo ejecuciones múltiples sin conflictos
- **Documentación inline**: Código documentado con docstrings explicando cada función y método, facilitando la comprensión del código

### Proceso de Desarrollo

Durante el desarrollo se priorizaron los siguientes requisitos:

1. **Seguridad primero**: Implementar medidas de seguridad desde el inicio (encriptación, acceso restringido, variables de entorno)
2. **Automatización completa**: Minimizar la intervención manual durante el despliegue
3. **Compatibilidad con ejercicios previos**: Reutilizar patrones y conceptos aprendidos en ejercicios de boto3
4. **Documentación completa**: Asegurar que el proyecto incluya toda la documentación necesaria en el README
5. **Control de versiones**: Estructurar el proyecto para facilitar el uso de Git y GitHub con commits descriptivos y branches organizados

El diseño resultante prioriza la seguridad desde el inicio, implementando encriptación, acceso restringido y mejores prácticas de AWS desde el primer despliegue, mientras mantiene el código limpio y fácil de mantener.

## Referencias y Recursos Utilizados

### Documentación Oficial

- **AWS SDK for Python (Boto3)**: [Documentación oficial de boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- **AWS EC2**: [Documentación de EC2](https://docs.aws.amazon.com/ec2/)
- **AWS RDS**: [Documentación de RDS](https://docs.aws.amazon.com/rds/)
- **AWS S3**: [Documentación de S3](https://docs.aws.amazon.com/s3/)
- **AWS Security Groups**: [Documentación de Security Groups](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html)

### Recursos de Aprendizaje

- **Bash Scripting**: Conceptos de scripting en bash para automatización de tareas en Linux
- **Python boto3**: Patrones y mejores prácticas para interactuar con servicios de AWS mediante Python
- **AWS Best Practices**: Guías de seguridad y mejores prácticas para despliegues en AWS

### Consideraciones de Desarrollo

Durante el desarrollo de este proyecto se consideraron los siguientes aspectos técnicos:

1. **Arquitectura de Seguridad**: Se investigaron y aplicaron medidas de seguridad estándar de la industria para proteger información sensible, incluyendo encriptación en reposo y en tránsito, control de acceso mediante Security Groups, y gestión segura de credenciales mediante variables de entorno.

2. **Automatización con boto3**: Se estudiaron los patrones comunes de uso de boto3 para la creación y gestión de recursos AWS, incluyendo manejo de excepciones, reutilización de recursos existentes, y configuración de tags para trazabilidad.

3. **Buenas Prácticas de Código**: Se aplicaron principios de código limpio, incluyendo modularidad mediante clases, validación temprana de entradas, manejo robusto de errores, y documentación inline mediante docstrings.

4. **Control de Versiones**: Se estructuró el proyecto considerando las mejores prácticas de Git y GitHub, incluyendo uso de branches, commits descriptivos, y protección de información sensible mediante `.gitignore`.

5. **Documentación Completa**: Se priorizó la documentación exhaustiva en el README, incluyendo descripción del proyecto, requisitos detallados, modo de uso con ejemplos, solución de problemas, y referencias a recursos utilizados.

---

## Licencia

Ver archivo `LICENSE` para más detalles.
