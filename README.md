# Obligatorio Programación para DevOps Linux

Este repositorio contiene los ejercicios del obligatorio de Programación para DevOps Linux.

---

# Ejercicio 1 - Script de Creación de Usuarios

Script para crear múltiples usuarios en Linux desde un archivo de configuración.

## Requisitos

- Sistema operativo Linux (desarrollado y probado en Ubuntu 24.04 en WSL)
- Permisos de root (sudo)
- Bash shell
- Git

## Uso

```bash
sudo ./ej1_crea_usuarios.sh [-i] [-c contraseña] Archivo_con_los_usuarios_a_crear
```

### Opciones

- `-i`: Muestra información sobre la creación de cada usuario
- `-c contraseña`: Asigna la contraseña especificada a todos los usuarios creados
- `Archivo_con_los_usuarios_a_crear`: Archivo con la información de usuarios

## Formato del Archivo de Usuarios

El archivo debe contener un usuario por línea con el siguiente formato (campos separados por `:`):

```
usuario:comentario:directorio_home:crear_home(SI/NO):shell
```

### Campos

- **usuario**: Nombre del usuario a crear
- **comentario**: Comentario/descripción del usuario
- **directorio_home**: Directorio home del usuario
- **crear_home**: `SI` o `NO` para crear o no el directorio home
- **shell**: Shell por defecto (ej: /bin/bash, /bin/sh)

### Ejemplo de archivo

```
pepe:Este es mi amigo pepe:/home/jose:SI:/bin/bash
papanatas:Este es un usuario trucho:/trucho:NO:/bin/sh
elmaligno::::/bin/el_maligno
```

## Ejemplos de Uso

```bash
sudo ./ej1_crea_usuarios.sh Usuarios
sudo ./ej1_crea_usuarios.sh -c MiPassword123 Usuarios
sudo ./ej1_crea_usuarios.sh -i Usuarios
sudo ./ej1_crea_usuarios.sh -i -c MiPassword123 Usuarios
```

## Códigos de Retorno

- `1`: Archivo no existe
- `2`: Archivo no es un archivo regular
- `3`: Sin permisos de lectura para el archivo
- `4`: Error de sintaxis en el archivo
- `5`: Parámetro incorrecto
- `6`: Número incorrecto de parámetros
- `7`: Otros errores
- `0`: Éxito

---

# Ejercicio 2 - Script de Despliegue de Aplicación de Recursos Humanos

Script que automatiza el despliegue completo de una aplicación de recursos humanos en AWS. Crea todos los recursos necesarios (Security Group, RDS, S3, EC2) y despliega la aplicación automáticamente usando AWS Systems Manager (SSM) sin necesidad de SSH.

## Requisitos

- Sistema operativo Linux (desarrollado y probado en Ubuntu 24.04 en WSL)
- Git
- Python 3.7 o superior
- boto3
- Credenciales de AWS configuradas
- Directorio `obligatorio-main/obligatorio-main` con los archivos de la aplicación

## Instalación de requerimientos

```bash
sudo apt update #Descarga la lista de paquetes más reciente
sudo apt install git #Instala Git
sudo apt install -y python3-pip #Instala pip para Python 3
sudo apt install python3-boto3 #Instala boto3 para Python 3
aws configure #Para configurar la conexión con la CLI de AWS
```
## Ejecutar el script

```bash
python3 ej2_despliegue_rh.py
```

## Se mostrará al finalizar (cómo ejemplo)

```bash
Instancia EC2      : i-0abcd12345
IP pública EC2     : X.X.X.X
Instancia RDS      : RDS-Base-De-Datos
Endpoint RDS       : db-xxxxxxxx.rds.amazonaws.com

>>> URL de la aplicación
http://X.X.X.X/index.php
```

## Recursos Creados

1. **Security Group** (`SG-EC2`): Reglas para HTTP (80) y HTTPS (443)
2. **Security Group para conexión RDS-EC2** (`SG-RDS-RDS-Base-De-Datos`): Reglas para puerto 3306
3. **Instancia EC2** (`rh-app-web`): Servidor web con Apache, PHP y cliente MySQL
4. **Instancia RDS** (`rds-base-de-datos`): MySQL 8.0 con encriptación, acceso privado


## Características de Seguridad

- **RDS privado**: La base de datos no es accesible desde Internet
- **Despliegue sin SSH**: Usa AWS Systems Manager (SSM) en lugar de claves SSH
- **Encriptación**: RDS con encriptación en reposo habilitada

## Estructura del Proyecto

```
.
├── ej1_crea_usuarios.sh
├── ej2_despliegue_rh.py
├── obligatorio-main/
│   └── obligatorio-main/
│       ├── *.php, *.html, *.css, *.js  (archivos de la aplicación)
│       └── init_db.sql                 (script de inicialización de BD)
├── README.md
├── Usuarios
└── LICENSE
```

## Anexo - Prompts utilizados para la confección del código mediante la IA

## Ejercicio 1

Prompt 1 – Estructura de sctipt, diseño de opciones con case 

    Genera el estructura del script: 
    – Instale httpd, php, php-cli, php-fpm, php-common, php-mysqlnd y mariadb105, 
    – Habilite y arranque httpd y php-fpm, 
    – Configure la integración Apache + php-fpm 
    – Cree el archivo /var/www/html/info.php con phpinfo(). 

## Ejercicio 2

Prompt 1 – User Data para EC2 (Apache + PHP) 

    Genera contendido del user_data para una instancia AWS que haga lo siguiente: 
    – Instale httpd, php, php-cli, php-fpm, php-common, php-mysqlnd y mariadb105, 
    – Habilite y arranque httpd y php-fpm, 
    – Configure la integración Apache + php-fpm 
    – Cree el archivo /var/www/html/info.php con phpinfo(). 

Prompt 2 – Creación de EC2 y asociación de Security Group 

    “Ayudame a escribir en Python, usando boto3, la parte del script que: 
    – Cree una instancia EC2 t2.micro con la AMI ami-06b21ccaeff8cd686, 
    – Use el Instance Profile LabInstanceProfile, 
    – Asigne el user_data que ya tengo definido, 
    – Etiquete la instancia con Name = rh-app-web, 
    – Cree (o reutilice si ya existe) un Security Group llamado SG-EC2 en la VPC por defecto, 
    – Agregue la regla de entrada HTTP (puerto 80 desde 0.0.0.0/0) y permita salida HTTPS (puerto 443) para que SSM funcione, 
    – Y asocie ese Security Group nuevo a la instancia sin eliminar los que ya tenga.  

Prompt 3 – Manejo de RDS (existente o nueva) y contraseña 

    “Quiero que el script gestione una instancia RDS MySQL con identificador RDS-Base-De-Datos. 
    – Si la instancia ya existe, debe detectarlo con describe_db_instances, mostrar su estado y pedirme por consola la contraseña del admin usando getpass. 
    – Si no existe (capturando la excepción correspondiente), debe pedir la contraseña de admin por consola (validando que no esté vacía y que tenga al menos 8 caracteres), crear una instancia db.t3.micro de 20 GB, no pública, con DB_NAME = demo_db y DB_USERNAME = admin, 
    – Esperar a que la instancia esté disponible usando el waiter db_instance_available 
    – Y finalmente obtener el endpoint para usarlo luego en la configuración de la aplicación. 

Prompt 4 – Función auxiliar para ejecutar comandos SSM 

    “Necesito una función en Python que use SSM para ejecutar comandos en la instancia EC2. Llamala send_ssm_and_wait. Debe: 
    – Recibir el instance_id, una lista de comandos (idealmente un solo string grande con un script bash), un timeout y un comentario; 
    – Usar ssm.send_command con el documento AWS-RunShellScript; 
    – Hacer polling con get_command_invocation hasta que el comando termine (Success, Failed, Cancelled o TimedOut); 
    – Manejar los errores InvocationDoesNotExist y ThrottlingException con reintentos y backoff; 
    – Devolver una tupla (status, stdout, stderr). 
    Por favor agregá comentarios en español para explicar cada paso.” 

Prompt 5 – Script bash remoto para desplegar la app PHP 
 
    “Generá el contenido de un script bash (que yo después voy a interpolar como string en Python) que haga lo siguiente en la instancia EC2: 
    – Detectar la carpeta real descomprimida obligatorio-main* dentro de /home/ssm-user/app, 
    – Mover el contenido (incluyendo archivos ocultos) al directorio /var/www/html, 
    – Mover init_db.sql a /var/www/init_db.sql si existe, 
    – Eliminar README.md de /var/www/html si está, 
    – Crear un archivo /var/www/.env con las variables DB_HOST, DB_NAME, DB_USER, DB_PASS, APP_USER y APP_PASS, usando valores que yo voy a inyectar desde Python ({endpoint}, {DB_NAME}, {DB_USERNAME}, {DB_PASSWORD}, etc.), 
    – Asegurarse de que el cliente mysql esté instalado (vía dnf o yum), 
    – Ejecutar /var/www/init_db.sql contra la base RDS usando un archivo temporal de configuración. 
    – Ajustar permisos para que apache:apache sea dueño de /var/www/html y que /var/www/.env tenga permisos 600, 
    – Y al final reiniciar httpd y php-fpm, mostrando errores claros si algún reinicio falla. 

Prompt 6 – Mensajes finales del despliegue 
 
    “Ayudame a definir la salida final del script en Python. 
    – Debe obtener la IP pública de la instancia EC2 con describe_instances, 
    – Si no hay IP pública, mostrar un mensaje de error en español indicando que se verifique que la instancia tenga IP pública y esté en estado ‘running’, 
    – Si la hay, imprimir un bloque formateado que diga ‘DESPLIEGUE FINALIZADO CORRECTAMENTE’ y muestre: 
        • ID de la instancia EC2, 
        • IP pública de la EC2, 
        • Identificador de la instancia RDS, 
        • Endpoint de RDS, 
        • URL de la aplicación http://IP/index.php, 
 

## Licencia

Ver archivo `LICENSE` para más detalles.
