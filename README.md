# Obligatorio Programación para DevOps Linux

Este repositorio contiene los ejercicios del obligatorio de Programación para DevOps Linux.

---

# Ejercicio 1 - Script de Creación de Usuarios

Script para crear múltiples usuarios en Linux desde un archivo de configuración.

## Requisitos

- Sistema operativo Linux (desarrollado y probado en Ubuntu en WSL)
- Permisos de root (sudo)
- Bash shell

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

Script que automatiza el despliegue de una aplicación de recursos humanos en AWS.

## Requisitos

- Python 3.7 o superior (desarrollado y probado en Ubuntu en WSL)
- boto3
- Credenciales de AWS configuradas

## Instalación

```bash
pip install boto3
```

## Configuración

Configurar variables de entorno:

```bash
export RDS_ADMIN_PASSWORD='tu_password_seguro'
export AWS_ACCESS_KEY_ID='tu_access_key'
export AWS_SECRET_ACCESS_KEY='tu_secret_key'
```

Para hacerlo permanente:

```bash
echo 'export AWS_ACCESS_KEY_ID="tu_access_key_id"' >> ~/.bashrc
echo 'export AWS_SECRET_ACCESS_KEY="tu_secret_access_key"' >> ~/.bashrc
echo 'export RDS_ADMIN_PASSWORD="tu_password_seguro"' >> ~/.bashrc
source ~/.bashrc
```

## Permisos IAM

El usuario/rol de AWS debe tener permisos para:
- EC2: `ec2:CreateSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:RunInstances`, `ec2:CreateTags`, `ec2:DescribeInstances`, `ec2:ModifyInstanceAttribute`
- RDS: `rds:CreateDBInstance`, `rds:DescribeDBInstances`, `rds:AddTagsToResource`
- S3: `s3:CreateBucket`, `s3:PutBucketEncryption`, `s3:PutBucketVersioning`, `s3:PutBucketTagging`, `s3:PutPublicAccessBlock`

## Uso

### Uso básico

```bash
python ej2_despliegue_rh.py
```

### Con archivo de configuración

```bash
cp config.example.json config.json
# Edita config.json
python ej2_despliegue_rh.py --config config.json
```

## Archivo de Configuración

El archivo `config.json` permite personalizar:

- **region**: Región de AWS (ej: `us-east-1`)
- **ami_id**: ID de la AMI para EC2
- **instance_type**: Tipo de instancia EC2 (ej: `t2.micro`)
- **db_instance_class**: Clase de instancia RDS (ej: `db.t3.micro`)
- **db_allocated_storage**: Almacenamiento RDS en GB
- **app_name**: Nombre de la aplicación
- **environment**: Ambiente (ej: `production`, `staging`)

## Recursos Creados

1. **Security Group**: Reglas para HTTPS (443) y SSH (22)
2. **Bucket S3**: Encriptación AES256, versionado habilitado
3. **Instancia EC2**: Servidor web con Apache
4. **Base de Datos RDS**: MySQL 8.0 con encriptación

## Solución de Problemas

**Error: Variables de entorno no definidas**

```bash
export RDS_ADMIN_PASSWORD='tu_password'
export AWS_ACCESS_KEY_ID='tu_key'
export AWS_SECRET_ACCESS_KEY='tu_secret'
```

**Error: "boto3 no está instalado"**

```bash
python3 -m pip install --user boto3
```

**Error: "NoCredentialsError" o "Access Denied"**

Verifica que las credenciales de AWS sean correctas y que el usuario IAM tenga los permisos necesarios.

**Error: "AMI not found"**

El AMI puede no estar disponible en tu región. Busca un AMI válido en la consola de AWS y actualiza `config.json`.

## Códigos de Retorno

- `0`: Despliegue exitoso
- `1`: Error en la configuración o variables de entorno
- `2`: Error al crear recursos en AWS

## Estructura del Proyecto

```
.
├── ej1_crea_usuarios.sh
├── ej2_despliegue_rh.py
├── config.example.json
├── requirements.txt
├── .gitignore
├── README.md
├── Usuarios
└── LICENSE
```

---

## Licencia

Ver archivo `LICENSE` para más detalles.
