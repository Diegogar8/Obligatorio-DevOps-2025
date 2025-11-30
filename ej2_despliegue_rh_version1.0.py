#!/usr/bin/env python3

import boto3          # SDK de AWS para Python (para usar EC2, RDS, etc.)
import os             # Para leer variables de entorno del sistema
import sys            # Para salir con códigos de error y escribir en stderr
import time           # Para esperas y reintentos
from botocore.exceptions import ClientError  # Excepción específica de errores de AWS

# ---------------------------
# CONSTANTES DE CONFIGURACIÓN
# ---------------------------
REGION = 'us-east-1'                       # Región de AWS donde se desplegarán los recursos
AMI_ID = 'ami-06b21ccaeff8cd686'           # ID de la AMI utilizada para la instancia EC2
INSTANCE_TYPE = 't2.micro'                 # Tipo de instancia EC2
SG_EC2_NAME = 'rh-app-ec2-sg'              # Nombre del Security Group para EC2 (Web Server)
SG_RDS_NAME = 'rh-app-rds-sg'              # Nombre del Security Group para RDS (Base de datos)
DB_INSTANCE_ID = 'rh-app-db'               # Identificador de la instancia RDS
DB_NAME = 'demo_db'                        # Nombre de la base de datos que se creará en RDS
DB_USER = 'admin'                          # Usuario administrador de la base de datos
APP_NAME = 'rh-app-web'                    # Nombre que se usará como tag de la instancia EC2

# ---------------------------
# LECTURA DE VARIABLES DE ENTORNO
# ---------------------------
SG_EC2_ID_ENV = os.environ.get('SECURITY_GROUP_EC2_ID')  # Si está, se usará este Security Group para EC2
SG_RDS_ID_ENV = os.environ.get('SECURITY_GROUP_RDS_ID')  # Si está, se usará este Security Group para RDS
RDS_ENDPOINT_ENV = os.environ.get('RDS_ENDPOINT')        # Si está, se usará este endpoint de RDS ya existente
RDS_PASSWORD = os.environ.get('RDS_ADMIN_PASSWORD')      # Password del usuario admin de RDS

# Si no se definió la variable de entorno con la contraseña, el script no puede continuar
if not RDS_PASSWORD:
    print("Error: Debes definir la variable de entorno RDS_ADMIN_PASSWORD", file=sys.stderr)
    print("Ejemplo: export RDS_ADMIN_PASSWORD='tu_password_seguro'", file=sys.stderr)
    sys.exit(1)  # Sale con código de error 1

# ---------------------------
# CLIENTES DE AWS (EC2 y RDS)
# ---------------------------
ec2 = boto3.client('ec2', region_name=REGION)  # Cliente para interactuar con EC2
rds = boto3.client('rds', region_name=REGION)  # Cliente para interactuar con RDS

# Mensajes iniciales de log
print("=" * 60)
print("INICIANDO DESPLIEGUE DE APLICACIÓN DE RECURSOS HUMANOS")
print("Arquitectura: EC2 (Web Server + Apache) + RDS (MySQL)")
print("=" * 60)

# ---------------------------
# PASO 1: CREAR SECURITY GROUP PARA EC2 (WEB SERVER)
# ---------------------------
print("\n[1/5] Configurando Security Group para EC2 (Web Server)...")

sg_ec2_id = None  # Aquí se guardará el ID del Security Group de EC2

# Si el usuario definió un SECURITY_GROUP_EC2_ID por variable de entorno, se usa directamente
if SG_EC2_ID_ENV:
    sg_ec2_id = SG_EC2_ID_ENV
    print(f"✓ Usando Security Group EC2 especificado: {sg_ec2_id}")
else:
    # Si no hay SG especificado, se intenta crear uno nuevo
    try:
        # Obtener el VPC por defecto para asociar el Security Group
        vpc_response = ec2.describe_vpcs(Filters=[{'Name': 'is-default', 'Values': ['true']}])
        if vpc_response['Vpcs']:
            vpc_id = vpc_response['Vpcs'][0]['VpcId']
        else:
            # Si no hay VPC default, usar el primero disponible
            vpc_response = ec2.describe_vpcs()
            vpc_id = vpc_response['Vpcs'][0]['VpcId']
        
        response = ec2.create_security_group(
            GroupName=SG_EC2_NAME,
            Description='Security Group para EC2 Web Server - Permite HTTP desde Internet',
            VpcId=vpc_id
        )
        sg_ec2_id = response['GroupId']  # Guardamos el ID del SG recién creado
        print(f"✓ Security Group EC2 creado: {sg_ec2_id}")
        
        # Se agrega regla de entrada para HTTP (80) desde cualquier IP (expuesto a Internet)
        ec2.authorize_security_group_ingress(
            GroupId=sg_ec2_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP desde Internet'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH para administración'}]
                }
            ]
        )
        print(f"✓ Reglas de seguridad EC2 configuradas:")
        print(f"  - HTTP (puerto 80) abierto a Internet (0.0.0.0/0)")
        print(f"  - SSH (puerto 22) abierto para administración")
        
        # Agregar tags al Security Group
        ec2.create_tags(
            Resources=[sg_ec2_id],
            Tags=[
                {'Key': 'Name', 'Value': SG_EC2_NAME},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Web Server'}
            ]
        )
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        
        # Caso 1: El Security Group con ese nombre ya existe
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                response = ec2.describe_security_groups(GroupNames=[SG_EC2_NAME])
                sg_ec2_id = response['SecurityGroups'][0]['GroupId']
                print(f"⚠ Security Group EC2 ya existe: {sg_ec2_id}")
            except:
                pass
        
        # Caso 2: No tenemos permisos para crear/listar Security Groups
        elif 'UnauthorizedOperation' in str(e) or error_code == 'UnauthorizedOperation':
            print("⚠ No se tienen permisos para crear Security Groups")
            print("  Nota: Puedes especificar un Security Group ID con:")
            print("  export SECURITY_GROUP_EC2_ID='sg-xxxxxxxxxxxxx'")
            sg_ec2_id = None
        else:
            print(f"⚠ Error creando Security Group EC2: {e}")

if sg_ec2_id is None:
    print("✗ Error: No se pudo crear/obtener el Security Group para EC2", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 2: CREAR SECURITY GROUP PARA RDS (BASE DE DATOS)
# ---------------------------
print("\n[2/5] Configurando Security Group para RDS (Base de Datos)...")

sg_rds_id = None  # Aquí se guardará el ID del Security Group de RDS

# Si el usuario definió un SECURITY_GROUP_RDS_ID por variable de entorno, se usa directamente
if SG_RDS_ID_ENV:
    sg_rds_id = SG_RDS_ID_ENV
    print(f"✓ Usando Security Group RDS especificado: {sg_rds_id}")
else:
    try:
        # Obtener el VPC por defecto para asociar el Security Group
        vpc_response = ec2.describe_vpcs(Filters=[{'Name': 'is-default', 'Values': ['true']}])
        if vpc_response['Vpcs']:
            vpc_id = vpc_response['Vpcs'][0]['VpcId']
        else:
            vpc_response = ec2.describe_vpcs()
            vpc_id = vpc_response['Vpcs'][0]['VpcId']
        
        response = ec2.create_security_group(
            GroupName=SG_RDS_NAME,
            Description='Security Group para RDS - Solo permite MySQL desde EC2 Security Group',
            VpcId=vpc_id
        )
        sg_rds_id = response['GroupId']
        print(f"✓ Security Group RDS creado: {sg_rds_id}")
        
        # Se agrega regla de entrada para MySQL (3306) SOLO desde el Security Group de EC2
        # Esto asegura que solo la instancia EC2 pueda conectarse a la base de datos
        ec2.authorize_security_group_ingress(
            GroupId=sg_rds_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 3306,
                    'ToPort': 3306,
                    'UserIdGroupPairs': [
                        {
                            'GroupId': sg_ec2_id,
                            'Description': 'MySQL solo desde EC2 Web Server'
                        }
                    ]
                }
            ]
        )
        print(f"✓ Reglas de seguridad RDS configuradas:")
        print(f"  - MySQL (puerto 3306) solo accesible desde SG: {sg_ec2_id}")
        print(f"  - NO accesible directamente desde Internet")
        
        # Agregar tags al Security Group
        ec2.create_tags(
            Resources=[sg_rds_id],
            Tags=[
                {'Key': 'Name', 'Value': SG_RDS_NAME},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Database'}
            ]
        )
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                response = ec2.describe_security_groups(GroupNames=[SG_RDS_NAME])
                sg_rds_id = response['SecurityGroups'][0]['GroupId']
                print(f"⚠ Security Group RDS ya existe: {sg_rds_id}")
            except:
                pass
        
        elif 'UnauthorizedOperation' in str(e) or error_code == 'UnauthorizedOperation':
            print("⚠ No se tienen permisos para crear Security Groups")
            print("  Nota: Puedes especificar un Security Group ID con:")
            print("  export SECURITY_GROUP_RDS_ID='sg-xxxxxxxxxxxxx'")
            sg_rds_id = None
        else:
            print(f"⚠ Error creando Security Group RDS: {e}")

if sg_rds_id is None:
    print("✗ Error: No se pudo crear/obtener el Security Group para RDS", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 3: CONFIGURAR RDS CON SU SECURITY GROUP
# ---------------------------
print("\n[3/5] Configurando RDS (Base de Datos MySQL)...")

db_endpoint = None  # Aquí se guardará el endpoint de la base de datos

# Si el usuario dio un endpoint de RDS por variable de entorno, se usa directamente
if RDS_ENDPOINT_ENV:
    db_endpoint = RDS_ENDPOINT_ENV
    print(f"✓ Usando RDS endpoint especificado: {db_endpoint}")
else:
    try:
        rds.create_db_instance(
            DBInstanceIdentifier=DB_INSTANCE_ID,
            AllocatedStorage=20,
            DBInstanceClass='db.t3.micro',
            Engine='mysql',
            EngineVersion='8.0',
            MasterUsername=DB_USER,
            MasterUserPassword=RDS_PASSWORD,
            DBName=DB_NAME,
            VpcSecurityGroupIds=[sg_rds_id],  # Asociar el Security Group de RDS
            PubliclyAccessible=False,         # NO accesible desde Internet
            StorageEncrypted=True,            # Encriptación en reposo
            BackupRetentionPeriod=7,          # Retención de backups por 7 días
            Tags=[
                {'Key': 'Name', 'Value': DB_INSTANCE_ID},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Database'}
            ]
        )
        print(f"✓ Instancia RDS creada: {DB_INSTANCE_ID}")
        print(f"  - Security Group asociado: {sg_rds_id}")
        print(f"  - Encriptación en reposo: Habilitada")
        print(f"  - Acceso público: Deshabilitado")
        
        # Espera a que la instancia RDS cambie a estado 'available'
        print("  Esperando a que RDS esté disponible (esto puede tomar varios minutos)...")
        waiter = rds.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID, WaiterConfig={'Delay': 30, 'MaxAttempts': 40})
        
        # Una vez disponible, se obtiene su endpoint
        db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
        db_endpoint = db_response['DBInstances'][0]['Endpoint']['Address']
        print(f"✓ RDS disponible. Endpoint: {db_endpoint}")
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        
        if error_code == 'DBInstanceAlreadyExists':
            print(f"⚠ Instancia RDS {DB_INSTANCE_ID} ya existe")
            try:
                db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
                db_endpoint = db_response['DBInstances'][0]['Endpoint']['Address']
                print(f"✓ Endpoint de RDS: {db_endpoint}")
            except Exception as e2:
                print(f"⚠ No se pudo obtener el endpoint: {e2}")
                print("  Usa: export RDS_ENDPOINT='tu-endpoint.rds.amazonaws.com'")
        
        elif 'AccessDenied' in str(e) or error_code == 'AccessDenied':
            print("⚠ No se tienen permisos para crear RDS")
            print("  Nota: Puedes especificar un endpoint de RDS existente con:")
            print("  export RDS_ENDPOINT='tu-endpoint.rds.amazonaws.com'")
            db_endpoint = None
        else:
            print(f"⚠ Error con RDS: {e}")
            print("  Continuando sin RDS. Puedes especificar un endpoint con:")
            print("  export RDS_ENDPOINT='tu-endpoint.rds.amazonaws.com'")
            db_endpoint = None

# Si no se tiene un endpoint válido, se usa "localhost" como placeholder
if not db_endpoint:
    db_endpoint = "localhost"
    print(f"⚠ Usando placeholder para RDS endpoint. Configura manualmente después.")

# ---------------------------
# PASO 4: CREAR INSTANCIA EC2 (WEB SERVER CON APACHE)
# ---------------------------
print("\n[4/5] Creando instancia EC2 (Web Server con Apache)...")

# SCRIPT DE USER DATA PARA EC2
user_data = f'''#!/bin/bash
# ==============================================
# SCRIPT DE CONFIGURACIÓN DEL WEB SERVER
# Aplicación de Recursos Humanos
# ==============================================

# Actualizar el sistema
yum update -y

# Instalar Apache, PHP y cliente MySQL
yum install -y httpd php php-cli php-fpm php-common php-mysqlnd mariadb105

# Habilitar y arrancar servicios
systemctl enable --now httpd
systemctl enable --now php-fpm

# Configurar PHP-FPM para Apache
cat > /etc/httpd/conf.d/php-fpm.conf << 'EOFPHP'
<FilesMatch \\.php$>
  SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost/"
</FilesMatch>
EOFPHP

# Crear directorio para la aplicación
mkdir -p /var/www/html

# Crear archivo de configuración con variables de entorno
cat > /var/www/.env << EOFENV
DB_HOST={db_endpoint}
DB_NAME={DB_NAME}
DB_USER={DB_USER}
DB_PASS={RDS_PASSWORD}
APP_USER=admin
APP_PASS=admin123
EOFENV

# Configurar permisos seguros
chown -R apache:apache /var/www/html
chown apache:apache /var/www/.env
chmod 600 /var/www/.env

# Crear página principal de la aplicación
cat > /var/www/html/index.php << 'EOFINDEX'
<?php
echo "<h1>Aplicación de Recursos Humanos</h1>";
echo "<p>Web Server desplegado correctamente en EC2</p>";
echo "<p>Conexión a base de datos: RDS MySQL</p>";
echo "<p><strong>Nota:</strong> Los archivos de la aplicación deben subirse a /var/www/html</p>";
echo "<hr>";
echo "<p><a href='login.php'>Ir al login</a></p>";
?>
EOFINDEX

# Crear página de estado para verificar el despliegue
cat > /var/www/html/health.php << 'EOFHEALTH'
<?php
header('Content-Type: application/json');
$status = array(
    'status' => 'healthy',
    'server' => 'Apache',
    'php_version' => phpversion(),
    'timestamp' => date('Y-m-d H:i:s')
);
echo json_encode($status);
?>
EOFHEALTH

# Reiniciar servicios para aplicar configuración
systemctl restart httpd php-fpm

# Registrar estado del despliegue
echo "Despliegue completado - $(date)" > /var/www/html/status.txt
echo "EC2 Web Server configurado correctamente" >> /var/www/html/status.txt
'''

try:
    # Parámetros para crear la instancia EC2
    instance_params = {
        'ImageId': AMI_ID,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': INSTANCE_TYPE,
        'IamInstanceProfile': {'Name': 'LabInstanceProfile'},
        'UserData': user_data,
        'SecurityGroupIds': [sg_ec2_id],  # Security Group que permite HTTP
        'TagSpecifications': [
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': APP_NAME},
                    {'Key': 'Application', 'Value': 'Recursos Humanos'},
                    {'Key': 'Layer', 'Value': 'Web Server'}
                ]
            }
        ]
    }
    
    # Creación de la instancia EC2
    response = ec2.run_instances(**instance_params)
    instance_id = response['Instances'][0]['InstanceId']
    print(f"✓ Instancia EC2 creada: {instance_id}")
    print(f"  - Security Group asociado: {sg_ec2_id}")
    
    # ---------------------------
    # ESPERAR A QUE LA INSTANCIA ESTÉ EN ESTADO 'RUNNING'
    # ---------------------------
    print("\n[5/5] Esperando a que la instancia EC2 esté en estado 'running'...")
    
    # Usar el waiter de AWS para esperar al estado running
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(
        InstanceIds=[instance_id],
        WaiterConfig={
            'Delay': 5,        # Verificar cada 5 segundos
            'MaxAttempts': 60  # Máximo 60 intentos (5 minutos)
        }
    )
    
    print(f"✓ Instancia EC2 en estado 'running'")
    
    # Obtener información de la instancia
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance_info = response['Reservations'][0]['Instances'][0]
    public_ip = instance_info.get('PublicIpAddress', 'N/A')
    private_ip = instance_info.get('PrivateIpAddress', 'N/A')
    
    print(f"  - IP pública: {public_ip}")
    print(f"  - IP privada: {private_ip}")
    
    # Esperar un poco más para que los servicios internos arranquen
    print("\n  Esperando a que Apache y PHP inicien (30 segundos adicionales)...")
    time.sleep(30)
    print("✓ Servicios web deberían estar disponibles")
    
except ClientError as e:
    print(f"✗ Error creando instancia EC2: {e}", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# RESUMEN FINAL
# ---------------------------
print("\n" + "=" * 60)
print("DESPLIEGUE COMPLETADO EXITOSAMENTE")
print("=" * 60)

print("\n📊 ARQUITECTURA DESPLEGADA:")
print("-" * 40)
print("┌─────────────────────────────────────┐")
print("│           INTERNET                  │")
print("└───────────────┬─────────────────────┘")
print("                │ HTTP (80)")
print("                ▼")
print("┌─────────────────────────────────────┐")
print(f"│  EC2 Web Server (Apache + PHP)      │")
print(f"│  SG: {sg_ec2_id}            │")
print(f"│  IP: {public_ip:<27} │")
print("└───────────────┬─────────────────────┘")
print("                │ MySQL (3306)")
print("                ▼")
print("┌─────────────────────────────────────┐")
print(f"│  RDS MySQL Database                 │")
print(f"│  SG: {sg_rds_id}            │")
print(f"│  Endpoint: {db_endpoint[:25] if len(db_endpoint) > 25 else db_endpoint:<25} │")
print("└─────────────────────────────────────┘")

print("\n📋 RECURSOS CREADOS:")
print("-" * 40)
print(f"  Security Groups:")
print(f"    - EC2 (Web): {sg_ec2_id} → HTTP abierto a Internet")
print(f"    - RDS (DB):  {sg_rds_id} → MySQL solo desde EC2 SG")
print(f"  Instancias:")
print(f"    - EC2: {instance_id}")
print(f"    - RDS: {DB_INSTANCE_ID}")

print("\n🔒 SEGURIDAD IMPLEMENTADA:")
print("-" * 40)
print("  ✓ RDS no accesible desde Internet (PubliclyAccessible=False)")
print("  ✓ RDS solo acepta conexiones MySQL desde el Security Group de EC2")
print("  ✓ Encriptación de datos en reposo habilitada en RDS")
print("  ✓ Archivo .env con permisos 600 (solo lectura para Apache)")

print("\n⚠ PASOS SIGUIENTES:")
print("-" * 40)
if db_endpoint and db_endpoint != "localhost":
    print(f"  1. Sube los archivos de la aplicación a /var/www/html en la instancia EC2")
    print(f"  2. Conéctate a EC2 y ejecuta init_db.sql en RDS:")
    print(f"     ssh -i tu-key.pem ec2-user@{public_ip}")
    print(f"     mysql -h {db_endpoint} -u {DB_USER} -p < /var/www/init_db.sql")
    print(f"  3. Accede a la aplicación en: http://{public_ip}/")
    print(f"  4. Verifica el estado en: http://{public_ip}/health.php")
    print(f"  5. Usuario por defecto: admin / admin123")
    print(f"\n  ⚠ IMPORTANTE: Cambia las contraseñas por defecto en producción")
else:
    print(f"  1. Configura el endpoint de RDS en /var/www/.env en la instancia EC2")
    print(f"  2. Sube los archivos de la aplicación a /var/www/html en la instancia EC2")
    print(f"  3. Ejecuta init_db.sql en RDS desde la instancia EC2")
    print(f"  4. Accede a la aplicación en: http://{public_ip}/")
    print(f"  5. Usuario por defecto: admin / admin123")

print("\n" + "=" * 60)


