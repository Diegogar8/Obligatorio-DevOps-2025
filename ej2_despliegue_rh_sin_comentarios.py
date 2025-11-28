#!/usr/bin/env python3

import boto3          # SDK de AWS para Python (para usar EC2, RDS, etc.)
import os             # Para leer variables de entorno del sistema
import sys            # Para salir con códigos de error y escribir en stderr
import time           # (no se usa directamente en el código, pero podría usarse para esperas)
from botocore.exceptions import ClientError  # Excepción específica de errores de AWS

# ---------------------------
# CONSTANTES DE CONFIGURACIÓN
# ---------------------------
REGION = 'us-east-1'                       # Región de AWS donde se desplegarán los recursos
AMI_ID = 'ami-06b21ccaeff8cd686'           # ID de la AMI utilizada para la instancia EC2
INSTANCE_TYPE = 't2.micro'                 # Tipo de instancia EC2
SG_NAME = 'rh-app-sg'                      # Nombre del Security Group para la app
DB_INSTANCE_ID = 'rh-app-db'               # Identificador de la instancia RDS
DB_NAME = 'demo_db'                        # Nombre de la base de datos que se creará en RDS
DB_USER = 'admin'                          # Usuario administrador de la base de datos
APP_NAME = 'rh-app-web'                    # Nombre que se usará como tag de la instancia EC2

# ---------------------------
# LECTURA DE VARIABLES DE ENTORNO
# ---------------------------
SG_ID_ENV = os.environ.get('SECURITY_GROUP_ID')  # Si está, se usará este Security Group ya creado
RDS_ENDPOINT_ENV = os.environ.get('RDS_ENDPOINT')  # Si está, se usará este endpoint de RDS ya existente

RDS_PASSWORD = os.environ.get('RDS_ADMIN_PASSWORD')  # Password del usuario admin de RDS

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
print("=" * 60)

print("\n[1/4] Configurando Security Group...")
sg_id = None  # Aquí se guardará el ID del Security Group a utilizar

# Si el usuario definió un SECURITY_GROUP_ID por variable de entorno, se usa directamente
if SG_ID_ENV:
    sg_id = SG_ID_ENV
    print(f"✓ Usando Security Group especificado: {sg_id}")
else:
    # Si no hay SG especificado, se intenta crear uno nuevo
    try:
        response = ec2.create_security_group(
            GroupName=SG_NAME,
            Description='Security Group para aplicación de RH - Permite HTTP, HTTPS y SSH'
        )
        sg_id = response['GroupId']  # Guardamos el ID del SG recién creado
        print(f"✓ Security Group creado: {sg_id}")
        
        # Se agregan reglas de entrada para HTTP (80), HTTPS (443) y SSH (22) desde cualquier IP
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH'}]
                }
            ]
        )
        print(f"✓ Reglas de seguridad configuradas")
        
    except ClientError as e:
        # Captura el código de error devuelto por AWS
        error_code = e.response.get('Error', {}).get('Code', '')
        
        # Caso 1: El Security Group con ese nombre ya existe
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                response = ec2.describe_security_groups(GroupNames=[SG_NAME])
                sg_id = response['SecurityGroups'][0]['GroupId']
                print(f"⚠ Security Group ya existe: {sg_id}")
            except:
                pass
        
        # Caso 2: No tenemos permisos para crear/listar Security Groups
        if 'UnauthorizedOperation' in str(e) or error_code == 'UnauthorizedOperation':
            print("⚠ No se tienen permisos para crear/listar Security Groups")
            print("⚠ Continuando sin especificar Security Group (usará el default de la VPC)")
            print("  Nota: Puedes especificar un Security Group ID con:")
            print("  export SECURITY_GROUP_ID='sg-xxxxxxxxxxxxx'")
            sg_id = None

# Si no se pudo determinar ningún SG, se avisa que se usará el default de la VPC
if sg_id is None:
    print("⚠ No se especificó Security Group - la instancia usará el default de la VPC")

print("\n[2/4] Configurando RDS...")
db_endpoint = None  # Aquí se guardará el endpoint de la base de datos

# Si el usuario dio un endpoint de RDS por variable de entorno, se usa directamente
if RDS_ENDPOINT_ENV:
    db_endpoint = RDS_ENDPOINT_ENV
    print(f"✓ Usando RDS endpoint especificado: {db_endpoint}")
else:
    # Si no hay endpoint especificado, el script intenta crear una nueva instancia RDS
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
            PubliclyAccessible=False,    # No accesible desde Internet
            StorageEncrypted=True,       # Encriptación en reposo
            BackupRetentionPeriod=7,     # Retención de backups por 7 días
            Tags=[
                {'Key': 'Name', 'Value': DB_INSTANCE_ID},
                {'Key': 'Application', 'Value': 'Recursos Humanos'}
            ]
        )
        print(f"✓ Instancia RDS creada: {DB_INSTANCE_ID}")
        print("  - Encriptación en reposo: Habilitada")
        print("  - Acceso público: Deshabilitado")
        
        # Espera a que la instancia RDS cambie a estado 'available'
        print("Esperando a que RDS esté disponible...")
        waiter = rds.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID, WaiterConfig={'Delay': 30, 'MaxAttempts': 40})
        
        # Una vez disponible, se obtiene su endpoint
        db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
        db_endpoint = db_response['DBInstances'][0]['Endpoint']['Address']
        print(f"✓ RDS disponible. Endpoint: {db_endpoint}")
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        
        # Caso 1: La instancia RDS ya existe
        if error_code == 'DBInstanceAlreadyExists':
            print(f"⚠ Instancia RDS {DB_INSTANCE_ID} ya existe")
            try:
                db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
                db_endpoint = db_response['DBInstances'][0]['Endpoint']['Address']
                print(f"✓ Endpoint de RDS: {db_endpoint}")
            except Exception as e2:
                print(f"⚠ No se pudo obtener el endpoint: {e2}")
                print("  Usa: export RDS_ENDPOINT='tu-endpoint.rds.amazonaws.com'")
        
        # Caso 2: No hay permisos para crear RDS
        elif 'AccessDenied' in str(e) or error_code == 'AccessDenied':
            print("⚠ No se tienen permisos para crear RDS")
            print("⚠ Continuando sin crear RDS")
            print("  Nota: Puedes especificar un endpoint de RDS existente con:")
            print("  export RDS_ENDPOINT='tu-endpoint.rds.amazonaws.com'")
            db_endpoint = None
        else:
            # Cualquier otro error genérico
            print(f"⚠ Error con RDS: {e}")
            print("  Continuando sin RDS. Puedes especificar un endpoint con:")
            print("  export RDS_ENDPOINT='tu-endpoint.rds.amazonaws.com'")
            db_endpoint = None

# Si a esta altura no se tiene un endpoint válido, se usa "localhost" como placeholder
if not db_endpoint:
    db_endpoint = "localhost"
    print(f"⚠ Usando placeholder para RDS endpoint. Configura manualmente después.")

# ---------------------------
# SCRIPT DE USER DATA PARA EC2
# ---------------------------
# Este string contiene un script bash que se ejecutará automáticamente al iniciar la instancia EC2
user_data = f'''#!/bin/bash
yum update -y

yum install -y httpd php php-cli php-fpm php-common php-mysqlnd mariadb105

systemctl enable --now httpd
systemctl enable --now php-fpm

cat > /etc/httpd/conf.d/php-fpm.conf << 'EOFPHP'
<FilesMatch \\.php$>
  SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost/"
</FilesMatch>
EOFPHP

mkdir -p /var/www/html

cat > /var/www/.env << EOFENV
DB_HOST={db_endpoint}
DB_NAME={DB_NAME}
DB_USER={DB_USER}
DB_PASS={RDS_PASSWORD}
APP_USER=admin
APP_PASS=admin123
EOFENV

chown -R apache:apache /var/www/html
chown apache:apache /var/www/.env
chmod 600 /var/www/.env

cat > /var/www/html/index.php << 'EOFINDEX'
<?php
echo "<h1>Aplicación de Recursos Humanos</h1>";
echo "<p>Desplegada correctamente</p>";
echo "<p>Nota: Los archivos de la aplicación deben subirse a /var/www/html</p>";
echo "<p><a href='login.php'>Ir al login</a></p>";
?>
EOFINDEX

systemctl restart httpd php-fpm

echo "Despliegue completado - $(date)" > /var/www/html/status.txt
'''

# En resumen, este user_data:
# - Actualiza el sistema
# - Instala Apache, PHP y cliente MariaDB
# - Habilita y arranca los servicios
# - Crea un archivo .env con variables de conexión a la BD y credenciales por defecto
# - Crea un index.php básico
# - Ajusta permisos de archivos

print("\n[3/4] Creando instancia EC2...")
try:
    # Parámetros para crear la instancia EC2
    instance_params = {
        'ImageId': AMI_ID,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': INSTANCE_TYPE,
        'IamInstanceProfile': {'Name': 'LabInstanceProfile'},  # Perfil de rol IAM asociado a la instancia
        'UserData': user_data,  # Script que se ejecuta al boot de la instancia
        'TagSpecifications': [
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': APP_NAME},
                    {'Key': 'Application', 'Value': 'Recursos Humanos'}
                ]
            }
        ]
    }
    
    # Si tenemos un Security Group, lo asociamos a la instancia
    if sg_id:
        instance_params['SecurityGroupIds'] = [sg_id]
    
    # Creación de la instancia EC2
    response = ec2.run_instances(**instance_params)
    instance_id = response['Instances'][0]['InstanceId']
    print(f"✓ Instancia EC2 creada: {instance_id}")
    
    # Se espera a que la instancia pase a estado 'running'
    print("Esperando a que la instancia esté lista...")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    
    # Una vez corriendo, se obtiene su IP pública
    response = ec2.describe_instances(InstanceIds=[instance_id])
    public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress', 'N/A')
    print(f"✓ Instancia en estado 'running'")
    print(f"  IP pública: {public_ip}")
    
except ClientError as e:
    # Si hay error creando la EC2, se imprime y se sale
    print(f"✗ Error creando instancia EC2: {e}", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# CONFIGURACIÓN DE ACCESO ENTRE EC2 Y RDS
# ---------------------------
# Solo tiene sentido si hay un endpoint real de RDS (no localhost)
if db_endpoint and db_endpoint != "localhost":
    print("\n[4/4] Configurando acceso de RDS desde EC2...")
    try:
        # Se obtiene la información de la instancia RDS
        db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
        # Se toma el Security Group asociado a RDS
        db_sg_id = db_response['DBInstances'][0]['VpcSecurityGroups'][0]['VpcSecurityGroupId'] if db_response['DBInstances'][0].get('VpcSecurityGroups') else None
        
        if db_sg_id and sg_id:
            try:
                # Se obtiene info del SG de la instancia EC2 (el que creamos antes)
                ec2_sg_response = ec2.describe_security_groups(GroupIds=[sg_id])
                ec2_sg_id = ec2_sg_response['SecurityGroups'][0]['GroupId']
                
                # Se construye un objeto SecurityGroup correspondiente al SG de RDS
                ec2_sg = boto3.resource('ec2', region_name=REGION).SecurityGroup(db_sg_id)
                try:
                    # Se agrega una regla de ingreso MySQL (3306) que permite tráfico desde el SG de la EC2
                    ec2_sg.authorize_ingress(
                        GroupId=db_sg_id,
                        IpPermissions=[
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 3306,
                                'ToPort': 3306,
                                'UserIdGroupPairs': [{'GroupId': ec2_sg_id}]
                            }
                        ]
                    )
                    print(f"✓ Acceso MySQL configurado desde EC2")
                except ClientError as e:
                    # Si la regla ya existe, se avisa en lugar de fallar
                    if 'InvalidPermission.Duplicate' in str(e):
                        print(f"⚠ Regla de acceso ya existe")
                    else:
                        print(f"⚠ No se pudo configurar acceso: {e}")
            except Exception as e:
                print(f"⚠ No se pudo configurar acceso RDS: {e}")
        else:
            print("⚠ No se pudo configurar acceso RDS (falta información)")
    except Exception as e:
        print(f"⚠ No se pudo configurar acceso RDS: {e}")
else:
    # Si no hay RDS real, se salta esta parte
    print("\n[4/4] Saltando configuración de acceso RDS (no hay RDS configurado)")

# ---------------------------
# RESUMEN FINAL
# ---------------------------
print("\n" + "=" * 60)
print("DESPLIEGUE COMPLETADO")
print("=" * 60)
print(f"\nRecursos creados:")
print(f"  - Security Group: {sg_id}")
print(f"  - Instancia RDS: {DB_INSTANCE_ID}")
print(f"  - Instancia EC2: {instance_id}")
print(f"  - IP pública EC2: {public_ip}")

print(f"\n⚠ IMPORTANTE:")
# Instrucciones finales dependen de si se configuró RDS real o solo placeholder
if db_endpoint and db_endpoint != "localhost":
    print(f"  1. Sube los archivos de la aplicación a /var/www/html en la instancia EC2")
    print(f"  2. Ejecuta init_db.sql en RDS desde la instancia EC2:")
    print(f"     mysql -h {db_endpoint} -u {DB_USER} -p{RDS_PASSWORD} {DB_NAME} < /var/www/init_db.sql")
    print(f"  3. Accede a la aplicación en: http://{public_ip}/login.php")
    print(f"  4. Usuario por defecto: admin / admin123")
    print(f"  5. Cambia las contraseñas por defecto en producción")
else:
    print(f"  1. Configura el endpoint de RDS en /var/www/.env en la instancia EC2")
    print(f"  2. Sube los archivos de la aplicación a /var/www/html en la instancia EC2")
    print(f"  3. Ejecuta init_db.sql en RDS desde la instancia EC2")
    print(f"  4. Accede a la aplicación en: http://{public_ip}/login.php")
    print(f"  5. Usuario por defecto: admin / admin123")

