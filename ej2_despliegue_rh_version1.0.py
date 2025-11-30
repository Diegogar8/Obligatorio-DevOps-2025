#!/usr/bin/env python3

import boto3          # SDK de AWS para Python (para usar EC2, RDS, SSM, etc.)
import os             # Para leer variables de entorno del sistema
import sys            # Para salir con códigos de error y escribir en stderr
import time           # Para esperas entre reintentos de SSM
from botocore.exceptions import ClientError  # Excepción específica de errores de AWS

# ---------------------------
# CONSTANTES DE CONFIGURACIÓN
# ---------------------------
REGION = 'us-east-1'                       # Región de AWS donde se desplegarán los recursos
AMI_ID = 'ami-06b21ccaeff8cd686'           # ID de la AMI utilizada para la instancia EC2 (Amazon Linux 2023)
INSTANCE_TYPE = 't2.micro'                 # Tipo de instancia EC2
EC2_SG_NAME = 'rh-app-ec2-sg'              # Nombre del Security Group para EC2 (Web Server)
RDS_SG_NAME = 'rh-app-rds-sg'              # Nombre del Security Group para RDS (Base de Datos)
DB_INSTANCE_ID = 'rh-app-db'               # Identificador de la instancia RDS
DB_NAME = 'demo_db'                        # Nombre de la base de datos que se creará en RDS
DB_USER = 'admin'                          # Usuario administrador de la base de datos
APP_NAME = 'rh-app-web'                    # Nombre que se usará como tag de la instancia EC2
APP_USER = 'admin'                         # Usuario por defecto de la aplicación
APP_PASS = 'admin123'                      # Contraseña por defecto de la aplicación
IAM_INSTANCE_PROFILE = 'LabInstanceProfile' # Perfil de instancia IAM para SSM

# ---------------------------
# LECTURA DE VARIABLES DE ENTORNO
# ---------------------------
EC2_SG_ID_ENV = os.environ.get('EC2_SECURITY_GROUP_ID')  # Si está, se usará este Security Group para EC2
RDS_SG_ID_ENV = os.environ.get('RDS_SECURITY_GROUP_ID')  # Si está, se usará este Security Group para RDS
RDS_ENDPOINT_ENV = os.environ.get('RDS_ENDPOINT')        # Si está, se usará este endpoint de RDS ya existente
RDS_PASSWORD = os.environ.get('RDS_ADMIN_PASSWORD')      # Password del usuario admin de RDS

# Si no se definió la variable de entorno con la contraseña, el script no puede continuar
if not RDS_PASSWORD:
    print("Error: Debes definir la variable de entorno RDS_ADMIN_PASSWORD", file=sys.stderr)
    print("Ejemplo: export RDS_ADMIN_PASSWORD='tu_password_seguro'", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# CLIENTES DE AWS (EC2, RDS y SSM)
# ---------------------------
ec2 = boto3.client('ec2', region_name=REGION)
rds = boto3.client('rds', region_name=REGION)
ssm = boto3.client('ssm', region_name=REGION)

# Mensajes iniciales de log
print("=" * 60)
print("INICIANDO DESPLIEGUE DE APLICACIÓN DE RECURSOS HUMANOS")
print("=" * 60)

# ---------------------------
# FUNCIÓN PARA OBTENER VPC Y SUBNET POR DEFECTO (OPCIONAL)
# ---------------------------
def get_default_vpc_and_subnet():
    """Obtiene la VPC por defecto y una subnet pública (si hay permisos)"""
    try:
        vpcs = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
        if vpcs['Vpcs']:
            vpc_id = vpcs['Vpcs'][0]['VpcId']
            subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            if subnets['Subnets']:
                subnet_ids = [s['SubnetId'] for s in subnets['Subnets']]
                return vpc_id, subnet_ids
    except Exception as e:
        print(f"⚠ No se pudo obtener VPC/Subnet (permisos limitados): {str(e)[:100]}...")
    return None, []

vpc_id, subnet_ids = get_default_vpc_and_subnet()
if vpc_id:
    print(f"✓ VPC por defecto: {vpc_id}")
    print(f"✓ Subnets disponibles: {len(subnet_ids)}")
else:
    print("⚠ VPC no especificada - Se usará la VPC por defecto de la cuenta")

# ---------------------------
# [1/5] CREACIÓN DE SECURITY GROUP PARA EC2 (WEB SERVER)
# ---------------------------
print("\n[1/5] Configurando Security Group para EC2 (Web Server)...")
ec2_sg_id = None

if EC2_SG_ID_ENV:
    ec2_sg_id = EC2_SG_ID_ENV
    print(f"✓ Usando Security Group EC2 especificado: {ec2_sg_id}")
else:
    try:
        # Crear Security Group para EC2
        sg_params = {
            'GroupName': EC2_SG_NAME,
            'Description': 'Security Group para EC2 Web Server - Permite HTTP desde Internet'
        }
        # Solo agregar VpcId si está disponible
        if vpc_id:
            sg_params['VpcId'] = vpc_id
        
        response = ec2.create_security_group(**sg_params)
        ec2_sg_id = response['GroupId']
        print(f"✓ Security Group EC2 creado: {ec2_sg_id}")

        # Agregar regla de entrada para HTTP (80) desde cualquier IP
        ec2.authorize_security_group_ingress(
            GroupId=ec2_sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP desde Internet'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS desde Internet'}]
                }
            ]
        )
        print(f"✓ Regla HTTP/HTTPS configurada para EC2")

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                # Buscar SG existente por nombre
                filters = [{'Name': 'group-name', 'Values': [EC2_SG_NAME]}]
                if vpc_id:
                    filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
                response = ec2.describe_security_groups(Filters=filters)
                if response['SecurityGroups']:
                    ec2_sg_id = response['SecurityGroups'][0]['GroupId']
                    print(f"⚠ Security Group EC2 ya existe: {ec2_sg_id}")
            except Exception as e2:
                print(f"⚠ Error obteniendo SG existente: {e2}")
        else:
            print(f"⚠ Error creando Security Group EC2: {e}")

# ---------------------------
# [2/5] CREACIÓN DE SECURITY GROUP PARA RDS (BASE DE DATOS)
# ---------------------------
print("\n[2/5] Configurando Security Group para RDS (Base de Datos)...")
rds_sg_id = None

if RDS_SG_ID_ENV:
    rds_sg_id = RDS_SG_ID_ENV
    print(f"✓ Usando Security Group RDS especificado: {rds_sg_id}")
else:
    try:
        # Crear Security Group para RDS
        sg_params = {
            'GroupName': RDS_SG_NAME,
            'Description': 'Security Group para RDS - Solo permite MySQL desde EC2 SG'
        }
        # Solo agregar VpcId si está disponible
        if vpc_id:
            sg_params['VpcId'] = vpc_id
        
        response = ec2.create_security_group(**sg_params)
        rds_sg_id = response['GroupId']
        print(f"✓ Security Group RDS creado: {rds_sg_id}")

        # Agregar regla de entrada para MySQL (3306) SOLO desde el Security Group de EC2
        if ec2_sg_id:
            ec2.authorize_security_group_ingress(
                GroupId=rds_sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 3306,
                        'ToPort': 3306,
                        'UserIdGroupPairs': [
                            {
                                'GroupId': ec2_sg_id,
                                'Description': 'MySQL solo desde EC2 Security Group'
                            }
                        ]
                    }
                ]
            )
            print(f"✓ Regla MySQL configurada: Solo acepta tráfico desde {ec2_sg_id}")
        else:
            print("⚠ No se pudo configurar regla MySQL (falta EC2 SG)")

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                # Buscar SG existente por nombre
                filters = [{'Name': 'group-name', 'Values': [RDS_SG_NAME]}]
                if vpc_id:
                    filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
                response = ec2.describe_security_groups(Filters=filters)
                if response['SecurityGroups']:
                    rds_sg_id = response['SecurityGroups'][0]['GroupId']
                    print(f"⚠ Security Group RDS ya existe: {rds_sg_id}")
            except Exception as e2:
                print(f"⚠ Error obteniendo SG existente: {e2}")
        else:
            print(f"⚠ Error creando Security Group RDS: {e}")

# ---------------------------
# [3/5] CONFIGURACIÓN DE RDS
# ---------------------------
print("\n[3/5] Configurando RDS...")
db_endpoint = None

if RDS_ENDPOINT_ENV:
    db_endpoint = RDS_ENDPOINT_ENV
    print(f"✓ Usando RDS endpoint especificado: {db_endpoint}")
else:
    try:
        # Crear DB Subnet Group solo si tenemos subnets disponibles
        db_subnet_group_name = None
        if len(subnet_ids) >= 2:
            db_subnet_group_name = 'rh-app-db-subnet-group'
            try:
                rds.create_db_subnet_group(
                    DBSubnetGroupName=db_subnet_group_name,
                    DBSubnetGroupDescription='Subnet group para RH App RDS',
                    SubnetIds=subnet_ids[:2]
                )
                print(f"✓ DB Subnet Group creado: {db_subnet_group_name}")
            except ClientError as e:
                if 'DBSubnetGroupAlreadyExists' in str(e):
                    print(f"⚠ DB Subnet Group ya existe: {db_subnet_group_name}")
                else:
                    print(f"⚠ Error creando DB Subnet Group: {e}")
                    db_subnet_group_name = None
        else:
            print("⚠ No hay suficientes subnets - RDS usará configuración por defecto")

        # Crear instancia RDS
        create_params = {
            'DBInstanceIdentifier': DB_INSTANCE_ID,
            'AllocatedStorage': 20,
            'DBInstanceClass': 'db.t3.micro',
            'Engine': 'mysql',
            'EngineVersion': '8.0',
            'MasterUsername': DB_USER,
            'MasterUserPassword': RDS_PASSWORD,
            'DBName': DB_NAME,
            'PubliclyAccessible': False,
            'StorageEncrypted': True,
            'BackupRetentionPeriod': 7,
            'Tags': [
                {'Key': 'Name', 'Value': DB_INSTANCE_ID},
                {'Key': 'Application', 'Value': 'Recursos Humanos'}
            ]
        }
        
        # Agregar DB Subnet Group solo si fue creado
        if db_subnet_group_name:
            create_params['DBSubnetGroupName'] = db_subnet_group_name
        
        # Asociar Security Group de RDS si existe
        if rds_sg_id:
            create_params['VpcSecurityGroupIds'] = [rds_sg_id]

        rds.create_db_instance(**create_params)
        print(f"✓ Instancia RDS creada: {DB_INSTANCE_ID}")
        print("  - Encriptación en reposo: Habilitada")
        print("  - Acceso público: Deshabilitado")
        print(f"  - Security Group: {rds_sg_id}")

        # Esperar a que la instancia RDS esté disponible
        print("Esperando a que RDS esté disponible (esto puede tomar varios minutos)...")
        waiter = rds.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID, WaiterConfig={'Delay': 30, 'MaxAttempts': 40})

        # Obtener endpoint de RDS
        db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
        db_endpoint = db_response['DBInstances'][0]['Endpoint']['Address']
        print(f"✓ RDS disponible. Endpoint: {db_endpoint}")

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'DBInstanceAlreadyExists':
            print(f"⚠ Instancia RDS {DB_INSTANCE_ID} ya existe")
            try:
                db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
                db_status = db_response['DBInstances'][0]['DBInstanceStatus']
                if db_status != 'available':
                    print(f"  Estado actual: {db_status}. Esperando...")
                    waiter = rds.get_waiter('db_instance_available')
                    waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID, WaiterConfig={'Delay': 30, 'MaxAttempts': 40})
                db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
                db_endpoint = db_response['DBInstances'][0]['Endpoint']['Address']
                print(f"✓ Endpoint de RDS: {db_endpoint}")
            except Exception as e2:
                print(f"⚠ No se pudo obtener el endpoint: {e2}")
        else:
            print(f"⚠ Error con RDS: {e}")

if not db_endpoint:
    print("✗ Error: No se pudo obtener el endpoint de RDS. Abortando.", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# [4/5] CREACIÓN DE INSTANCIA EC2 CON SSM
# ---------------------------
print("\n[4/5] Creando instancia EC2...")

try:
    # Parámetros para crear la instancia EC2
    instance_params = {
        'ImageId': AMI_ID,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': INSTANCE_TYPE,
        'IamInstanceProfile': {'Name': IAM_INSTANCE_PROFILE},  # Perfil para SSM
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

    # Asociar Security Group de EC2 si existe
    if ec2_sg_id:
        instance_params['SecurityGroupIds'] = [ec2_sg_id]

    # Crear la instancia EC2
    response = ec2.run_instances(**instance_params)
    instance_id = response['Instances'][0]['InstanceId']
    print(f"✓ Instancia EC2 creada: {instance_id}")
    print(f"  - IAM Instance Profile: {IAM_INSTANCE_PROFILE}")
    print(f"  - Security Group: {ec2_sg_id}")

    # Esperar a que la instancia esté en estado 'running'
    print("Esperando a que la instancia esté en estado 'running'...")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    print(f"✓ Instancia en estado 'running'")

    # Esperar a que la instancia pase las comprobaciones de estado (instance_status_ok)
    # Esto asegura que SSM Agent esté listo
    print("Esperando a que la instancia pase las comprobaciones de estado...")
    waiter = ec2.get_waiter('instance_status_ok')
    waiter.wait(InstanceIds=[instance_id])
    print(f"✓ Instancia pasó las comprobaciones de estado")

    # Obtener IP pública
    response = ec2.describe_instances(InstanceIds=[instance_id])
    public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress', 'N/A')
    print(f"  IP pública: {public_ip}")

except ClientError as e:
    print(f"✗ Error creando instancia EC2: {e}", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# [5/5] CONFIGURACIÓN DEL WEB SERVER VÍA SSM
# ---------------------------
print("\n[5/5] Configurando Web Server vía SSM...")

# Función para ejecutar comandos via SSM y esperar resultado
def run_ssm_command(instance_id, commands, description=""):
    """Ejecuta comandos via SSM y espera el resultado"""
    print(f"  Ejecutando: {description}...")
    
    # Esperar un momento para asegurar que SSM Agent esté completamente listo
    time.sleep(10)
    
    max_retries = 5
    for attempt in range(max_retries):
        try:
            response = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': commands},
                TimeoutSeconds=600
            )
            command_id = response['Command']['CommandId']
            
            # Esperar a que el comando termine
            while True:
                time.sleep(5)
                result = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                status = result['Status']
                if status in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                    break
            
            if status == 'Success':
                print(f"    ✓ {description} - Completado")
                return True, result.get('StandardOutputContent', '')
            else:
                print(f"    ✗ {description} - Falló: {result.get('StandardErrorContent', '')}")
                return False, result.get('StandardErrorContent', '')
                
        except ClientError as e:
            if 'InvalidInstanceId' in str(e) and attempt < max_retries - 1:
                print(f"    ⚠ SSM Agent no está listo aún. Reintentando ({attempt + 1}/{max_retries})...")
                time.sleep(30)
            else:
                print(f"    ✗ Error SSM: {e}")
                return False, str(e)
    
    return False, "Max retries exceeded"

# Paso 1: Actualizar sistema e instalar paquetes
commands_install = [
    '#!/bin/bash',
    'set -e',
    '# 1) Actualiza índices y paquetes',
    'sudo dnf clean all',
    'sudo dnf makecache',
    'sudo dnf -y update',
    '',
    '# 2) Instala Apache + PHP 8.4 + mariadb y extensiones típicas',
    'sudo dnf -y install httpd php php-cli php-fpm php-common php-mysqlnd mariadb105 git',
    '',
    '# 3) Habilita y arranca servicios',
    'sudo systemctl enable --now httpd',
    'sudo systemctl enable --now php-fpm',
    '',
    '# 4) Configura PHP-FPM para Apache',
    'echo \'<FilesMatch \\.php$>',
    '  SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost/"',
    '</FilesMatch>\' | sudo tee /etc/httpd/conf.d/php-fpm.conf',
    '',
    '# 5) Archivo de prueba',
    'echo "<?php phpinfo(); ?>" | sudo tee /var/www/html/info.php',
    '',
    '# 6) Reinicia para tomar config',
    'sudo systemctl restart httpd php-fpm'
]

success, output = run_ssm_command(instance_id, commands_install, "Instalación de Apache, PHP y MariaDB")
if not success:
    print("⚠ La instalación tuvo problemas, pero continuamos...")

# Paso 2: Clonar repositorio
commands_clone = [
    '#!/bin/bash',
    'set -e',
    'cd /var/www/html',
    'sudo rm -rf obligatorio 2>/dev/null || true',
    'sudo git clone https://github.com/ORT-AII-ProgramacionDevOps/obligatorio.git',
    '',
    '# Mover archivos del repositorio a /var/www/html (excepto README e init_db.sql)',
    'sudo mv obligatorio/* . 2>/dev/null || true',
    'sudo mv obligatorio/.* . 2>/dev/null || true',
    '',
    '# Mover init_db.sql fuera del webroot a /var/www',
    'sudo mv init_db.sql /var/www/ 2>/dev/null || true',
    '',
    '# Eliminar directorio vacío del repo',
    'sudo rm -rf obligatorio',
    '',
    '# Eliminar README si existe (no debe estar en webroot)',
    'sudo rm -f README.md README 2>/dev/null || true'
]

success, output = run_ssm_command(instance_id, commands_clone, "Clonación del repositorio")
if not success:
    print("⚠ La clonación tuvo problemas, pero continuamos...")

# Paso 3: Crear archivo .env con configuración de BD
env_content = f'''DB_HOST={db_endpoint}
DB_NAME={DB_NAME}
DB_USER={DB_USER}
DB_PASS={RDS_PASSWORD}
APP_USER={APP_USER}
APP_PASS={APP_PASS}'''

commands_env = [
    '#!/bin/bash',
    'set -e',
    '',
    '# Crear archivo .env fuera del webroot',
    f'sudo tee /var/www/.env >/dev/null <<\'ENV\'',
    env_content,
    'ENV',
    '',
    '# Configurar permisos del .env',
    'sudo chown apache:apache /var/www/.env',
    'sudo chmod 600 /var/www/.env',
    '',
    '# Configurar permisos del webroot',
    'sudo chown -R apache:apache /var/www/html',
    '',
    '# Reiniciar servicios',
    'sudo systemctl restart httpd php-fpm'
]

success, output = run_ssm_command(instance_id, commands_env, "Configuración de archivo .env")
if not success:
    print("⚠ La configuración del .env tuvo problemas...")

# Paso 4: Ejecutar init_db.sql en RDS
commands_init_db = [
    '#!/bin/bash',
    'set -e',
    '',
    '# Ejecutar script de inicialización de BD',
    f'mysql -h {db_endpoint} -u {DB_USER} -p{RDS_PASSWORD} {DB_NAME} < /var/www/init_db.sql',
    '',
    'echo "Base de datos inicializada correctamente"'
]

success, output = run_ssm_command(instance_id, commands_init_db, "Inicialización de base de datos")
if not success:
    print("⚠ La inicialización de BD tuvo problemas (puede que ya esté inicializada)")

# Paso 5: Verificación final
commands_verify = [
    '#!/bin/bash',
    '',
    'echo "=== Estado de servicios ==="',
    'sudo systemctl status httpd --no-pager | head -5',
    'sudo systemctl status php-fpm --no-pager | head -5',
    '',
    'echo "=== Archivos en /var/www/html ==="',
    'ls -la /var/www/html/',
    '',
    'echo "=== Archivo .env existe ==="',
    'ls -la /var/www/.env',
    '',
    'echo "=== Test de conexión a BD ==="',
    f'mysql -h {db_endpoint} -u {DB_USER} -p{RDS_PASSWORD} -e "SHOW DATABASES;" 2>&1 | head -10'
]

success, output = run_ssm_command(instance_id, commands_verify, "Verificación final")
if success:
    print(f"\n  Resultado de verificación:\n{output[:500]}...")

# ---------------------------
# RESUMEN FINAL
# ---------------------------
print("\n" + "=" * 60)
print("DESPLIEGUE COMPLETADO")
print("=" * 60)
print(f"\nRecursos creados:")
print(f"  - Security Group EC2 (Web): {ec2_sg_id}")
print(f"  - Security Group RDS (BD):  {rds_sg_id}")
print(f"  - Instancia RDS:            {DB_INSTANCE_ID}")
print(f"  - Endpoint RDS:             {db_endpoint}")
print(f"  - Instancia EC2:            {instance_id}")
print(f"  - IP pública EC2:           {public_ip}")
print(f"\n✓ ACCESO A LA APLICACIÓN:")
print(f"  URL: http://{public_ip}/")
print(f"  Login: http://{public_ip}/login.php")
print(f"\n✓ CREDENCIALES POR DEFECTO:")
print(f"  Usuario: {APP_USER}")
print(f"  Contraseña: {APP_PASS}")
print(f"\n⚠ IMPORTANTE:")
print(f"  1. Cambia las contraseñas por defecto en producción")
print(f"  2. El Security Group de RDS solo permite MySQL desde el SG de EC2")
print(f"  3. La instancia EC2 está configurada con SSM para administración remota")
print(f"  4. Los archivos sensibles (.env, init_db.sql) están fuera del webroot")
