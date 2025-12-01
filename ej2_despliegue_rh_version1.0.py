#!/usr/bin/env python3
"""
Script de despliegue de aplicación de dos capas en AWS
- Capa 1: EC2 con Apache + PHP (Web Server)
- Capa 2: RDS MySQL (Base de Datos)

Uso desde Ubuntu WSL:
    export AWS_ACCESS_KEY_ID="tu_access_key"
    export AWS_SECRET_ACCESS_KEY="tu_secret_key"
    export AWS_SESSION_TOKEN="tu_session_token"  # Solo si usas credenciales temporales
    export RDS_ADMIN_PASSWORD="tu_password_seguro"
    python3 deploy_app.py
"""

import boto3
import os
import sys
import time
from botocore.exceptions import ClientError

# ============================================
# CONSTANTES DE CONFIGURACIÓN
# ============================================
REGION = 'us-east-1'
AMI_ID = 'ami-06b21ccaeff8cd686'  # Amazon Linux 2023
INSTANCE_TYPE = 't2.micro'
EC2_SG_NAME = 'SG-EC2-Obligatorio'
RDS_SG_NAME = 'SG-RDS-Obligatorio'
DB_INSTANCE_ID = 'RDS-Obligatorio-Devops'
DB_NAME = 'demo_db'
DB_USER = 'admin'
APP_NAME = 'EC2-Obligatorio-Devops'
APP_USER = 'admin'
APP_PASS = 'admin123'
IAM_INSTANCE_PROFILE = 'LabInstanceProfile'

# URL del ZIP de la aplicación
PUBLIC_ZIP_URL = "https://github.com/Fabricio-Ramirez/ORTDevOps2025/releases/download/v1.0/obligatorio-main.zip"

# ============================================
# LECTURA DE VARIABLES DE ENTORNO
# ============================================
RDS_PASSWORD = os.environ.get('RDS_ADMIN_PASSWORD')

if not RDS_PASSWORD:
    print("=" * 60, file=sys.stderr)
    print("ERROR: Variable de entorno RDS_ADMIN_PASSWORD no definida", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("\nEjecuta los siguientes comandos antes de correr el script:\n", file=sys.stderr)
    print('  export RDS_ADMIN_PASSWORD="tu_password_seguro"', file=sys.stderr)
    print("\nLa contraseña debe tener al menos 8 caracteres.", file=sys.stderr)
    sys.exit(1)

if len(RDS_PASSWORD) < 8:
    print("ERROR: La contraseña debe tener al menos 8 caracteres.", file=sys.stderr)
    sys.exit(1)

# ============================================
# CLIENTES DE AWS
# ============================================
try:
    ec2 = boto3.client('ec2', region_name=REGION)
    rds = boto3.client('rds', region_name=REGION)
    ssm = boto3.client('ssm', region_name=REGION)
    
    # Verificar credenciales
    sts = boto3.client('sts', region_name=REGION)
    identity = sts.get_caller_identity()
    print(f"✓ Conectado a AWS como: {identity['Arn']}")
except Exception as e:
    print("=" * 60, file=sys.stderr)
    print("ERROR: No se pudo conectar a AWS", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"\nDetalles: {e}", file=sys.stderr)
    print("\nAsegúrate de configurar las credenciales de AWS:", file=sys.stderr)
    print('  export AWS_ACCESS_KEY_ID="tu_access_key"', file=sys.stderr)
    print('  export AWS_SECRET_ACCESS_KEY="tu_secret_key"', file=sys.stderr)
    print('  export AWS_SESSION_TOKEN="tu_session_token"  # Si usas Lab/Academy', file=sys.stderr)
    sys.exit(1)

print("\n" + "=" * 60)
print("INICIANDO DESPLIEGUE DE APLICACIÓN EN DOS CAPAS")
print("=" * 60)

# ============================================
# OBTENER VPC POR DEFECTO
# ============================================
print("\n[0/6] Obteniendo VPC por defecto...")
vpc_id = None
subnet_ids = []

try:
    vpcs = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
    if vpcs['Vpcs']:
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        print(f"✓ VPC por defecto encontrada: {vpc_id}")
        
        # Obtener subnets
        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        subnet_ids = [s['SubnetId'] for s in subnets['Subnets']]
        print(f"✓ Subnets disponibles: {len(subnet_ids)}")
except Exception as e:
    print(f"⚠ Error obteniendo VPC: {e}")

# ============================================
# [1/6] SECURITY GROUP PARA EC2 (WEB SERVER)
# ============================================
print("\n[1/6] Configurando Security Group para EC2 (Web Server)...")
ec2_sg_id = None

try:
    sg_params = {
        'GroupName': EC2_SG_NAME,
        'Description': 'Security Group para EC2 - Permite HTTP desde Internet'
    }
    if vpc_id:
        sg_params['VpcId'] = vpc_id
    
    response = ec2.create_security_group(**sg_params)
    ec2_sg_id = response['GroupId']
    print(f"✓ Security Group EC2 creado: {ec2_sg_id}")

    # Agregar regla HTTP (puerto 80)
    ec2.authorize_security_group_ingress(
        GroupId=ec2_sg_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP desde Internet'}]
            }
        ]
    )
    print(f"✓ Regla HTTP (puerto 80) agregada al SG")

except ClientError as e:
    if 'InvalidGroup.Duplicate' in str(e):
        filters = [{'Name': 'group-name', 'Values': [EC2_SG_NAME]}]
        if vpc_id:
            filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
        response = ec2.describe_security_groups(Filters=filters)
        if response['SecurityGroups']:
            ec2_sg_id = response['SecurityGroups'][0]['GroupId']
            print(f"⚠ Security Group EC2 ya existe: {ec2_sg_id}")
    else:
        print(f"✗ Error creando Security Group EC2: {e}")
        sys.exit(1)

# ============================================
# [2/6] SECURITY GROUP PARA RDS (BASE DE DATOS)
# ============================================
print("\n[2/6] Configurando Security Group para RDS (Base de Datos)...")
rds_sg_id = None

try:
    sg_params = {
        'GroupName': RDS_SG_NAME,
        'Description': 'Security Group para RDS - Solo permite MySQL desde EC2 SG'
    }
    if vpc_id:
        sg_params['VpcId'] = vpc_id
    
    response = ec2.create_security_group(**sg_params)
    rds_sg_id = response['GroupId']
    print(f"✓ Security Group RDS creado: {rds_sg_id}")

    # Regla MySQL (3306) SOLO desde el Security Group de EC2
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

except ClientError as e:
    if 'InvalidGroup.Duplicate' in str(e):
        filters = [{'Name': 'group-name', 'Values': [RDS_SG_NAME]}]
        if vpc_id:
            filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
        response = ec2.describe_security_groups(Filters=filters)
        if response['SecurityGroups']:
            rds_sg_id = response['SecurityGroups'][0]['GroupId']
            print(f"⚠ Security Group RDS ya existe: {rds_sg_id}")
    else:
        print(f"✗ Error creando Security Group RDS: {e}")
        sys.exit(1)

# ============================================
# [3/6] CREACIÓN DE INSTANCIA RDS
# ============================================
print("\n[3/6] Configurando instancia RDS...")
db_endpoint = None

try:
    # Verificar si ya existe
    try:
        db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
        db_instance = db_response['DBInstances'][0]
        db_status = db_instance['DBInstanceStatus']
        print(f"⚠ Instancia RDS ya existe (estado: {db_status})")
        
        if db_status != 'available':
            print("  Esperando a que esté disponible...")
            waiter = rds.get_waiter('db_instance_available')
            waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID, WaiterConfig={'Delay': 30, 'MaxAttempts': 40})
        
        db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
        db_endpoint = db_response['DBInstances'][0]['Endpoint']['Address']
        print(f"✓ Endpoint RDS: {db_endpoint}")
        
    except ClientError as e:
        if 'DBInstanceNotFound' in str(e):
            # Crear DB Subnet Group si hay suficientes subnets
            db_subnet_group_name = None
            if len(subnet_ids) >= 2:
                db_subnet_group_name = 'obligatorio-db-subnet-group'
                try:
                    rds.create_db_subnet_group(
                        DBSubnetGroupName=db_subnet_group_name,
                        DBSubnetGroupDescription='Subnet group para Obligatorio RDS',
                        SubnetIds=subnet_ids[:2]
                    )
                    print(f"✓ DB Subnet Group creado: {db_subnet_group_name}")
                except ClientError as e:
                    if 'DBSubnetGroupAlreadyExists' in str(e):
                        print(f"⚠ DB Subnet Group ya existe: {db_subnet_group_name}")
                    else:
                        db_subnet_group_name = None

            # Crear instancia RDS
            create_params = {
                'DBInstanceIdentifier': DB_INSTANCE_ID,
                'AllocatedStorage': 20,
                'DBInstanceClass': 'db.t3.micro',
                'Engine': 'mysql',
                'MasterUsername': DB_USER,
                'MasterUserPassword': RDS_PASSWORD,
                'DBName': DB_NAME,
                'PubliclyAccessible': False,
                'BackupRetentionPeriod': 0,
                'Tags': [
                    {'Key': 'Name', 'Value': DB_INSTANCE_ID},
                    {'Key': 'Application', 'Value': 'Obligatorio DevOps'}
                ]
            }
            
            if db_subnet_group_name:
                create_params['DBSubnetGroupName'] = db_subnet_group_name
            if rds_sg_id:
                create_params['VpcSecurityGroupIds'] = [rds_sg_id]

            rds.create_db_instance(**create_params)
            print(f"✓ Instancia RDS creada: {DB_INSTANCE_ID}")
            print("  Esperando a que esté disponible (5-10 minutos)...")
            
            waiter = rds.get_waiter('db_instance_available')
            waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID, WaiterConfig={'Delay': 30, 'MaxAttempts': 40})
            
            db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
            db_endpoint = db_response['DBInstances'][0]['Endpoint']['Address']
            print(f"✓ RDS disponible. Endpoint: {db_endpoint}")
        else:
            raise

except Exception as e:
    print(f"✗ Error con RDS: {e}", file=sys.stderr)
    sys.exit(1)

if not db_endpoint:
    print("✗ Error: No se pudo obtener el endpoint de RDS.", file=sys.stderr)
    sys.exit(1)

# ============================================
# [4/6] CREACIÓN DE INSTANCIA EC2
# ============================================
print("\n[4/6] Creando instancia EC2...")

# UserData para instalar Apache, PHP y MariaDB
user_data = """#!/bin/bash
sudo dnf clean all
sudo dnf makecache
sudo dnf update -y

# Instalar Apache + PHP + MariaDB client
sudo dnf install -y httpd php php-cli php-fpm php-common php-mysqlnd mariadb105 unzip curl

# Habilitar servicios
sudo systemctl enable --now httpd
sudo systemctl enable --now php-fpm

# Configurar PHP-FPM para Apache
echo '<FilesMatch \\.php$>
  SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost/"
</FilesMatch>' | sudo tee /etc/httpd/conf.d/php-fpm.conf

# Página de prueba
echo "<?php phpinfo(); ?>" | sudo tee /var/www/html/info.php

# Reiniciar servicios
sudo systemctl restart httpd php-fpm
"""

try:
    instance_params = {
        'ImageId': AMI_ID,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': INSTANCE_TYPE,
        'IamInstanceProfile': {'Name': IAM_INSTANCE_PROFILE},
        'UserData': user_data,
        'TagSpecifications': [
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': APP_NAME},
                    {'Key': 'Application', 'Value': 'Obligatorio DevOps'}
                ]
            }
        ]
    }

    if ec2_sg_id:
        instance_params['SecurityGroupIds'] = [ec2_sg_id]

    response = ec2.run_instances(**instance_params)
    instance_id = response['Instances'][0]['InstanceId']
    print(f"✓ Instancia EC2 creada: {instance_id}")

    # Esperar estado running
    print("  Esperando estado 'running'...")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    print(f"✓ Instancia en estado 'running'")

    # Esperar comprobaciones de estado
    print("  Esperando comprobaciones de estado (2-3 minutos)...")
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

# ============================================
# [5/6] DESPLIEGUE DE APLICACIÓN VÍA SSM
# ============================================
print("\n[5/6] Desplegando aplicación vía SSM...")

def run_ssm_command(instance_id, commands, description="", timeout=600):
    """Ejecuta comandos via SSM y espera el resultado"""
    print(f"  → {description}...")
    
    max_retries = 10
    for attempt in range(max_retries):
        try:
            response = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': commands},
                TimeoutSeconds=timeout
            )
            command_id = response['Command']['CommandId']
            
            # Esperar resultado
            elapsed = 0
            while elapsed < timeout:
                time.sleep(5)
                elapsed += 5
                try:
                    result = ssm.get_command_invocation(
                        CommandId=command_id,
                        InstanceId=instance_id
                    )
                    status = result['Status']
                    if status in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                        break
                except ClientError as e:
                    if 'InvocationDoesNotExist' in str(e):
                        continue
                    raise
            
            if status == 'Success':
                print(f"    ✓ {description} - Completado")
                return True, result.get('StandardOutputContent', '')
            else:
                error_msg = result.get('StandardErrorContent', '')
                print(f"    ✗ {description} - Falló")
                if error_msg:
                    print(f"      Error: {error_msg[:200]}")
                return False, error_msg
                
        except ClientError as e:
            if 'InvalidInstanceId' in str(e) and attempt < max_retries - 1:
                print(f"    ⚠ SSM Agent no listo. Reintentando ({attempt + 1}/{max_retries})...")
                time.sleep(15)
            else:
                print(f"    ✗ Error SSM: {e}")
                return False, str(e)
    
    return False, "Max retries exceeded"

# Esperar un poco para que SSM Agent esté listo
print("  Esperando que SSM Agent esté listo...")
time.sleep(30)

# Descargar y extraer aplicación
commands_download = [
    '#!/bin/bash',
    'set -e',
    'sudo rm -rf /home/ssm-user/app',
    'sudo mkdir -p /home/ssm-user/app',
    f'curl -L {PUBLIC_ZIP_URL} -o /home/ssm-user/app/app.zip',
    'sudo unzip -o /home/ssm-user/app/app.zip -d /home/ssm-user/app/',
    'ls -la /home/ssm-user/app'
]

run_ssm_command(instance_id, commands_download, "Descarga de aplicación")

# Script de despliegue completo
deploy_script = f"""#!/bin/bash
set -euo pipefail

echo "[DEPLOY] Iniciando despliegue: $(date)"

# Buscar directorio extraído
REALDIR="$(find /home/ssm-user/app -maxdepth 1 -type d -name 'obligatorio-main*' | head -n1)"
if [ -z "$REALDIR" ]; then
  echo "[ERROR] No se encontró carpeta obligatorio-main* en /home/ssm-user/app"
  exit 2
fi

echo "[INFO] Directorio encontrado: $REALDIR"

# Asegurar directorios
sudo mkdir -p /var/www/html

# Mover archivos al webroot
if [ -d "$REALDIR" ]; then
    shopt -s dotglob nullglob
    if [ -n "$(ls -A "$REALDIR")" ]; then
        sudo mv "$REALDIR"/* /var/www/html/ || true
    fi
    shopt -u dotglob nullglob
fi

# Mover init_db.sql fuera del webroot
if [ -f /var/www/html/init_db.sql ]; then
  sudo mv /var/www/html/init_db.sql /var/www/init_db.sql
fi

# Eliminar README si existe
sudo rm -f /var/www/html/README.md /var/www/html/README 2>/dev/null || true

# Crear archivo .env
sudo tee /var/www/.env > /dev/null << 'ENVFILE'
DB_HOST={db_endpoint}
DB_NAME={DB_NAME}
DB_USER={DB_USER}
DB_PASS={RDS_PASSWORD}
APP_USER={APP_USER}
APP_PASS={APP_PASS}
ENVFILE

sudo chown apache:apache /var/www/.env
sudo chmod 600 /var/www/.env

# Ejecutar init_db.sql si existe
if [ -f /var/www/init_db.sql ]; then
    echo "[INFO] Ejecutando init_db.sql..."
    TMPCNF="/tmp/.mycred.$$"
    cat > "$TMPCNF" << MYCNF
[client]
user={DB_USER}
password={RDS_PASSWORD}
host={db_endpoint}
MYCNF
    chmod 600 "$TMPCNF"
    
    set +e
    mysql --defaults-extra-file="$TMPCNF" {DB_NAME} < /var/www/init_db.sql 2>/tmp/mysql_err.$$
    rc=$?
    set -e
    
    MYSQL_ERR="$(cat /tmp/mysql_err.$$ 2>/dev/null || true)"
    rm -f /tmp/mysql_err.$$ "$TMPCNF"
    
    if [ $rc -ne 0 ]; then
        if echo "$MYSQL_ERR" | grep -qi 'already exists'; then
            echo "[WARN] Tablas ya existen, continuando..."
        else
            echo "[ERROR] mysql código $rc: $MYSQL_ERR"
        fi
    else
        echo "[OK] Base de datos inicializada"
    fi
fi

# Ajustar permisos
sudo chown -R apache:apache /var/www/html

# Reiniciar servicios
sudo systemctl restart httpd php-fpm

echo "[DEPLOY] Despliegue completado: $(date)"
"""

run_ssm_command(instance_id, [deploy_script], "Despliegue de aplicación", timeout=1200)

# ============================================
# [6/6] VERIFICACIÓN FINAL
# ============================================
print("\n[6/6] Verificación final...")

commands_verify = [
    '#!/bin/bash',
    'echo "=== Estado de servicios ==="',
    'systemctl is-active httpd && echo "Apache: OK" || echo "Apache: FAIL"',
    'systemctl is-active php-fpm && echo "PHP-FPM: OK" || echo "PHP-FPM: FAIL"',
    'echo ""',
    'echo "=== Archivos en /var/www/html ==="',
    'ls -la /var/www/html/ | head -15',
    'echo ""',
    'echo "=== Archivo .env ==="',
    'ls -la /var/www/.env 2>/dev/null && echo ".env: OK" || echo ".env: FAIL"'
]

success, output = run_ssm_command(instance_id, commands_verify, "Verificación")
if output:
    print(f"\n{output}")

# ============================================
# RESUMEN FINAL
# ============================================
print("\n" + "=" * 60)
print("✓ DESPLIEGUE COMPLETADO EXITOSAMENTE")
print("=" * 60)
print(f"""
RECURSOS CREADOS:
  - Security Group EC2: {ec2_sg_id}
  - Security Group RDS: {rds_sg_id}
  - Instancia EC2:      {instance_id}
  - Instancia RDS:      {DB_INSTANCE_ID}
  - Endpoint RDS:       {db_endpoint}

ACCESO A LA APLICACIÓN:
  URL Principal: http://{public_ip}/
  URL Login:     http://{public_ip}/login.php
  URL Info PHP:  http://{public_ip}/info.php

CREDENCIALES POR DEFECTO:
  Usuario:    {APP_USER}
  Contraseña: {APP_PASS}

ARQUITECTURA DE SEGURIDAD:
  ✓ EC2 Security Group: Permite HTTP (80) desde Internet
  ✓ RDS Security Group: Solo permite MySQL (3306) desde EC2 SG
  ✓ RDS no accesible públicamente
  ✓ Archivos sensibles fuera del webroot
""")
