#!/usr/bin/env python3
"""
Script de despliegue para AWS Academy Lab
- Usa el Security Group por defecto (sin crear nuevos)
- Compatible con las restricciones del Lab

Uso:
    export AWS_ACCESS_KEY_ID="..."
    export AWS_SECRET_ACCESS_KEY="..."
    export AWS_SESSION_TOKEN="..."
    export RDS_ADMIN_PASSWORD="password123"
    python3 deploy_lab.py
"""

import boto3
import os
import sys
import time
from botocore.exceptions import ClientError

# ============================================
# CONFIGURACIÓN
# ============================================
REGION = 'us-east-1'
AMI_ID = 'ami-06b21ccaeff8cd686'  # Amazon Linux 2023
INSTANCE_TYPE = 't2.micro'
DB_INSTANCE_ID = 'rds-obligatorio-devops'
DB_NAME = 'demo_db'
DB_USER = 'admin'
APP_NAME = 'EC2-Obligatorio-Devops'
APP_USER = 'admin'
APP_PASS = 'admin123'
IAM_INSTANCE_PROFILE = 'LabInstanceProfile'

PUBLIC_ZIP_URL = "https://github.com/Fabricio-Ramirez/ORTDevOps2025/releases/download/v1.0/obligatorio-main.zip"

# ============================================
# VARIABLES DE ENTORNO
# ============================================
RDS_PASSWORD = os.environ.get('RDS_ADMIN_PASSWORD')

if not RDS_PASSWORD:
    print("ERROR: Debes definir RDS_ADMIN_PASSWORD", file=sys.stderr)
    print('  export RDS_ADMIN_PASSWORD="tu_password"', file=sys.stderr)
    sys.exit(1)

if len(RDS_PASSWORD) < 8:
    print("ERROR: Password debe tener al menos 8 caracteres", file=sys.stderr)
    sys.exit(1)

# ============================================
# CLIENTES AWS
# ============================================
try:
    ec2 = boto3.client('ec2', region_name=REGION)
    rds = boto3.client('rds', region_name=REGION)
    ssm = boto3.client('ssm', region_name=REGION)
    ec2_resource = boto3.resource('ec2', region_name=REGION)
    
    sts = boto3.client('sts', region_name=REGION)
    identity = sts.get_caller_identity()
    print(f"✓ Conectado como: {identity['Arn']}")
except Exception as e:
    print(f"ERROR conectando a AWS: {e}", file=sys.stderr)
    sys.exit(1)

print("\n" + "=" * 60)
print("DESPLIEGUE PARA AWS ACADEMY LAB")
print("=" * 60)

# ============================================
# [1/5] OBTENER SECURITY GROUP POR DEFECTO
# ============================================
print("\n[1/5] Buscando Security Group por defecto...")

default_sg_id = None
vpc_id = None

try:
    # Buscar el security group "default"
    sgs = ec2.describe_security_groups(
        Filters=[{'Name': 'group-name', 'Values': ['default']}]
    )
    if sgs['SecurityGroups']:
        default_sg_id = sgs['SecurityGroups'][0]['GroupId']
        vpc_id = sgs['SecurityGroups'][0]['VpcId']
        print(f"✓ Security Group default: {default_sg_id}")
        print(f"✓ VPC: {vpc_id}")
except ClientError as e:
    print(f"⚠ No se pudo obtener SG default: {e}")

# Intentar agregar regla HTTP al SG default
if default_sg_id:
    try:
        ec2.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 3306,
                    'ToPort': 3306,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Para RDS desde EC2
                }
            ]
        )
        print("✓ Reglas HTTP y MySQL agregadas al SG")
    except ClientError as e:
        if 'InvalidPermission.Duplicate' in str(e):
            print("✓ Reglas ya existen en el SG")
        else:
            print(f"⚠ No se pudieron agregar reglas: {e}")

# ============================================
# [2/5] CREAR INSTANCIA RDS
# ============================================
print("\n[2/5] Configurando RDS...")
db_endpoint = None

try:
    # Verificar si ya existe
    try:
        resp = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
        db_instance = resp['DBInstances'][0]
        status = db_instance['DBInstanceStatus']
        print(f"✓ RDS ya existe (estado: {status})")
        
        if status != 'available':
            print("  Esperando disponibilidad...")
            waiter = rds.get_waiter('db_instance_available')
            waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID)
        
        resp = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
        db_endpoint = resp['DBInstances'][0]['Endpoint']['Address']
        print(f"✓ Endpoint: {db_endpoint}")
        
    except ClientError as e:
        if 'DBInstanceNotFound' in str(e):
            print("  Creando instancia RDS...")
            
            create_params = {
                'DBInstanceIdentifier': DB_INSTANCE_ID,
                'AllocatedStorage': 20,
                'DBInstanceClass': 'db.t3.micro',
                'Engine': 'mysql',
                'MasterUsername': DB_USER,
                'MasterUserPassword': RDS_PASSWORD,
                'DBName': DB_NAME,
                'PubliclyAccessible': True,  # Necesario en Lab para conexión desde EC2
                'BackupRetentionPeriod': 0
            }
            
            if default_sg_id:
                create_params['VpcSecurityGroupIds'] = [default_sg_id]
            
            rds.create_db_instance(**create_params)
            print("✓ RDS creada, esperando disponibilidad (5-10 min)...")
            
            waiter = rds.get_waiter('db_instance_available')
            waiter.wait(
                DBInstanceIdentifier=DB_INSTANCE_ID,
                WaiterConfig={'Delay': 30, 'MaxAttempts': 40}
            )
            
            resp = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
            db_endpoint = resp['DBInstances'][0]['Endpoint']['Address']
            print(f"✓ RDS disponible. Endpoint: {db_endpoint}")
        else:
            raise

except Exception as e:
    print(f"ERROR con RDS: {e}", file=sys.stderr)
    sys.exit(1)

if not db_endpoint:
    print("ERROR: No se pudo obtener endpoint de RDS", file=sys.stderr)
    sys.exit(1)

# ============================================
# [3/5] CREAR INSTANCIA EC2
# ============================================
print("\n[3/5] Creando instancia EC2...")

user_data = """#!/bin/bash
yum update -y 2>/dev/null || dnf update -y
yum install -y httpd php php-mysqlnd mariadb105 unzip curl 2>/dev/null || dnf install -y httpd php php-cli php-fpm php-common php-mysqlnd mariadb105 unzip curl

systemctl enable httpd
systemctl start httpd
systemctl enable php-fpm 2>/dev/null
systemctl start php-fpm 2>/dev/null

# Configurar PHP-FPM si existe
if [ -d /run/php-fpm ]; then
    echo '<FilesMatch \\.php$>
      SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost/"
    </FilesMatch>' > /etc/httpd/conf.d/php-fpm.conf
fi

echo "<?php phpinfo(); ?>" > /var/www/html/info.php
systemctl restart httpd
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
                'Tags': [{'Key': 'Name', 'Value': APP_NAME}]
            }
        ]
    }
    
    if default_sg_id:
        instance_params['SecurityGroupIds'] = [default_sg_id]
    
    response = ec2.run_instances(**instance_params)
    instance_id = response['Instances'][0]['InstanceId']
    print(f"✓ EC2 creada: {instance_id}")
    
    print("  Esperando estado running...")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    print("✓ Instancia running")
    
    print("  Esperando comprobaciones de estado (2-3 min)...")
    waiter = ec2.get_waiter('instance_status_ok')
    waiter.wait(InstanceIds=[instance_id])
    print("✓ Comprobaciones OK")
    
    # Obtener IP pública
    response = ec2.describe_instances(InstanceIds=[instance_id])
    public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress', 'N/A')
    print(f"  IP pública: {public_ip}")

except ClientError as e:
    print(f"ERROR creando EC2: {e}", file=sys.stderr)
    sys.exit(1)

# ============================================
# [4/5] DESPLEGAR APLICACIÓN VÍA SSM
# ============================================
print("\n[4/5] Desplegando aplicación via SSM...")

def run_ssm(instance_id, commands, desc="", timeout=600):
    """Ejecuta comandos via SSM"""
    print(f"  → {desc}...")
    
    for attempt in range(15):
        try:
            resp = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': commands},
                TimeoutSeconds=timeout
            )
            cmd_id = resp['Command']['CommandId']
            
            elapsed = 0
            while elapsed < timeout:
                time.sleep(5)
                elapsed += 5
                try:
                    inv = ssm.get_command_invocation(
                        CommandId=cmd_id,
                        InstanceId=instance_id
                    )
                    if inv['Status'] in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                        if inv['Status'] == 'Success':
                            print(f"    ✓ {desc}")
                            return True, inv.get('StandardOutputContent', '')
                        else:
                            print(f"    ✗ {desc}: {inv.get('StandardErrorContent', '')[:200]}")
                            return False, inv.get('StandardErrorContent', '')
                except ClientError:
                    continue
            
            return False, "Timeout"
            
        except ClientError as e:
            if 'InvalidInstanceId' in str(e) and attempt < 14:
                print(f"    SSM no listo, reintentando ({attempt+1}/15)...")
                time.sleep(20)
            else:
                return False, str(e)
    
    return False, "Max retries"

# Esperar SSM
print("  Esperando SSM Agent...")
time.sleep(45)

# Descargar aplicación
run_ssm(instance_id, [
    '#!/bin/bash',
    'set -e',
    'rm -rf /tmp/app',
    'mkdir -p /tmp/app',
    f'curl -L {PUBLIC_ZIP_URL} -o /tmp/app/app.zip',
    'unzip -o /tmp/app/app.zip -d /tmp/app/',
    'ls -la /tmp/app'
], "Descarga de aplicación")

# Deploy script
deploy = f"""#!/bin/bash
set -e

echo "=== DEPLOY START ==="

# Buscar carpeta extraída
SRCDIR=$(find /tmp/app -maxdepth 1 -type d -name 'obligatorio*' | head -1)
if [ -z "$SRCDIR" ]; then
    echo "ERROR: No se encontró carpeta obligatorio"
    exit 1
fi

echo "Carpeta fuente: $SRCDIR"

# Mover archivos
sudo mkdir -p /var/www/html
sudo cp -r "$SRCDIR"/* /var/www/html/ 2>/dev/null || true

# Mover init_db.sql fuera del webroot
if [ -f /var/www/html/init_db.sql ]; then
    sudo mv /var/www/html/init_db.sql /var/www/
fi

# Eliminar README
sudo rm -f /var/www/html/README.md /var/www/html/README 2>/dev/null || true

# Crear .env
sudo tee /var/www/.env > /dev/null << 'EOF'
DB_HOST={db_endpoint}
DB_NAME={DB_NAME}
DB_USER={DB_USER}
DB_PASS={RDS_PASSWORD}
APP_USER={APP_USER}
APP_PASS={APP_PASS}
EOF

sudo chmod 600 /var/www/.env
sudo chown apache:apache /var/www/.env 2>/dev/null || true

# Ejecutar SQL si existe
if [ -f /var/www/init_db.sql ]; then
    echo "Ejecutando init_db.sql..."
    mysql -h {db_endpoint} -u {DB_USER} -p'{RDS_PASSWORD}' {DB_NAME} < /var/www/init_db.sql 2>/dev/null || echo "SQL ya ejecutado o error (continuando)"
fi

# Permisos
sudo chown -R apache:apache /var/www/html 2>/dev/null || true

# Reiniciar Apache
sudo systemctl restart httpd
sudo systemctl restart php-fpm 2>/dev/null || true

echo "=== DEPLOY COMPLETE ==="
"""

run_ssm(instance_id, [deploy], "Deploy aplicación", timeout=1200)

# ============================================
# [5/5] VERIFICACIÓN
# ============================================
print("\n[5/5] Verificación final...")

run_ssm(instance_id, [
    '#!/bin/bash',
    'echo "=== SERVICIOS ==="',
    'systemctl is-active httpd && echo "Apache: OK" || echo "Apache: FAIL"',
    'echo ""',
    'echo "=== ARCHIVOS ==="',
    'ls -la /var/www/html/ | head -10',
    'echo ""',
    'echo "=== .ENV ==="',
    'ls -la /var/www/.env 2>/dev/null && echo ".env OK" || echo ".env FAIL"'
], "Verificación")

# ============================================
# RESUMEN
# ============================================
print("\n" + "=" * 60)
print("✓ DESPLIEGUE COMPLETADO")
print("=" * 60)
print(f"""
RECURSOS:
  EC2 Instance:  {instance_id}
  RDS Instance:  {DB_INSTANCE_ID}
  RDS Endpoint:  {db_endpoint}
  Security Group: {default_sg_id}

ACCESO:
  Aplicación:  http://{public_ip}/
  Login:       http://{public_ip}/login.php
  PHP Info:    http://{public_ip}/info.php

CREDENCIALES:
  Usuario: {APP_USER}
  Password: {APP_PASS}

NOTA: Abre en navegador modo PRIVADO/INCOGNITO
""")
