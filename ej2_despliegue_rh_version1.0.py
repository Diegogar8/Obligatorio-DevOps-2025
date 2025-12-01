import boto3
import time
import getpass
from botocore.exceptions import ClientError

ec2 = boto3.client('ec2')
rds = boto3.client("rds")

INSTANCE_NAME = "EC2-Obligatorio-Devops"
SG_EC2_NAME = "SG-EC2-Obligatorio"
DB_INSTANCE_ID = "RDS-Obligatorio-Devops"
SG_RDS_NAME = "SG-RDS-Obligatorio"
DB_NAME = "demo_db"
DB_USERNAME = "admin"
DB_PASSWORD = None

PUBLIC_ZIP_URL = "https://github.com/Fabricio-Ramirez/ORTDevOps2025/releases/download/v1.0/obligatorio-main.zip"

print("Bienvenido al script de creación de instancia EC2 y RDS para el obligatorio de DevOps.")

# === BLOQUE DE RDS PRIMERO (para obtener endpoint antes del User Data) ===
print(f"\n[1/5] Buscando RDS '{DB_INSTANCE_ID}'...")
rds_instance = None
endpoint = None

try:
    resp = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
    rds_instance = resp["DBInstances"][0]
    print(f"    → Existe (estado {rds_instance['DBInstanceStatus']}).")
    
    # Si RDS está creándose, esperar
    if rds_instance['DBInstanceStatus'] != 'available':
        print("Esperando a que RDS esté disponible...")
        rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=DB_INSTANCE_ID)
        rds_instance = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)["DBInstances"][0]
    
    endpoint = rds_instance['Endpoint']['Address']
    print(f"    → Endpoint: {endpoint}")
    print("Ingrese contraseña anterior para continuar:")
    DB_PASSWORD = getpass.getpass().strip()
    
except ClientError as e:
    if e.response["Error"]["Code"] == "DBInstanceNotFound":
        print("No existe. Creando RDS...")
        while True:
            DB_PASS = getpass.getpass('\nIngresa la contraseña del admin RDS (mín 8 caracteres): ').strip()
            if not DB_PASS:
                print('La contraseña no puede estar vacía.')
                continue
            if len(DB_PASS) < 8:
                print('La contraseña debe tener al menos 8 caracteres.')
                continue
            break
        
        DB_PASSWORD = DB_PASS
        
        rds.create_db_instance(
            DBName=DB_NAME,
            DBInstanceIdentifier=DB_INSTANCE_ID,
            AllocatedStorage=20,
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername=DB_USERNAME,
            MasterUserPassword=DB_PASSWORD,
            PubliclyAccessible=False,
            BackupRetentionPeriod=0
        )
        print("Esperando RDS disponible (5-10 minutos)...")
        rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=DB_INSTANCE_ID)
        rds_instance = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)["DBInstances"][0]
        endpoint = rds_instance['Endpoint']['Address']
        print(f"    → RDS creado. Endpoint: {endpoint}")
    else:
        raise

# === CREAR SECURITY GROUPS ===
print(f"\n[2/5] Configurando Security Groups...")

# SG para EC2
sg_id = None
try:
    response = ec2.create_security_group(
        GroupName=SG_EC2_NAME,
        Description="Permitir trafico web desde cualquier IP"
    )
    sg_id = response["GroupId"]
    print(f"    → SG EC2 creado: {sg_id}")
except ClientError as e:
    if e.response["Error"]["Code"] == "InvalidGroup.Duplicate":
        sg_id = ec2.describe_security_groups(GroupNames=[SG_EC2_NAME])["SecurityGroups"][0]["GroupId"]
        print(f"    → SG EC2 existente: {sg_id}")
    else:
        raise

# Regla HTTP para EC2
try:
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )
    print("    → Regla HTTP agregada")
except ClientError as e:
    if e.response["Error"]["Code"] == "InvalidPermission.Duplicate":
        print("    → Regla HTTP ya existe")
    else:
        raise

# SG para RDS
rds_sg_id = None
try:
    resp = ec2.create_security_group(
        GroupName=SG_RDS_NAME,
        Description="SG para RDS que permite acceso MySQL desde EC2"
    )
    rds_sg_id = resp["GroupId"]
    print(f"    → SG RDS creado: {rds_sg_id}")
except ClientError as e:
    if e.response["Error"]["Code"] == "InvalidGroup.Duplicate":
        rds_sg_id = ec2.describe_security_groups(GroupNames=[SG_RDS_NAME])["SecurityGroups"][0]["GroupId"]
        print(f"    → SG RDS existente: {rds_sg_id}")
    else:
        raise

# Regla MySQL para RDS (desde SG de EC2)
try:
    ec2.authorize_security_group_ingress(
        GroupId=rds_sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "UserIdGroupPairs": [{"GroupId": sg_id}]
        }]
    )
    print(f"    → Regla MySQL agregada (desde {sg_id})")
except ClientError as e:
    if e.response["Error"]["Code"] == "InvalidPermission.Duplicate":
        print("    → Regla MySQL ya existe")
    else:
        raise

# Asociar SG a RDS
try:
    rds.modify_db_instance(
        DBInstanceIdentifier=DB_INSTANCE_ID,
        VpcSecurityGroupIds=[rds_sg_id],
        ApplyImmediately=True
    )
    print(f"    → SG {rds_sg_id} asociado a RDS")
except ClientError as e:
    print(f"    → Advertencia al asociar SG a RDS: {e}")

# === USER DATA CON TODA LA CONFIGURACIÓN ===
user_data = f"""#!/bin/bash
exec > /var/log/user-data.log 2>&1
set -x

echo "[USER DATA] Inicio: $(date)"

# 1) Actualizar sistema e instalar paquetes
dnf clean all
dnf makecache
dnf update -y
dnf install -y httpd php php-cli php-fpm php-common php-mysqlnd mariadb105 unzip curl

# 2) Habilitar servicios
systemctl enable --now httpd
systemctl enable --now php-fpm

# 3) Configurar PHP-FPM
cat > /etc/httpd/conf.d/php-fpm.conf << 'EOFPHP'
<FilesMatch \\.php$>
  SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost/"
</FilesMatch>
EOFPHP

# 4) Crear directorios
mkdir -p /var/www/html
mkdir -p /home/ec2-user/app

# 5) Descargar y extraer aplicación
cd /home/ec2-user/app
curl -L "{PUBLIC_ZIP_URL}" -o app.zip
unzip -o app.zip

# 6) Encontrar directorio extraído y mover archivos
REALDIR=$(find /home/ec2-user/app -maxdepth 1 -type d -name 'obligatorio-main*' | head -n1)
if [ -n "$REALDIR" ] && [ -d "$REALDIR" ]; then
    shopt -s dotglob nullglob
    mv "$REALDIR"/* /var/www/html/ 2>/dev/null || true
    shopt -u dotglob nullglob
    echo "[OK] Archivos movidos desde $REALDIR"
else
    echo "[WARN] No se encontró directorio obligatorio-main*"
fi

# 7) Mover init_db.sql fuera del webroot
if [ -f /var/www/html/init_db.sql ]; then
    mv /var/www/html/init_db.sql /var/www/init_db.sql
    echo "[OK] init_db.sql movido a /var/www/"
fi

# 8) Eliminar README si existe
rm -f /var/www/html/README.md

# 9) Crear archivo .env
cat > /var/www/.env << 'EOFENV'
DB_HOST={endpoint}
DB_NAME={DB_NAME}
DB_USER={DB_USERNAME}
DB_PASS={DB_PASSWORD}
APP_USER=admin
APP_PASS=admin123
EOFENV

chown apache:apache /var/www/.env
chmod 600 /var/www/.env
echo "[OK] .env creado"

# 10) Crear archivo de prueba PHP
echo "<?php phpinfo(); ?>" > /var/www/html/info.php

# 11) Ejecutar init_db.sql contra RDS
if [ -f /var/www/init_db.sql ]; then
    echo "[INFO] Ejecutando init_db.sql..."
    
    # Esperar a que RDS esté accesible (máx 60 intentos)
    for i in $(seq 1 60); do
        if mysql -h {endpoint} -u {DB_USERNAME} -p'{DB_PASSWORD}' -e "SELECT 1" {DB_NAME} >/dev/null 2>&1; then
            echo "[OK] Conexión a RDS exitosa"
            break
        fi
        echo "Esperando conexión a RDS... intento $i"
        sleep 5
    done
    
    # Ejecutar SQL
    mysql -h {endpoint} -u {DB_USERNAME} -p'{DB_PASSWORD}' {DB_NAME} < /var/www/init_db.sql 2>/tmp/mysql_err.log || true
    
    if [ -s /tmp/mysql_err.log ]; then
        if grep -qi "already exists" /tmp/mysql_err.log; then
            echo "[WARN] Tablas ya existen, continuando..."
        else
            echo "[WARN] Error MySQL: $(cat /tmp/mysql_err.log)"
        fi
    else
        echo "[OK] init_db.sql ejecutado correctamente"
    fi
fi

# 12) Ajustar permisos
chown -R apache:apache /var/www/html

# 13) Reiniciar servicios
systemctl restart httpd
systemctl restart php-fpm

echo "[USER DATA] Fin: $(date)"
echo "DEPLOY_COMPLETE" > /var/www/html/status.txt
"""

# === CREAR INSTANCIA EC2 (SIN IamInstanceProfile) ===
print(f"\n[3/5] Creando instancia EC2...")

response = ec2.run_instances(
    ImageId='ami-06b21ccaeff8cd686',
    MinCount=1,
    MaxCount=1,
    InstanceType='t2.micro',
    SecurityGroupIds=[sg_id],
    UserData=user_data,
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [{'Key': 'Name', 'Value': INSTANCE_NAME}]
        }
    ]
)

instance_id = response['Instances'][0]['InstanceId']
print(f"    → Instancia creada: {instance_id}")

print("    → Esperando estado 'running' (2-3 minutos)...")
ec2.get_waiter('instance_running').wait(InstanceIds=[instance_id])
print(f"    → Instancia en estado 'running'")

# Obtener IP pública
resp = ec2.describe_instances(InstanceIds=[instance_id])
EC2_public_ip = resp['Reservations'][0]['Instances'][0].get('PublicIpAddress')

if not EC2_public_ip:
    print("    → Esperando IP pública...")
    time.sleep(10)
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    EC2_public_ip = resp['Reservations'][0]['Instances'][0].get('PublicIpAddress', 'N/A')

print(f"    → IP pública: {EC2_public_ip}")

# === RESUMEN FINAL ===
print("\n" + "=" * 60)
print("DESPLIEGUE COMPLETADO")
print("=" * 60)


