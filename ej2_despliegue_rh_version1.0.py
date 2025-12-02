#!/usr/bin/env python3

import boto3                    # SDK de AWS para Python (para usar EC2, RDS, SSM, etc.)
import time                     # Para esperas entre comandos SSM
import getpass 
from botocore.exceptions import ClientError    # Excepción específica de errores de AWS

# ---------------------------
# CONSTANTES DE CONFIGURACIÓN
# ---------------------------
REGION = 'us-east-1'

ec2 = boto3.client('ec2', region_name=REGION)
ssm = boto3.client('ssm', region_name=REGION)
rds = boto3.client("rds", region_name=REGION)

INSTANCE_NAME = "rh-app-web"
SG_EC2_NAME = "SG-EC2"
DB_INSTANCE_ID = "RDS-Base-De-Datos"
SG_RDS_NAME = "SG-RDS-RDS-Base-De-Datos"
DB_NAME = "demo_db"
DB_USERNAME = "admin"
DB_PASSWORD = None
# ---------------------------
# === Creación de instancia EC2 Y EL USER DATA ===
# ---------------------------
user_data = """#!/bin/bash
sudo dnf clean all
sudo dnf makecache
sudo dnf update -y
# Instalar web + php + mariadb + utilidades
sudo dnf install httpd php php-cli php-fpm php-common php-mysqlnd mariadb105 -y
sudo systemctl enable --now httpd
sudo systemctl enable --now php-fpm
echo '<FilesMatch \\.php$>
  SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost/"
</FilesMatch>' > /etc/httpd/conf.d/php-fpm.conf
sudo mkdir -p /var/www/html
echo "<?php phpinfo(); ?>" > /var/www/html/info.php
sudo systemctl restart httpd php-fpm
"""

print("=" * 60)
print("Lanzando la creación de la infraestructura EC2 y RDS en AWS")
print("Despliegue de aplicación de RRHH.")
print("=" * 60)

# Se Identificará la VPC predeterminada para asociar los Security Groups
vpcs = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
if not vpcs['Vpcs']:
    print("No se pudo localizar la VPC por defecto. Verifica la región y las credenciales de AWS.")
    exit(1)
VPC_ID = vpcs['Vpcs'][0]['VpcId']
print(f"[INFO] Usando VPC por defecto: {VPC_ID}")

# Iniciar una instancia EC2 con el perfil de instancia (Instance Profile) LabRole
print("\n[*] Creando instancia EC2...")
response = ec2.run_instances(
    ImageId='ami-06b21ccaeff8cd686',  # Amazon Linux 2023 en us-east-1
    MinCount=1,
    MaxCount=1,
    InstanceType='t2.micro',
    IamInstanceProfile={'Name': 'LabInstanceProfile'},
    UserData=user_data,
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [{'Key': 'Name', 'Value': INSTANCE_NAME}]
        }
    ]
)

instance_id = response['Instances'][0]['InstanceId']
print(f"[+] Instancia desplegada correctamente. ID: {instance_id}, tag '{INSTANCE_NAME}'")
print("[*] Monitoreando hasta que la instancia esté en estado 'running'...")
print("[*] El arranque suele tomar entre 5 y 8 minutos.")

# Esperar a que la instancia esté en estado running
ec2.get_waiter('instance_status_ok').wait(InstanceIds=[instance_id])
print("[+] Instancia EC2 lista y en estado 'running'.")


# ---------------------------
# CREAR SECURITY GROUP PARA EC2
# ---------------------------
print("\n[*] Preparando el Security Group para la instancia EC2...")
sg_name = SG_EC2_NAME
try:
    response = ec2.create_security_group(
        GroupName=sg_name,
        Description="Permitir trafico web desde cualquier IP",
        VpcId=VPC_ID
    )
    sg_id = response["GroupId"]
    print(f"[+] Security Group de EC2 creado correctamente. ID: {sg_id}")
except ClientError as e:
    error_code = e.response["Error"]["Code"]
    if error_code == "InvalidGroup.Duplicate":
        print("[*] El Security Group ya existe. Obteniendo su ID...")
        sg_id = ec2.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': [sg_name]},
                {'Name': 'vpc-id', 'Values': [VPC_ID]}
            ]
        )["SecurityGroups"][0]["GroupId"]
        print(f"[+] Security Group EC2 encontrado. ID: {sg_id}")
    else:
        raise

# -----------------------------------------------------------------------
# Verificar y agregar la regla HTTP (puerto 80) en caso de ser necesario
#------------------------------------------------------------------------
try:
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    )
    print("[+] Regla HTTP (puerto 80) aplicada correctamente al Security Group EC2.")
except ClientError as e:
    error_code = e.response["Error"]["Code"]
    if error_code == "InvalidPermission.Duplicate":
        print("[*] La regla HTTP ya existe. Continuando...")
    else:
        raise
#------------------------------------------------------
# Agregar regla de SALIDA HTTPS (puerto 443) para SSM
#------------------------------------------------------
try:
    ec2.authorize_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    )
    print("[+] Permiso de tráfico saliente HTTPS (443) habilitado para SSM.")
except ClientError as e:
    error_code = e.response["Error"]["Code"]
    if error_code == "InvalidPermission.Duplicate":
        print("[*] La regla HTTPS saliente ya existe. Continuando...")
    else:
        # Los SGs por defecto ya permiten todo el tráfico saliente,
        # así que este error es esperado
        print("[*] Tráfico saliente ya permitido por defecto.")
#-------------------------------------------------------------------------
# AÑADIR EL SG A LA INSTANCIA EC2 MANTENIENDO LOS SGs EXISTENTES
#-------------------------------------------------------------------------
print(f"\n[*] Actualizando la instancia {instance_id} para incluir el SG {sg_id}...")
try:
    # Listar los SGs actualmente vinculados a la instancia
    current_instance = ec2.describe_instances(InstanceIds=[instance_id])
    current_sgs = current_instance['Reservations'][0]['Instances'][0]['SecurityGroups']
    current_sg_ids = [sg['GroupId'] for sg in current_sgs]
    
    # Incluir el nuevo SG en la lista de asociados si todavía no está incluido
    if sg_id not in current_sg_ids:
        current_sg_ids.append(sg_id)
    
    # Vincular la instancia con todos los Security Groups definidos
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=current_sg_ids
    )
    print(f"[+] Asociación del SG {sg_id} con la instancia realizada con éxito.")
except ClientError as e:
    print("[ERROR] Error inesperado al asociar el SG:")
    raise
#--------------------------------------------------
# MANEJO DE LA INSTANCIA RDS (CREAR U OBTENER EXISTENTE)
#--------------------------------------------------
print(f"\n[*] Buscando instancia RDS '{DB_INSTANCE_ID}'...")

rds_exists = False

try:
    resp = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
    rds_instance = resp["DBInstances"][0]
    rds_exists = True
    print(f"[+] RDS existe (estado: {rds_instance['DBInstanceStatus']}).")
    print("[*] Ingrese la contraseña anterior para continuar:")
    DB_PASS = getpass.getpass().strip()
    DB_PASSWORD = DB_PASS

except ClientError as e:
    if e.response['Error']['Code'] == 'DBInstanceNotFound':
        print("[*] RDS no existe. Creando nueva instancia...")
    else:
        raise

if not rds_exists:
    while True:
        DB_PASS = getpass.getpass('\n[*] Ingresa la contraseña del admin RDS: ').strip()
        if not DB_PASS:
            print('[!] La contraseña no puede estar vacía. Intenta nuevamente.')
            continue
        if len(DB_PASS) < 8:
            print('[!] La contraseña debe tener al menos 8 caracteres. Intenta nuevamente.')
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
        MasterUserPassword=DB_PASS,
        PubliclyAccessible=False,
        BackupRetentionPeriod=0
    )
    print("[*] Esperando a que RDS esté disponible...")
    print("[*] Tiempo estimado: 5-10 minutos.")
    rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=DB_INSTANCE_ID)
    rds_instance = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)["DBInstances"][0]
    print("[+] Instancia RDS creada y disponible.")
#----------------------------------------------
# CREAR SECURITY GROUP PARA RDS 
#----------------------------------------------
print("\n[*] Iniciando configuración del Security Group específico para RDS...")
rds_sg_name = SG_RDS_NAME
try:
    resp = ec2.create_security_group(
        GroupName=rds_sg_name,
        Description="SG para RDS que permite acceso MySQL desde EC2",
        VpcId=VPC_ID
    )
    rds_sg_id = resp["GroupId"]
    print(f"[+] Security Group RDS creado: {rds_sg_id}")
except ClientError as e:
    code = e.response["Error"]["Code"]
    if code == "InvalidGroup.Duplicate":
        sgs = ec2.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': [rds_sg_name]},
                {'Name': 'vpc-id', 'Values': [VPC_ID]}
            ]
        )["SecurityGroups"]
        if not sgs:
            raise
        rds_sg_id = sgs[0]["GroupId"]
        print(f"[+] Security Group RDS existente: {rds_sg_id}")
    else:
        raise
#--------------------------------------------------------------------------------
# Habilitar ingreso al SG de RDS desde el SG de EC2 en el puerto MySQL (3306)
#--------------------------------------------------------------------------------
try:
    ec2.authorize_security_group_ingress(
        GroupId=rds_sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                'UserIdGroupPairs': [{'GroupId': sg_id}]
            }
        ]
    )
    print(f"[+] Regla de ingreso MySQL (puerto 3306) aplicada al SG de RDS para conexiones desde EC2.")
except ClientError as e:
    if e.response["Error"]["Code"] == "InvalidPermission.Duplicate":
        print("[*] La regla MySQL ya existe en el SG RDS. Continuando...")
    else:
        raise
#---------------------------------------------------------------------
# Esperar a que la instancia RDS esté disponible antes de modificarla
#---------------------------------------------------------------------
print(f"\n[*] Chequeando disponibilidad de la instancia RDS {DB_INSTANCE_ID}...")
waiter = rds.get_waiter('db_instance_available')
try:
    rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
    waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID)
    print(f"[+] Instancia RDS disponible.")
except ClientError as e:
    code = e.response['Error']['Code']
    if code == 'DBInstanceNotFoundFault':
        print(f"[ERROR] La instancia RDS '{DB_INSTANCE_ID}' no existe.")
    else:
        print(f"[ERROR] Error inesperado: {e}")
    raise
#--------------------------------------------------------------------------------
# Consultar nuevamente la instancia RDS para asegurarse de tener el endpoint actual
#--------------------------------------------------------------------------------
rds_instance = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)["DBInstances"][0]
endpoint = rds_instance['Endpoint']['Address']
print(f"[+] Endpoint RDS: {endpoint}")
#--------------------------------------------------
# Asignar el Security Group correspondiente a la instancia RDS
#--------------------------------------------------
print("\n[*] Actualizando la instancia RDS para usar el nuevo Security Group...")
try:
    rds.modify_db_instance(
        DBInstanceIdentifier=DB_INSTANCE_ID,
        VpcSecurityGroupIds=[rds_sg_id],
        ApplyImmediately=True
    )
    print(f"[+] SG RDS {rds_sg_name} asociado a la instancia RDS.")
    
    # Esperar a que la modificación se aplique completamente
    print("[*] Esperando a que los cambios de Security Group se propaguen...")
    time.sleep(30)  # Espera 30 segundos para que los cambios de red se apliquen
    
    # Esperar a que RDS vuelva a estar disponible después de la modificación
    waiter = rds.get_waiter('db_instance_available')
    waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID)
    print("[+] Instancia RDS lista después de la modificación.")
    
except ClientError as e:
    print("[ERROR] Error al asociar el SG a la instancia RDS:")
    raise

print(f"\n[+] Instancia RDS {DB_INSTANCE_ID} configurada correctamente.")
#-------------------------------------------------------
# === CONFIGURAR LA APLICACIÓN EN LA INSTANCIA EC2 ===
#-------------------------------------------------------
PUBLIC_ZIP_URL = "https://github.com/Diegogar8/Obligatorio-DevOps-2025/releases/download/v1.0/obligatorio-main.zip"

print("\n[*] Iniciando descarga y extracción del archivo ZIP desde GitHub Release...")
download_and_extract_cmds = [
    "sudo rm -rf /home/ssm-user/app",
    "sudo mkdir -p /home/ssm-user/app",
    f"curl -L {PUBLIC_ZIP_URL} -o /home/ssm-user/app/app.zip",
    "sudo unzip -o /home/ssm-user/app/app.zip -d /home/ssm-user/app/",
    "echo '[CHECK] Contenido /home/ssm-user/app:'",
    "ls -la /home/ssm-user/app"
]


def send_ssm_and_wait_simple(instance_id, commands, timeout=300, comment=""):
    """Envía comandos via SSM y espera el resultado."""
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        Comment=comment
    )
    cmd_id = resp['Command']['CommandId']
    elapsed = 0
    while elapsed < timeout:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ClientError as e:
            msg = str(e)
            if "InvocationDoesNotExist" in msg or "ThrottlingException" in msg:
                time.sleep(2)
                elapsed += 2
                continue
            else:
                raise

        status = inv.get('Status')
        if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
            return status, inv.get('StandardOutputContent', ''), inv.get('StandardErrorContent', '')
        time.sleep(2)
        elapsed += 2
    return 'Timeout', '', 'Timeout esperando descarga'


dl_status, dl_out, dl_err = send_ssm_and_wait_simple(
    instance_id, download_and_extract_cmds, comment="download-extract"
)
print(f"\n[Descarga ZIP] Estado: {dl_status}")
if dl_status != 'Success':
    print('[!] Advertencia: problemas durante la descarga/extracción.')
    if dl_err:
        print(f"    Error: {dl_err}")
#-------------------------------------
# COMANDOS SSM FINALES
#-------------------------------------
print("\n[*] Realizando tareas finales de configuración en EC2...")
print("    (copiar archivos, generar .env, importar SQL, ajustar permisos y reiniciar)")


def send_ssm_and_wait(instance_id, commands, timeout=600, poll=3, comment=""):
    """
    Envía comandos via SSM (commands: list with a single big script is recommended)
    Espera resultado y maneja InvocationDoesNotExist y throttling.
    Retorna (status, stdout, stderr).
    """
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        Comment=comment
    )
    cmd_id = resp["Command"]["CommandId"]
    elapsed = 0
    backoff = 1
    while elapsed < timeout:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ClientError as e:
            msg = str(e)
            if "InvocationDoesNotExist" in msg or "ThrottlingException" in msg:
                time.sleep(backoff)
                elapsed += backoff
                backoff = min(backoff * 2, 10)
                continue
            else:
                raise
        status = inv.get("Status")
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            return status, inv.get("StandardOutputContent", ""), inv.get("StandardErrorContent", "")
        time.sleep(poll)
        elapsed += poll
    return "Timeout", "", "SSM command timed out"


shell_script = f"""#!/bin/bash
set -euo pipefail
echo "[SSM SCRIPT] inicio: $(date)"

REALDIR="$(find /home/ssm-user/app -maxdepth 1 -type d -name 'obligatorio-main*' | head -n1)"
if [ -z "$REALDIR" ]; then
  echo "[ERROR] No se encontró ninguna carpeta obligatorio-main* en /home/ssm-user/app"
  exit 2
fi
#-----------------------------------
# Variables principales del script
#-----------------------------------
EXTRACTED="$REALDIR"
RDS_ENDPOINT="{endpoint}"
DB_NAME="{DB_NAME}"
DB_USER="{DB_USERNAME}"
DB_PASS="{DB_PASSWORD}"
#-------------------------------------------------
# 1) Verificar y crear los directorios necesarios
#-------------------------------------------------
sudo mkdir -p /var/www
sudo mkdir -p /var/www/html
#-------------------------------------------------------------------------
# 2) Copiar y mover el contenido, incluyendo archivos ocultos, si los hay
#-------------------------------------------------------------------------
if [ -d "$REALDIR" ]; then
    shopt -s dotglob nullglob
    if [ -z "$(ls -A "$REALDIR")" ]; then
        echo "[WARN] Directorio $REALDIR vacío, nada para mover"
    else
        sudo mv "$REALDIR"/* /var/www/html/ || true
    fi
    shopt -u dotglob nullglob
else
    echo "[ERROR] REALDIR ($REALDIR) no existe"
    exit 2
fi
#----------------------------------------------------------------------------
# 3) Proteger init_db.sql moviéndolo fuera del webroot, si el archivo existe
#----------------------------------------------------------------------------
if [ -f /var/www/html/init_db.sql ]; then
  sudo mv /var/www/html/init_db.sql /var/www/init_db.sql
else
  echo "[WARN] init_db.sql no encontrado en /var/www/html"
fi
#-----------------------------------------------------------------
# 4) Eliminar README del directorio web en caso de estar presente
#-----------------------------------------------------------------
if [ -f /var/www/html/README.md ]; then
  sudo rm -f /var/www/html/README.md
fi
#----------------------------------------------------------------
# 5) Crear el archivo .env con datos sensibles de manera segura
#----------------------------------------------------------------
sudo bash -c 'cat > /var/www/.env << "EOF"
DB_HOST={endpoint}
DB_NAME={DB_NAME}
DB_USER={DB_USERNAME}
DB_PASS={DB_PASSWORD}
APP_USER=admin
APP_PASS=admin123
EOF'
sudo chown apache:apache /var/www/.env || true
sudo chmod 600 /var/www/.env
#-------------------------------------------------
# 6) Asegurar cliente mysql instalado
#-------------------------------------------------
if ! command -v mysql >/dev/null 2>&1; then
  echo "[INFO] mysql no encontrado, instalando cliente..."
  if command -v dnf >/dev/null 2>&1; then
    sudo dnf -y install mariadb105 || sudo dnf -y install mariadb
  elif command -v yum >/dev/null 2>&1; then
    sudo yum -y install mariadb
  else
    echo "[ERROR] No hay gestor de paquetes conocido (dnf/yum)."
    exit 3
  fi
  echo "[OK] mysql client instalado"
else
  echo "[OK] mysql client ya presente"
fi
#------------------------------------------------------------------------
# 7) Lanzar el script init_db.sql sobre la base de datos RDS (si existe)
#------------------------------------------------------------------------
if [ -f /var/www/init_db.sql ]; then
    TMPCNF="/tmp/.mycred.$$"
    cat > "$TMPCNF" <<EOF
[client]
user={DB_USERNAME}
password={DB_PASSWORD}
host={endpoint}
EOF
    chmod 600 "$TMPCNF"
    echo "[INFO] Ejecutando init_db.sql en $RDS_ENDPOINT..."
    set +e
    mysql --defaults-extra-file="$TMPCNF" {DB_NAME} < /var/www/init_db.sql 2> /tmp/mysql_err.$$
    rc=$?
    set -e
    MYSQL_ERR_OUT="$(cat /tmp/mysql_err.$$ || true)"
    rm -f /tmp/mysql_err.$$ "$TMPCNF"
    if [ $rc -ne 0 ]; then
        if echo "$MYSQL_ERR_OUT" | grep -qi 'already exists'; then
            echo "[WARN] Tablas existentes detectadas, continuando: $MYSQL_ERR_OUT"
        else
            echo "[ERROR] mysql código $rc: $MYSQL_ERR_OUT"
            exit $rc
        fi
    else
        echo "[OK] init_db.sql ejecutado correctamente"
    fi
else
    echo "[WARN] /var/www/init_db.sql no existe; salto ejecución SQL"
fi
#------------------------------------------------------------------------
# 8) Alinear permisos finales de archivos y directorios de la aplicación
#------------------------------------------------------------------------
sudo chown -R apache:apache /var/www/html || true
#----------------------------
# 9) Reiniciar servicios
#----------------------------
sudo systemctl restart httpd || {{ echo '[ERROR] fallo restart httpd'; systemctl status httpd --no-pager || true; exit 4; }}
sudo systemctl restart php-fpm || {{ echo '[ERROR] fallo restart php-fpm'; systemctl status php-fpm --no-pager || true; exit 5; }}

echo "[SSM SCRIPT] fin: $(date)"
"""
#----------------------------------------------------------
# Lanzar este bloque como un único comando en la terminal
#----------------------------------------------------------
status, out, err = send_ssm_and_wait(instance_id, [shell_script], timeout=1200, comment="deploy-full-script")

print(f"\n[Despliegue] Estado SSM: {status}")
if status != "Success":
    print("=" * 40)
    print("STDOUT:")
    print(out)
    print("=" * 40)
    print("STDERR:")
    print(err)
    print("=" * 40)
    print("[ERROR] Fallo en el despliegue final en EC2.")
else:
    print("[+] Despliegue completado exitosamente.")
#----------------------------------------------
# Obtener la IP pública de la instancia EC2
#----------------------------------------------
resp = ec2.describe_instances(InstanceIds=[instance_id])
EC2_public_ip = resp['Reservations'][0]['Instances'][0].get('PublicIpAddress')

if not EC2_public_ip:
    print("\n[ERROR] No fue posible obtener la IP pública de la instancia EC2.")
    print("        Verifica que la instancia tenga una IP pública asociada y esté en estado 'running'.")
else:
    print("\n" + "=" * 60)
    print("   DESPLIEGUE FINALIZADO CORRECTAMENTE   ")
    print("=" * 60)
    print(f"\n[+] Instancia EC2      : {instance_id}")
    print(f"[+] IP pública EC2     : {EC2_public_ip}")
    print(f"[+] Instancia RDS      : {DB_INSTANCE_ID}")
    print(f"[+] Endpoint RDS       : {endpoint}")

    print("\n>>> URL de la aplicación")
    print(f"    http://{EC2_public_ip}/index.php")

    print("\n>>> Página de información de PHP:")
    print(f"    http://{EC2_public_ip}/info.php")
    print("=" * 60)









