#!/usr/bin/env python3

import boto3
import os
import sys
import time
from botocore.exceptions import ClientError

# ---------------------------
# CONSTANTES DE CONFIGURACIÓN
# ---------------------------
REGION = 'us-east-1'
AMI_ID = 'ami-06b21ccaeff8cd686'
INSTANCE_TYPE = 't2.micro'
SG_NAME = 'rh-app-sg'
DB_INSTANCE_ID = 'rh-app-db'
DB_NAME = 'demo_db'
DB_USER = 'admin'
APP_NAME = 'rh-app-web'
GITHUB_REPO_URL = 'https://github.com/ORT-AII-ProgramacionDevOps/obligatorio.git'
INSTANCE_PROFILE_ARN = 'arn:aws:iam::535735706108:instance-profile/LabInstanceProfile'

APP_USER = 'admin'
APP_PASS = 'admin123'

# ---------------------------
# LECTURA DE VARIABLES DE ENTORNO
# ---------------------------
SG_ID_ENV = os.environ.get('SECURITY_GROUP_ID')
RDS_ENDPOINT_ENV = os.environ.get('RDS_ENDPOINT')
RDS_PASSWORD = os.environ.get('RDS_ADMIN_PASSWORD')

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

# ---------------------------
# FUNCIÓN AUXILIAR PARA EJECUTAR COMANDOS SSM
# ---------------------------
def run_ssm_command(instance_id, commands, description=""):
    """
    Ejecuta comandos en una instancia EC2 a través de SSM y espera su finalización.
    """
    try:
        if description:
            print(f"  Ejecutando: {description}...")
        
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': commands},
            TimeoutSeconds=600
        )
        command_id = response['Command']['CommandId']
        
        max_attempts = 60
        for attempt in range(max_attempts):
            time.sleep(5)
            
            try:
                result = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                status = result['Status']
                
                if status == 'Success':
                    print(f"  ✓ Comando completado exitosamente")
                    return True
                elif status in ['Failed', 'Cancelled', 'TimedOut']:
                    print(f"  ✗ Comando falló con estado: {status}")
                    if result.get('StandardErrorContent'):
                        print(f"    Error: {result['StandardErrorContent'][:500]}")
                    return False
                
            except ClientError as e:
                if 'InvocationDoesNotExist' in str(e):
                    continue
                raise
        
        print(f"  ⚠ Timeout esperando comando SSM")
        return False
        
    except ClientError as e:
        print(f"  ✗ Error ejecutando comando SSM: {e}")
        return False

# ---------------------------
# INICIO DEL SCRIPT
# ---------------------------
print("=" * 60)
print("INICIANDO DESPLIEGUE DE APLICACIÓN DE RECURSOS HUMANOS")
print("=" * 60)

print("\n[1/6] Configurando Security Group...")
sg_id = None

if SG_ID_ENV:
    sg_id = SG_ID_ENV
    print(f"✓ Usando Security Group especificado: {sg_id}")
else:
    try:
        response = ec2.create_security_group(
            GroupName=SG_NAME,
            Description='Security Group para aplicación de RH - Permite HTTP, HTTPS y SSH'
        )
        sg_id = response['GroupId']
        print(f"✓ Security Group creado: {sg_id}")
        
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP'}]},
                {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS'}]},
                {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH'}]}
            ]
        )
        print(f"✓ Reglas de seguridad configuradas")
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                response = ec2.describe_security_groups(GroupNames=[SG_NAME])
                sg_id = response['SecurityGroups'][0]['GroupId']
                print(f"⚠ Security Group ya existe: {sg_id}")
            except:
                pass
        if 'UnauthorizedOperation' in str(e) or error_code == 'UnauthorizedOperation':
            print("⚠ No se tienen permisos para crear/listar Security Groups")
            print("  Nota: Puedes especificar un Security Group ID con:")
            print("  export SECURITY_GROUP_ID='sg-xxxxxxxxxxxxx'")
            sg_id = None

if sg_id is None:
    print("⚠ No se especificó Security Group - la instancia usará el default de la VPC")

print("\n[2/6] Configurando RDS...")
db_endpoint = None

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
            PubliclyAccessible=False,
            StorageEncrypted=True,
            BackupRetentionPeriod=7,
            Tags=[
                {'Key': 'Name', 'Value': DB_INSTANCE_ID},
                {'Key': 'Application', 'Value': 'Recursos Humanos'}
            ]
        )
        print(f"✓ Instancia RDS creada: {DB_INSTANCE_ID}")
        print("  - Encriptación en reposo: Habilitada")
        print("  - Acceso público: Deshabilitado")
        
        print("Esperando a que RDS esté disponible...")
        waiter = rds.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID, WaiterConfig={'Delay': 30, 'MaxAttempts': 40})
        
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

if not db_endpoint:
    db_endpoint = "localhost"
    print(f"⚠ Usando placeholder para RDS endpoint. Configura manualmente después.")

print("\n[3/6] Creando instancia EC2...")
try:
    instance_params = {
        'ImageId': AMI_ID,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': INSTANCE_TYPE,
        'IamInstanceProfile': {
            'Arn': INSTANCE_PROFILE_ARN
        },
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
    
    if sg_id:
        instance_params['SecurityGroupIds'] = [sg_id]
    
    response = ec2.run_instances(**instance_params)
    instance_id = response['Instances'][0]['InstanceId']
    print(f"✓ Instancia EC2 creada: {instance_id}")
    
    print("Esperando a que la instancia esté en estado 'running'...")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    print(f"✓ Instancia en estado 'running'")
    
    print("Esperando a que la instancia pase los checks de estado (necesario para SSM)...")
    waiter_status = ec2.get_waiter('instance_status_ok')
    waiter_status.wait(InstanceIds=[instance_id])
    print(f"✓ Instancia lista para recibir comandos SSM")
    
    response = ec2.describe_instances(InstanceIds=[instance_id])
    public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress', 'N/A')
    print(f"  IP pública: {public_ip}")
    
except ClientError as e:
    print(f"✗ Error creando instancia EC2: {e}", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# CONFIGURACIÓN VÍA SSM
# ---------------------------
print("\n[4/6] Configurando servidor mediante SSM...")

print("Esperando que el agente SSM esté activo...")
time.sleep(30)

# 1) Instalar git y clonar el repositorio
print("\n  >> Instalando git y clonando repositorio...")
clone_commands = [
    'sudo dnf -y install git',
    f'sudo git clone {GITHUB_REPO_URL} /tmp/obligatorio',
    'sudo mkdir -p /var/www/html',
    'sudo cp -r /tmp/obligatorio/* /var/www/html/ 2>/dev/null || true',
    'sudo rm -f /var/www/html/README.md 2>/dev/null || true',
    'sudo rm -f /var/www/html/init_db.sql 2>/dev/null || true',
    'sudo cp /tmp/obligatorio/init_db.sql /var/www/init_db.sql 2>/dev/null || true',
    'sudo rm -rf /tmp/obligatorio'
]
if not run_ssm_command(instance_id, clone_commands, "Clonando repositorio GitHub"):
    print("⚠ Hubo problemas clonando el repositorio, continuando...")

# 2) Actualizar sistema e instalar Apache + PHP
print("\n  >> Instalando Apache y PHP...")
install_commands = [
    'sudo dnf clean all',
    'sudo dnf makecache',
    'sudo dnf -y update',
    'sudo dnf -y install httpd php php-cli php-fpm php-common php-mysqlnd mariadb105'
]
if not run_ssm_command(instance_id, install_commands, "Instalando paquetes"):
    print("⚠ Hubo problemas instalando paquetes, continuando...")

# 3) Habilitar y arrancar servicios
print("\n  >> Habilitando servicios...")
service_commands = [
    'sudo systemctl enable --now httpd',
    'sudo systemctl enable --now php-fpm'
]
if not run_ssm_command(instance_id, service_commands, "Habilitando servicios"):
    print("⚠ Hubo problemas habilitando servicios, continuando...")

# 4) Configurar PHP-FPM para Apache
print("\n  >> Configurando PHP-FPM...")
phpfpm_commands = [
    '''echo '<FilesMatch \\.php$>
  SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost/"
</FilesMatch>' | sudo tee /etc/httpd/conf.d/php-fpm.conf'''
]
if not run_ssm_command(instance_id, phpfpm_commands, "Configurando PHP-FPM"):
    print("⚠ Hubo problemas configurando PHP-FPM, continuando...")

# 5) Crear archivo de prueba info.php
print("\n  >> Creando archivo de prueba PHP...")
info_commands = [
    'echo "<?php phpinfo(); ?>" | sudo tee /var/www/html/info.php'
]
if not run_ssm_command(instance_id, info_commands, "Creando info.php"):
    print("⚠ Hubo problemas creando info.php, continuando...")

# 6) Crear archivo .env fuera del webroot
print("\n  >> Creando archivo .env...")
env_content = f'''DB_HOST={db_endpoint}
DB_NAME={DB_NAME}
DB_USER={DB_USER}
DB_PASS={RDS_PASSWORD}
APP_USER={APP_USER}
APP_PASS={APP_PASS}'''

env_commands = [
    f'''sudo tee /var/www/.env >/dev/null <<'ENV'
{env_content}
ENV''',
    'sudo chown apache:apache /var/www/.env',
    'sudo chmod 600 /var/www/.env'
]
if not run_ssm_command(instance_id, env_commands, "Creando .env"):
    print("⚠ Hubo problemas creando .env, continuando...")

# 7) Configurar permisos y reiniciar servicios
print("\n  >> Configurando permisos y reiniciando servicios...")
final_commands = [
    'sudo chown -R apache:apache /var/www/html',
    'sudo systemctl restart httpd php-fpm'
]
if not run_ssm_command(instance_id, final_commands, "Finalizando configuración"):
    print("⚠ Hubo problemas finalizando configuración, continuando...")

print("\n✓ Configuración SSM completada")

# ---------------------------
# CONFIGURACIÓN DE ACCESO ENTRE EC2 Y RDS
# ---------------------------
if db_endpoint and db_endpoint != "localhost":
    print("\n[5/6] Configurando acceso de RDS desde EC2...")
    try:
        db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
        db_sg_id = db_response['DBInstances'][0]['VpcSecurityGroups'][0]['VpcSecurityGroupId'] if db_response['DBInstances'][0].get('VpcSecurityGroups') else None
        
        if db_sg_id and sg_id:
            try:
                ec2_sg = boto3.resource('ec2', region_name=REGION).SecurityGroup(db_sg_id)
                try:
                    ec2_sg.authorize_ingress(
                        GroupId=db_sg_id,
                        IpPermissions=[
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 3306,
                                'ToPort': 3306,
                                'UserIdGroupPairs': [{'GroupId': sg_id}]
                            }
                        ]
                    )
                    print(f"✓ Acceso MySQL configurado desde EC2")
                except ClientError as e:
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
    print("\n[5/6] Saltando configuración de acceso RDS (no hay RDS configurado)")

# ---------------------------
# INICIALIZAR BASE DE DATOS
# ---------------------------
if db_endpoint and db_endpoint != "localhost":
    print("\n[6/6] Inicializando base de datos...")
    init_db_command = [
        f'mysql -h {db_endpoint} -u {DB_USER} -p{RDS_PASSWORD} {DB_NAME} < /var/www/init_db.sql'
    ]
    if run_ssm_command(instance_id, init_db_command, "Ejecutando init_db.sql"):
        print("✓ Base de datos inicializada correctamente")
    else:
        print("⚠ No se pudo inicializar la base de datos automáticamente")
        print("  Ejecuta manualmente desde la instancia EC2:")
        print(f"  mysql -h {db_endpoint} -u {DB_USER} -p{RDS_PASSWORD} {DB_NAME} < /var/www/init_db.sql")
else:
    print("\n[6/6] Saltando inicialización de BD (no hay RDS configurado)")

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
if db_endpoint and db_endpoint != "localhost":
    print(f"  1. Los archivos de la aplicación ya están en /var/www/html")
    print(f"  2. El archivo .env está configurado en /var/www/.env")
    print(f"  3. El archivo init_db.sql está en /var/www/init_db.sql")
    print(f"  4. Accede a la aplicación en: http://{public_ip}/login.php")
    print(f"  5. Prueba PHP en: http://{public_ip}/info.php")
    print(f"  6. Usuario por defecto: {APP_USER} / {APP_PASS}")
    print(f"  7. ¡Cambia las contraseñas por defecto en producción!")


