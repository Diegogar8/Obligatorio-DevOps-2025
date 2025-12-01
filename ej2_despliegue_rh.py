#!/usr/bin/env python3

import boto3          # SDK de AWS para Python (para usar EC2, RDS, SSM, etc.)
import os             # Para leer variables de entorno del sistema
import sys            # Para salir con códigos de error y escribir en stderr
import time           # Para esperas entre comandos SSM
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
GITHUB_REPO_URL = 'https://github.com/ORT-AII-ProgramacionDevOps/obligatorio.git'  # URL del repositorio

# Credenciales por defecto de la aplicación
APP_USER = 'admin'
APP_PASS = 'admin123'

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
# CLIENTES DE AWS (EC2, RDS y SSM)
# ---------------------------
ec2 = boto3.client('ec2', region_name=REGION)  # Cliente para interactuar con EC2
rds = boto3.client('rds', region_name=REGION)  # Cliente para interactuar con RDS
ssm = boto3.client('ssm', region_name=REGION)  # Cliente para interactuar con SSM

# ---------------------------
# FUNCIÓN AUXILIAR PARA EJECUTAR COMANDOS SSM
# ---------------------------
def run_ssm_command(instance_id, commands, description=""):
    """
    Ejecuta comandos en una instancia EC2 a través de SSM y espera su finalización.
    
    Args:
        instance_id: ID de la instancia EC2
        commands: Lista de comandos a ejecutar
        description: Descripción del comando para logs
    
    Returns:
        True si el comando fue exitoso, False en caso contrario
    """
    try:
        if description:
            print(f"  Ejecutando: {description}...")
        
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': commands},
            TimeoutSeconds=600  # Timeout de 10 minutos
        )
        command_id = response['Command']['CommandId']
        
        # Esperar a que el comando termine
        max_attempts = 60
        for attempt in range(max_attempts):
            time.sleep(5)  # Esperar 5 segundos entre consultas
            
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
                # Si está 'InProgress' o 'Pending', seguir esperando
                
            except ClientError as e:
                if 'InvocationDoesNotExist' in str(e):
                    # El comando aún no está registrado, seguir esperando
                    continue
                raise
        
        print(f"  ⚠ Timeout esperando comando SSM")
        return False
        
    except ClientError as e:
        print(f"  ✗ Error ejecutando comando SSM: {e}")
        return False

# Mensajes iniciales de log
print("=" * 60)
print("INICIANDO DESPLIEGUE DE APLICACIÓN DE RECURSOS HUMANOS")
print("=" * 60)

print("\n[1/6] Configurando Security Group...")
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

print("\n[2/6] Configurando RDS...")
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

print("\n[3/6] Creando instancia EC2...")
try:
    # Parámetros para crear la instancia EC2
    instance_params = {
        'ImageId': AMI_ID,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': INSTANCE_TYPE,
        'IamInstanceProfile': {'Name': 'LabInstanceProfile'},  # Perfil de rol IAM para SSM
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
    print("Esperando a que la instancia esté en estado 'running'...")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    print(f"✓ Instancia en estado 'running'")
    
    # Esperar a que la instancia esté completamente lista para SSM
    print("Esperando a que la instancia pase los checks de estado (necesario para SSM)...")
    waiter_status = ec2.get_waiter('instance_status_ok')
    waiter_status.wait(InstanceIds=[instance_id])
    print(f"✓ Instancia lista para recibir comandos SSM")
    
    # Una vez corriendo, se obtiene su IP pública
    response = ec2.describe_instances(InstanceIds=[instance_id])
    public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress', 'N/A')
    print(f"  IP pública: {public_ip}")
    
except ClientError as e:
    # Si hay error creando la EC2, se imprime y se sale
    print(f"✗ Error creando instancia EC2: {e}", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# CONFIGURACIÓN VÍA SSM
# ---------------------------
print("\n[4/6] Configurando servidor mediante SSM...")

# Esperar un poco más para asegurar que el agente SSM esté completamente activo
print("Esperando que el agente SSM esté activo...")
time.sleep(30)

# 1) Instalar git y clonar el repositorio
print("\n  >> Instalando git y clonando repositorio...")
clone_commands = [
    'sudo dnf -y install git',
    f'sudo git clone {GITHUB_REPO_URL} /tmp/obligatorio',
    'sudo mkdir -p /var/www/html',
    # Mover archivos del repo a /var/www/html (excepto README.md e init_db.sql)
    'sudo cp -r /tmp/obligatorio/* /var/www/html/ 2>/dev/null || true',
    'sudo rm -f /var/www/html/README.md 2>/dev/null || true',
    'sudo rm -f /var/www/html/init_db.sql 2>/dev/null || true',
    # Mover init_db.sql a /var/www (fuera del webroot)
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
# Solo tiene sentido si hay un endpoint real de RDS (no localhost)
if db_endpoint and db_endpoint != "localhost":
    print("\n[5/6] Configurando acceso de RDS desde EC2...")
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
# Instrucciones finales dependen de si se configuró RDS real o solo placeholder
if db_endpoint and db_endpoint != "localhost":
    print(f"  1. Los archivos de la aplicación ya están en /var/www/html")
    print(f"  2. El archivo .env está configurado en /var/www/.env")
    print(f"  3. El archivo init_db.sql está en /var/www/init_db.sql")
    print(f"  4. Accede a la aplicación en: http://{public_ip}/login.php")
    print(f"  5. Prueba PHP en: http://{public_ip}/info.php")
    print(f"  6. Usuario por defecto: {APP_USER} / {APP_PASS}")
    print(f"  7. ¡Cambia las contraseñas por defecto en producción!")
else:
    print(f"  1. Configura el endpoint de RDS en /var/www/.env en la instancia EC2")
    print(f"  2. Los archivos de la aplicación ya están en /var/www/html")
    print(f"  3. Ejecuta init_db.sql en RDS desde la instancia EC2:")
    print(f"     mysql -h <endpoint-rds> -u {DB_USER} -p<contraseña> {DB_NAME} < /var/www/init_db.sql")
    print(f"  4. Accede a la aplicación en: http://{public_ip}/login.php")
    print(f"  5. Prueba PHP en: http://{public_ip}/info.php")
    print(f"  6. Usuario por defecto: {APP_USER} / {APP_PASS}")

print(f"\n📌 Nota: Si falta el favicon.ico, puedes ignorar el error o subir un archivo vacío.")
    print(f"  4. Accede a la aplicación en: http://{public_ip}/login.php")
    print(f"  5. Usuario por defecto: admin / admin123")

