#!/usr/bin/env python3
"""
Script de despliegue seguro para aplicación de Recursos Humanos.
Arquitectura de dos capas: EC2 (Web Server) + RDS (Base de Datos)
Con medidas de seguridad para proteger información sensible.
"""

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
EC2_SG_NAME = 'rh-app-ec2-sg'              # Security Group para EC2 (Web Server)
RDS_SG_NAME = 'rh-app-rds-sg'              # Security Group para RDS (Base de Datos)
DB_INSTANCE_ID = 'rh-app-db'
DB_NAME = 'demo_db'
DB_USER = 'admin'
APP_NAME = 'rh-app-web'

# IAM Instance Profile para SSM
IAM_INSTANCE_PROFILE = 'LabInstanceProfile'
IAM_INSTANCE_PROFILE_ARN = 'arn:aws:iam::535735706108:instance-profile/LabInstanceProfile'

# ---------------------------
# LECTURA DE VARIABLES DE ENTORNO
# ---------------------------
EC2_SG_ID_ENV = os.environ.get('EC2_SECURITY_GROUP_ID')
RDS_SG_ID_ENV = os.environ.get('RDS_SECURITY_GROUP_ID')
RDS_ENDPOINT_ENV = os.environ.get('RDS_ENDPOINT')
RDS_PASSWORD = os.environ.get('RDS_ADMIN_PASSWORD')
VPC_ID_ENV = os.environ.get('VPC_ID')

if not RDS_PASSWORD:
    print("Error: Debes definir la variable de entorno RDS_ADMIN_PASSWORD", file=sys.stderr)
    print("Ejemplo: export RDS_ADMIN_PASSWORD='tu_password_seguro'", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# CLIENTES DE AWS
# ---------------------------
ec2 = boto3.client('ec2', region_name=REGION)
ec2_resource = boto3.resource('ec2', region_name=REGION)
rds = boto3.client('rds', region_name=REGION)
ssm = boto3.client('ssm', region_name=REGION)

# ---------------------------
# FUNCIONES AUXILIARES
# ---------------------------
def get_default_vpc_id():
    """Obtiene el ID de la VPC por defecto."""
    try:
        response = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
        if response['Vpcs']:
            return response['Vpcs'][0]['VpcId']
    except ClientError as e:
        print(f"⚠ Error obteniendo VPC por defecto: {e}")
    return None

def wait_for_ssm_agent(instance_id, max_attempts=30, delay=10):
    """Espera a que el agente SSM esté disponible en la instancia."""
    print("  Esperando a que el agente SSM esté disponible...")
    for attempt in range(max_attempts):
        try:
            response = ssm.describe_instance_information(
                Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
            )
            if response['InstanceInformationList']:
                print("  ✓ Agente SSM disponible")
                return True
        except ClientError:
            pass
        time.sleep(delay)
    return False

def run_ssm_command(instance_id, commands, description=""):
    """Ejecuta comandos en la instancia via SSM y espera el resultado."""
    if description:
        print(f"  Ejecutando: {description}")
    
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': commands},
            TimeoutSeconds=300
        )
        command_id = response['Command']['CommandId']
        
        # Esperar resultado
        while True:
            try:
                output = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                if output['Status'] in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                    break
            except ClientError as e:
                if 'InvocationDoesNotExist' not in str(e):
                    raise
            time.sleep(2)
        
        if output['Status'] == 'Success':
            print(f"  ✓ Comando ejecutado exitosamente")
            if output.get('StandardOutputContent'):
                print("  Output:")
                for line in output['StandardOutputContent'].split('\n')[:10]:
                    if line.strip():
                        print(f"    {line}")
            return True, output
        else:
            print(f"  ✗ Comando falló con estado: {output['Status']}")
            if output.get('StandardErrorContent'):
                print(f"  Error: {output['StandardErrorContent'][:500]}")
            return False, output
            
    except ClientError as e:
        print(f"  ✗ Error ejecutando comando SSM: {e}")
        return False, None

# ---------------------------
# INICIO DEL DESPLIEGUE
# ---------------------------
print("=" * 70)
print("DESPLIEGUE SEGURO - APLICACIÓN DE RECURSOS HUMANOS")
print("Arquitectura: EC2 (Web Server) + RDS (Base de Datos)")
print("=" * 70)

# Obtener VPC ID
vpc_id = VPC_ID_ENV or get_default_vpc_id()
if not vpc_id:
    print("Error: No se pudo determinar el VPC ID", file=sys.stderr)
    print("Define la variable de entorno VPC_ID", file=sys.stderr)
    sys.exit(1)
print(f"\n✓ Usando VPC: {vpc_id}")

# ---------------------------
# PASO 1: SECURITY GROUP PARA EC2 (Web Server)
# ---------------------------
print("\n[1/5] Configurando Security Group para EC2 (Web Server)...")
ec2_sg_id = None

if EC2_SG_ID_ENV:
    ec2_sg_id = EC2_SG_ID_ENV
    print(f"✓ Usando Security Group EC2 especificado: {ec2_sg_id}")
else:
    try:
        response = ec2.create_security_group(
            GroupName=EC2_SG_NAME,
            Description='Security Group para Web Server - Solo HTTP/HTTPS desde Internet',
            VpcId=vpc_id
        )
        ec2_sg_id = response['GroupId']
        print(f"✓ Security Group EC2 creado: {ec2_sg_id}")
        
        # Reglas de entrada: Solo HTTP y HTTPS desde Internet
        # NOTA: SSH removido por seguridad - usar SSM Session Manager
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
        print("✓ Reglas de seguridad EC2 configuradas:")
        print("  - HTTP (80): Abierto a Internet")
        print("  - HTTPS (443): Abierto a Internet")
        print("  - SSH: Deshabilitado (usar SSM Session Manager)")
        
        # Agregar tags
        ec2.create_tags(
            Resources=[ec2_sg_id],
            Tags=[
                {'Key': 'Name', 'Value': EC2_SG_NAME},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Web'}
            ]
        )
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                response = ec2.describe_security_groups(
                    Filters=[
                        {'Name': 'group-name', 'Values': [EC2_SG_NAME]},
                        {'Name': 'vpc-id', 'Values': [vpc_id]}
                    ]
                )
                ec2_sg_id = response['SecurityGroups'][0]['GroupId']
                print(f"⚠ Security Group EC2 ya existe: {ec2_sg_id}")
            except Exception as e2:
                print(f"⚠ Error obteniendo SG existente: {e2}")
        else:
            print(f"⚠ Error creando Security Group EC2: {e}")

if not ec2_sg_id:
    print("Error: No se pudo crear/obtener Security Group para EC2", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 2: SECURITY GROUP PARA RDS (Base de Datos)
# ---------------------------
print("\n[2/5] Configurando Security Group para RDS (Base de Datos)...")
rds_sg_id = None

if RDS_SG_ID_ENV:
    rds_sg_id = RDS_SG_ID_ENV
    print(f"✓ Usando Security Group RDS especificado: {rds_sg_id}")
else:
    try:
        response = ec2.create_security_group(
            GroupName=RDS_SG_NAME,
            Description='Security Group para RDS - Solo MySQL desde EC2 Web Server',
            VpcId=vpc_id
        )
        rds_sg_id = response['GroupId']
        print(f"✓ Security Group RDS creado: {rds_sg_id}")
        
        # Regla de entrada: MySQL SOLO desde el Security Group de EC2
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
                            'Description': 'MySQL solo desde EC2 Web Server'
                        }
                    ]
                }
            ]
        )
        print("✓ Reglas de seguridad RDS configuradas:")
        print(f"  - MySQL (3306): Solo desde Security Group EC2 ({ec2_sg_id})")
        print("  - Sin acceso público a Internet")
        
        # Agregar tags
        ec2.create_tags(
            Resources=[rds_sg_id],
            Tags=[
                {'Key': 'Name', 'Value': RDS_SG_NAME},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Database'}
            ]
        )
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                response = ec2.describe_security_groups(
                    Filters=[
                        {'Name': 'group-name', 'Values': [RDS_SG_NAME]},
                        {'Name': 'vpc-id', 'Values': [vpc_id]}
                    ]
                )
                rds_sg_id = response['SecurityGroups'][0]['GroupId']
                print(f"⚠ Security Group RDS ya existe: {rds_sg_id}")
                
                # Verificar si la regla de MySQL desde EC2 ya existe
                try:
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
                                        'Description': 'MySQL solo desde EC2 Web Server'
                                    }
                                ]
                            }
                        ]
                    )
                    print(f"✓ Regla MySQL agregada al SG RDS existente")
                except ClientError as e3:
                    if 'InvalidPermission.Duplicate' in str(e3):
                        print("✓ Regla MySQL ya configurada")
                    else:
                        print(f"⚠ No se pudo agregar regla: {e3}")
            except Exception as e2:
                print(f"⚠ Error obteniendo SG existente: {e2}")
        else:
            print(f"⚠ Error creando Security Group RDS: {e}")

if not rds_sg_id:
    print("Error: No se pudo crear/obtener Security Group para RDS", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 3: CREAR INSTANCIA RDS
# ---------------------------
print("\n[3/5] Configurando RDS (Base de Datos)...")
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
            PubliclyAccessible=False,           # ✓ Sin acceso público
            StorageEncrypted=True,              # ✓ Encriptación en reposo
            BackupRetentionPeriod=7,            # ✓ Backups retenidos 7 días
            DeletionProtection=False,           # Cambiar a True en producción
            VpcSecurityGroupIds=[rds_sg_id],    # ✓ Usar SG dedicado para RDS
            Tags=[
                {'Key': 'Name', 'Value': DB_INSTANCE_ID},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'DataClassification', 'Value': 'Confidential'}
            ]
        )
        print(f"✓ Instancia RDS creada: {DB_INSTANCE_ID}")
        print("  Configuración de seguridad:")
        print("  - Encriptación en reposo: ✓ Habilitada")
        print("  - Acceso público: ✓ Deshabilitado")
        print(f"  - Security Group: {rds_sg_id}")
        print("  - Backups automáticos: ✓ 7 días")
        
        print("\n  Esperando a que RDS esté disponible...")
        waiter = rds.get_waiter('db_instance_available')
        waiter.wait(
            DBInstanceIdentifier=DB_INSTANCE_ID,
            WaiterConfig={'Delay': 30, 'MaxAttempts': 40}
        )
        
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
        else:
            print(f"⚠ Error con RDS: {e}")

if not db_endpoint:
    db_endpoint = "localhost"
    print("⚠ Usando placeholder para RDS. Configura manualmente después.")

# ---------------------------
# PASO 4: CREAR INSTANCIA EC2 CON SSM
# ---------------------------
print("\n[4/5] Creando instancia EC2 (Web Server)...")

# User data mínimo - NO incluye credenciales por seguridad
user_data_minimal = '''#!/bin/bash
yum install -y amazon-ssm-agent || true
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
'''

try:
    instance_params = {
        'ImageId': AMI_ID,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': INSTANCE_TYPE,
        'IamInstanceProfile': {'Name': IAM_INSTANCE_PROFILE},
        'SecurityGroupIds': [ec2_sg_id],
        'UserData': user_data_minimal,
        'TagSpecifications': [
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': APP_NAME},
                    {'Key': 'Application', 'Value': 'Recursos Humanos'},
                    {'Key': 'ManagedBy', 'Value': 'SSM'}
                ]
            }
        ],
        'MetadataOptions': {
            'HttpTokens': 'required',           # ✓ IMDSv2 requerido
            'HttpEndpoint': 'enabled'
        }
    }
    
    response = ec2.run_instances(**instance_params)
    instance_id = response['Instances'][0]['InstanceId']
    print(f"✓ Instancia EC2 creada: {instance_id}")
    
    # Esperar estado running
    print("\n  Esperando a que la instancia esté en estado 'running'...")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    print("  ✓ Instancia en estado 'running'")
    
    # Esperar verificaciones de estado
    print("  Esperando verificaciones de estado...")
    waiter = ec2.get_waiter('instance_status_ok')
    waiter.wait(InstanceIds=[instance_id])
    print("  ✓ Verificaciones de estado OK")
    
    # Obtener IP pública
    response = ec2.describe_instances(InstanceIds=[instance_id])
    public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress', 'N/A')
    print(f"  ✓ IP pública: {public_ip}")
    
except ClientError as e:
    print(f"✗ Error creando instancia EC2: {e}", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 5: CONFIGURAR WEB SERVER VIA SSM
# ---------------------------
print("\n[5/5] Configurando Web Server via SSM...")

if not wait_for_ssm_agent(instance_id, max_attempts=30, delay=10):
    print("⚠ SSM agent no disponible.")
else:
    # Contenido del archivo index.html
    index_html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Document</title>
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <meta name="description" content="Description">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-scale=1.0">
    <link rel="stylesheet" href="//cdn.jsdelivr.net/npm/docsify@4/lib/themes/vue.css">
</head>
<body>
    <div id="app"></div>
    <script>
        window.$docsify = {
            name: '',
            repo: ''
        }
    </script>
    <!-- Docsify v4 -->
    <script src="//cdn.jsdelivr.net/npm/docsify@4"></script>
</body>
</html>'''

    # Comando 1: Instalar Apache
    print("\n  Paso 5.1: Instalando Apache...")
    install_commands = [
        'yum update -y',
        'yum install -y httpd',
        'systemctl enable httpd',
        'systemctl start httpd'
    ]
    success, output = run_ssm_command(instance_id, install_commands, "Instalación de Apache")
    
    if success:
        # Comando 2: Desplegar index.html
        print("\n  Paso 5.2: Desplegando index.html...")
        deploy_commands = [
            'mkdir -p /var/www/html',
            f"cat > /var/www/html/index.html << 'EOFHTML'\n{index_html_content}\nEOFHTML",
            'chown -R apache:apache /var/www/html',
            'chmod 644 /var/www/html/index.html',
            'systemctl restart httpd',
            'echo "Despliegue completado - $(date)"'
        ]
        success, output = run_ssm_command(instance_id, deploy_commands, "Despliegue de archivos web")
        
        if success:
            print("\n  Paso 5.3: Verificando servicio Apache...")
            verify_commands = [
                'systemctl status httpd --no-pager',
                'curl -s -o /dev/null -w "%{http_code}" http://localhost/'
            ]
            run_ssm_command(instance_id, verify_commands, "Verificación de Apache")

# ---------------------------
# RESUMEN FINAL
# ---------------------------
print("\n" + "=" * 70)
print("DESPLIEGUE COMPLETADO")
print("=" * 70)

print("\n📋 RECURSOS CREADOS:")
print(f"  ├─ Security Group EC2: {ec2_sg_id}")
print(f"  ├─ Security Group RDS: {rds_sg_id}")
print(f"  ├─ Instancia RDS:      {DB_INSTANCE_ID}")
print(f"  ├─ Instancia EC2:      {instance_id}")
print(f"  └─ IP Pública EC2:     {public_ip}")

print("\n🔒 MEDIDAS DE SEGURIDAD:")
print("  ✓ Security Groups separados por capa")
print("  ✓ RDS solo accesible desde EC2")
print("  ✓ Encriptación en reposo para RDS")
print("  ✓ SSH deshabilitado - usar SSM")
print("  ✓ IMDSv2 requerido en EC2")
print("  ✓ Sin credenciales en user_data")

print(f"\n🌐 ACCESO: http://{public_ip}/")
print("=" * 70)
    
except ClientError as e:
    print(f"✗ Error creando instancia EC2: {e}", file=sys.stderr)
    sys.exit(1)



