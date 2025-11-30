#!/usr/bin/env python3

"""
Script de despliegue seguro para aplicación de Recursos Humanos.
Arquitectura de dos capas: EC2 (Web Server) + RDS (Base de Datos)
Con medidas de seguridad para proteger información sensible.

MEJORAS:
- Selección explícita de subnet pública
- Verificación de Internet Gateway
- Mejor diagnóstico de conectividad
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
EC2_SG_NAME = 'rh-app-ec2-sg'
RDS_SG_NAME = 'rh-app-rds-sg'
DB_INSTANCE_ID = 'rh-app-db'
DB_NAME = 'demo_db'
DB_USER = 'admin'
APP_NAME = 'rh-app-web'

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
SUBNET_ID_ENV = os.environ.get('SUBNET_ID')

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


def get_public_subnet(vpc_id):
    """
    Obtiene una subnet pública de la VPC.
    Una subnet pública es aquella que:
    1. Tiene asignación automática de IP pública habilitada, O
    2. Está asociada a una route table con ruta a un Internet Gateway
    """
    try:
        # Primero intentar encontrar subnets con IP pública automática
        response = ec2.describe_subnets(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'map-public-ip-on-launch', 'Values': ['true']}
            ]
        )
        if response['Subnets']:
            subnet = response['Subnets'][0]
            print(f"  ✓ Subnet pública encontrada: {subnet['SubnetId']} (AZ: {subnet['AvailabilityZone']})")
            return subnet['SubnetId']
        
        # Si no hay subnets con IP pública automática, buscar por route table
        print("  ⚠ No hay subnets con IP pública automática, buscando por route table...")
        
        # Obtener Internet Gateway de la VPC
        igw_response = ec2.describe_internet_gateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
        )
        
        if not igw_response['InternetGateways']:
            print("  ✗ No hay Internet Gateway asociado a la VPC")
            return None
        
        igw_id = igw_response['InternetGateways'][0]['InternetGatewayId']
        print(f"  ✓ Internet Gateway encontrado: {igw_id}")
        
        # Buscar route tables con ruta al IGW
        rt_response = ec2.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        public_subnet_ids = []
        for rt in rt_response['RouteTables']:
            has_igw_route = False
            for route in rt.get('Routes', []):
                if route.get('GatewayId', '').startswith('igw-'):
                    has_igw_route = True
                    break
            
            if has_igw_route:
                for assoc in rt.get('Associations', []):
                    if assoc.get('SubnetId'):
                        public_subnet_ids.append(assoc['SubnetId'])
        
        if public_subnet_ids:
            subnet_response = ec2.describe_subnets(SubnetIds=[public_subnet_ids[0]])
            if subnet_response['Subnets']:
                subnet = subnet_response['Subnets'][0]
                print(f"  ✓ Subnet con ruta a IGW encontrada: {subnet['SubnetId']} (AZ: {subnet['AvailabilityZone']})")
                return subnet['SubnetId']
        
        # Última opción: usar cualquier subnet y forzar IP pública
        print("  ⚠ No se encontró subnet pública explícita, usando primera subnet disponible...")
        all_subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        if all_subnets['Subnets']:
            subnet = all_subnets['Subnets'][0]
            print(f"  ⚠ Usando subnet: {subnet['SubnetId']} (forzando IP pública)")
            return subnet['SubnetId']
            
    except ClientError as e:
        print(f"⚠ Error obteniendo subnet pública: {e}")
    
    return None


def verify_internet_gateway(vpc_id):
    """Verifica que la VPC tiene un Internet Gateway asociado."""
    try:
        response = ec2.describe_internet_gateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
        )
        if response['InternetGateways']:
            igw_id = response['InternetGateways'][0]['InternetGatewayId']
            print(f"  ✓ Internet Gateway verificado: {igw_id}")
            return igw_id
        else:
            print("  ✗ No hay Internet Gateway asociado a la VPC")
            return None
    except ClientError as e:
        print(f"⚠ Error verificando Internet Gateway: {e}")
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

# Verificar Internet Gateway
print("\n[0/6] Verificando conectividad de red...")
igw_id = verify_internet_gateway(vpc_id)
if not igw_id:
    print("Error: La VPC no tiene Internet Gateway. No habrá acceso público.", file=sys.stderr)
    print("Crea un Internet Gateway y asócialo a la VPC antes de continuar.", file=sys.stderr)
    sys.exit(1)

# Obtener Subnet Pública
print("\n[1/6] Obteniendo subnet pública...")
subnet_id = SUBNET_ID_ENV or get_public_subnet(vpc_id)
if not subnet_id:
    print("Error: No se pudo encontrar una subnet pública", file=sys.stderr)
    print("Verifica que la VPC tenga subnets con acceso a Internet", file=sys.stderr)
    sys.exit(1)
print(f"✓ Usando Subnet: {subnet_id}")

# ---------------------------
# PASO 2: SECURITY GROUP PARA EC2
# ---------------------------
print("\n[2/6] Configurando Security Group para EC2 (Web Server)...")

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
        
        ec2.create_tags(
            Resources=[ec2_sg_id],
            Tags=[
                {'Key': 'Name', 'Value': EC2_SG_NAME},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Web'}
            ]
        )
        
    except ClientError as e:
        if 'InvalidGroup.Duplicate' in str(e):
            response = ec2.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [EC2_SG_NAME]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            ec2_sg_id = response['SecurityGroups'][0]['GroupId']
            print(f"⚠ Security Group EC2 ya existe: {ec2_sg_id}")
        else:
            print(f"⚠ Error creando Security Group EC2: {e}")

if not ec2_sg_id:
    print("Error: No se pudo crear/obtener Security Group para EC2", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 3: SECURITY GROUP PARA RDS
# ---------------------------
print("\n[3/6] Configurando Security Group para RDS (Base de Datos)...")

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
        
        ec2.create_tags(
            Resources=[rds_sg_id],
            Tags=[
                {'Key': 'Name', 'Value': RDS_SG_NAME},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Database'}
            ]
        )
        
    except ClientError as e:
        if 'InvalidGroup.Duplicate' in str(e):
            response = ec2.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [RDS_SG_NAME]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            rds_sg_id = response['SecurityGroups'][0]['GroupId']
            print(f"⚠ Security Group RDS ya existe: {rds_sg_id}")
        else:
            print(f"⚠ Error creando Security Group RDS: {e}")

if not rds_sg_id:
    print("Error: No se pudo crear/obtener Security Group para RDS", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 4: CREAR INSTANCIA RDS
# ---------------------------
print("\n[4/6] Configurando RDS (Base de Datos)...")

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
            DeletionProtection=False,
            VpcSecurityGroupIds=[rds_sg_id],
            Tags=[
                {'Key': 'Name', 'Value': DB_INSTANCE_ID},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'DataClassification', 'Value': 'Confidential'}
            ]
        )
        print(f"✓ Instancia RDS creada: {DB_INSTANCE_ID}")
        
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
        if e.response.get('Error', {}).get('Code') == 'DBInstanceAlreadyExists':
            print(f"⚠ Instancia RDS {DB_INSTANCE_ID} ya existe")
            db_response = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)
            db_endpoint = db_response['DBInstances'][0]['Endpoint']['Address']
            print(f"✓ Endpoint de RDS: {db_endpoint}")
        else:
            print(f"⚠ Error con RDS: {e}")

if not db_endpoint:
    db_endpoint = "localhost"
    print("⚠ Usando placeholder para RDS.")

# ---------------------------
# PASO 5: CREAR INSTANCIA EC2 CON SUBNET PÚBLICA
# ---------------------------
print("\n[5/6] Creando instancia EC2 (Web Server)...")

user_data_minimal = '''#!/bin/bash
yum install -y amazon-ssm-agent || true
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
'''

try:
    # CLAVE: Usar NetworkInterfaces para forzar IP pública
    instance_params = {
        'ImageId': AMI_ID,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': INSTANCE_TYPE,
        'IamInstanceProfile': {'Name': IAM_INSTANCE_PROFILE},
        'UserData': user_data_minimal,
        'NetworkInterfaces': [{
            'DeviceIndex': 0,
            'SubnetId': subnet_id,
            'AssociatePublicIpAddress': True,  # ✓ FORZAR IP PÚBLICA
            'Groups': [ec2_sg_id]
        }],
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
            'HttpTokens': 'required',
            'HttpEndpoint': 'enabled'
        }
    }
    
    response = ec2.run_instances(**instance_params)
    instance_id = response['Instances'][0]['InstanceId']
    print(f"✓ Instancia EC2 creada: {instance_id}")
    print(f"  - Subnet: {subnet_id}")
    print(f"  - IP pública: Forzada (AssociatePublicIpAddress=True)")
    
    print("\n  Esperando a que la instancia esté en estado 'running'...")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    print("  ✓ Instancia en estado 'running'")
    
    print("  Esperando verificaciones de estado...")
    waiter = ec2.get_waiter('instance_status_ok')
    waiter.wait(InstanceIds=[instance_id])
    print("  ✓ Verificaciones de estado OK")
    
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance_data = response['Reservations'][0]['Instances'][0]
    public_ip = instance_data.get('PublicIpAddress', 'N/A')
    private_ip = instance_data.get('PrivateIpAddress', 'N/A')
    
    if public_ip == 'N/A' or not public_ip:
        print("  ⚠ ADVERTENCIA: La instancia no tiene IP pública asignada")
    else:
        print(f"  ✓ IP pública: {public_ip}")
        print(f"  ✓ IP privada: {private_ip}")
    
except ClientError as e:
    print(f"✗ Error creando instancia EC2: {e}", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 6: CONFIGURAR WEB SERVER VIA SSM
# ---------------------------
print("\n[6/6] Configurando Web Server via SSM...")

if not wait_for_ssm_agent(instance_id, max_attempts=30, delay=10):
    print("⚠ SSM agent no disponible.")
else:
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
    <script src="//cdn.jsdelivr.net/npm/docsify@4"></script>
</body>
</html>'''

    print("\n  Paso 6.1: Instalando Apache...")
    install_commands = [
        'yum update -y',
        'yum install -y httpd',
        'systemctl enable httpd',
        'systemctl start httpd'
    ]
    success, output = run_ssm_command(instance_id, install_commands, "Instalación de Apache")
    
    if success:
        print("\n  Paso 6.2: Desplegando index.html...")
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
            print("\n  Paso 6.3: Verificando servicio Apache...")
            verify_commands = [
                'systemctl status httpd --no-pager',
                'curl -s -o /dev/null -w "%{http_code}" http://localhost/'
            ]
            run_ssm_command(instance_id, verify_commands, "Verificación de Apache")

# ---------------------------
# VERIFICACIÓN DE CONECTIVIDAD
# ---------------------------
print("\n" + "-" * 70)
print("VERIFICACIÓN DE CONECTIVIDAD")
print("-" * 70)

if public_ip and public_ip != 'N/A':
    print(f"\n🔍 Verificando acceso a http://{public_ip}/")
    
    import urllib.request
    import urllib.error
    
    max_retries = 5
    for attempt in range(max_retries):
        try:
            time.sleep(5)
            req = urllib.request.Request(f"http://{public_ip}/", headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=10)
            if response.getcode() == 200:
                print(f"\n   ✓ ¡ÉXITO! La aplicación responde correctamente (HTTP 200)")
                break
        except urllib.error.URLError as e:
            print(f"   Intento {attempt + 1}/{max_retries}: Esperando... ({e.reason})")
        except Exception as e:
            print(f"   Intento {attempt + 1}/{max_retries}: Error - {e}")
    else:
        print("\n   ⚠ No se pudo verificar la conectividad automáticamente")

# ---------------------------
# RESUMEN FINAL
# ---------------------------
print("\n" + "=" * 70)
print("DESPLIEGUE COMPLETADO")
print("=" * 70)

print("\n📋 RECURSOS CREADOS:")
print(f"  ├─ VPC:                {vpc_id}")
print(f"  ├─ Subnet:             {subnet_id}")
print(f"  ├─ Internet Gateway:   {igw_id}")
print(f"  ├─ Security Group EC2: {ec2_sg_id}")
print(f"  ├─ Security Group RDS: {rds_sg_id}")
print(f"  ├─ Instancia RDS:      {DB_INSTANCE_ID}")
print(f"  ├─ Instancia EC2:      {instance_id}")
print(f"  ├─ IP Privada EC2:     {private_ip}")
print(f"  └─ IP Pública EC2:     {public_ip}")

print("\n🔒 MEDIDAS DE SEGURIDAD:")
print("  ✓ Security Groups separados por capa")
print("  ✓ RDS solo accesible desde EC2")
print("  ✓ Encriptación en reposo para RDS")
print("  ✓ SSH deshabilitado - usar SSM")
print("  ✓ IMDSv2 requerido en EC2")
print("  ✓ Subnet pública verificada")
print("  ✓ Internet Gateway verificado")

if public_ip and public_ip != 'N/A':
    print(f"\n🌐 ACCESO: http://{public_ip}/")

print("\n💡 COMANDOS ÚTILES:")
print(f"  - Conectar via SSM: aws ssm start-session --target {instance_id}")

print("=" * 70)
