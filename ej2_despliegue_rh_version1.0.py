    print("Error: Debes definir la variable de entorno RDS_ADMIN_PASSWORD", file=sys.stderr)
    print("Ejemplo: export RDS_ADMIN_PASSWORD='tu_password_seguro'", file=sys.stderr)
    sys.exit(1)  # Sale con código de error 1

# ---------------------------
# CLIENTES DE AWS (EC2, RDS y SSM)
# ---------------------------
ec2 = boto3.client('ec2', region_name=REGION)  # Cliente para interactuar con EC2
rds = boto3.client('rds', region_name=REGION)  # Cliente para interactuar con RDS
ssm = boto3.client('ssm', region_name=REGION)  # Cliente para interactuar con SSM

# Mensajes iniciales de log
print("=" * 60)
print("INICIANDO DESPLIEGUE DE APLICACIÓN DE RECURSOS HUMANOS")
print("Arquitectura: EC2 (Web Server + Apache) + RDS (MySQL)")
print("=" * 60)

# ---------------------------
# PASO 1: CREAR SECURITY GROUP PARA EC2 (WEB SERVER)
# ---------------------------
print("\n[1/7] Configurando Security Group para EC2 (Web Server)...")

sg_ec2_id = None  # Aquí se guardará el ID del Security Group de EC2

# Si el usuario definió un SECURITY_GROUP_EC2_ID por variable de entorno, se usa directamente
if SG_EC2_ID_ENV:
    sg_ec2_id = SG_EC2_ID_ENV
    print(f"✓ Usando Security Group EC2 especificado: {sg_ec2_id}")
else:
    # Si no hay SG especificado, se intenta crear uno nuevo
    try:
        # Obtener el VPC por defecto para asociar el Security Group
        vpc_response = ec2.describe_vpcs(Filters=[{'Name': 'is-default', 'Values': ['true']}])
        if vpc_response['Vpcs']:
            vpc_id = vpc_response['Vpcs'][0]['VpcId']
        else:
            # Si no hay VPC default, usar el primero disponible
            vpc_response = ec2.describe_vpcs()
            vpc_id = vpc_response['Vpcs'][0]['VpcId']
        
        response = ec2.create_security_group(
            GroupName=SG_EC2_NAME,
            Description='Security Group para EC2 Web Server - Permite HTTP desde Internet',
            VpcId=vpc_id
        )
        sg_ec2_id = response['GroupId']  # Guardamos el ID del SG recién creado
        print(f"✓ Security Group EC2 creado: {sg_ec2_id}")
        
        # Se agrega regla de entrada para HTTP (80) desde cualquier IP (expuesto a Internet)
        ec2.authorize_security_group_ingress(
            GroupId=sg_ec2_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP desde Internet'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH para administración'}]
                }
            ]
        )
        print(f"✓ Reglas de seguridad EC2 configuradas:")
        print(f"  - HTTP (puerto 80) abierto a Internet (0.0.0.0/0)")
        print(f"  - SSH (puerto 22) abierto para administración")
        
        # Agregar tags al Security Group
        ec2.create_tags(
            Resources=[sg_ec2_id],
            Tags=[
                {'Key': 'Name', 'Value': SG_EC2_NAME},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Web Server'}
            ]
        )
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        
        # Caso 1: El Security Group con ese nombre ya existe
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                response = ec2.describe_security_groups(GroupNames=[SG_EC2_NAME])
                sg_ec2_id = response['SecurityGroups'][0]['GroupId']
                print(f"⚠ Security Group EC2 ya existe: {sg_ec2_id}")
            except:
                pass
        
        # Caso 2: No tenemos permisos para crear/listar Security Groups
        elif 'UnauthorizedOperation' in str(e) or error_code == 'UnauthorizedOperation':
            print("⚠ No se tienen permisos para crear Security Groups")
            print("  Nota: Puedes especificar un Security Group ID con:")
            print("  export SECURITY_GROUP_EC2_ID='sg-xxxxxxxxxxxxx'")
            sg_ec2_id = None
        else:
            print(f"⚠ Error creando Security Group EC2: {e}")

if sg_ec2_id is None:
    print("✗ Error: No se pudo crear/obtener el Security Group para EC2", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 2: CREAR SECURITY GROUP PARA RDS (BASE DE DATOS)
# ---------------------------
print("\n[2/7] Configurando Security Group para RDS (Base de Datos)...")

sg_rds_id = None  # Aquí se guardará el ID del Security Group de RDS

# Si el usuario definió un SECURITY_GROUP_RDS_ID por variable de entorno, se usa directamente
if SG_RDS_ID_ENV:
    sg_rds_id = SG_RDS_ID_ENV
    print(f"✓ Usando Security Group RDS especificado: {sg_rds_id}")
else:
    try:
        # Obtener el VPC por defecto para asociar el Security Group
        vpc_response = ec2.describe_vpcs(Filters=[{'Name': 'is-default', 'Values': ['true']}])
        if vpc_response['Vpcs']:
            vpc_id = vpc_response['Vpcs'][0]['VpcId']
        else:
            vpc_response = ec2.describe_vpcs()
            vpc_id = vpc_response['Vpcs'][0]['VpcId']
        
        response = ec2.create_security_group(
            GroupName=SG_RDS_NAME,
            Description='Security Group para RDS - Solo permite MySQL desde EC2 Security Group',
            VpcId=vpc_id
        )
        sg_rds_id = response['GroupId']
        print(f"✓ Security Group RDS creado: {sg_rds_id}")
        
        # Se agrega regla de entrada para MySQL (3306) SOLO desde el Security Group de EC2
        # Esto asegura que solo la instancia EC2 pueda conectarse a la base de datos
        ec2.authorize_security_group_ingress(
            GroupId=sg_rds_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 3306,
                    'ToPort': 3306,
                    'UserIdGroupPairs': [
                        {
                            'GroupId': sg_ec2_id,
                            'Description': 'MySQL solo desde EC2 Web Server'
                        }
                    ]
                }
            ]
        )
        print(f"✓ Reglas de seguridad RDS configuradas:")
        print(f"  - MySQL (puerto 3306) solo accesible desde SG: {sg_ec2_id}")
        print(f"  - NO accesible directamente desde Internet")
        
        # Agregar tags al Security Group
        ec2.create_tags(
            Resources=[sg_rds_id],
            Tags=[
                {'Key': 'Name', 'Value': SG_RDS_NAME},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Database'}
            ]
        )
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        
        if 'InvalidGroup.Duplicate' in str(e) or error_code == 'InvalidGroup.Duplicate':
            try:
                response = ec2.describe_security_groups(GroupNames=[SG_RDS_NAME])
                sg_rds_id = response['SecurityGroups'][0]['GroupId']
                print(f"⚠ Security Group RDS ya existe: {sg_rds_id}")
            except:
                pass
        
        elif 'UnauthorizedOperation' in str(e) or error_code == 'UnauthorizedOperation':
            print("⚠ No se tienen permisos para crear Security Groups")
            print("  Nota: Puedes especificar un Security Group ID con:")
            print("  export SECURITY_GROUP_RDS_ID='sg-xxxxxxxxxxxxx'")
            sg_rds_id = None
        else:
            print(f"⚠ Error creando Security Group RDS: {e}")

if sg_rds_id is None:
    print("✗ Error: No se pudo crear/obtener el Security Group para RDS", file=sys.stderr)
    sys.exit(1)

# ---------------------------
# PASO 3: CONFIGURAR RDS CON SU SECURITY GROUP
# ---------------------------
print("\n[3/7] Configurando RDS (Base de Datos MySQL)...")

db_endpoint = None  # Aquí se guardará el endpoint de la base de datos

# Si el usuario dio un endpoint de RDS por variable de entorno, se usa directamente
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
            VpcSecurityGroupIds=[sg_rds_id],  # Asociar el Security Group de RDS
            PubliclyAccessible=False,         # NO accesible desde Internet
            StorageEncrypted=True,            # Encriptación en reposo
            BackupRetentionPeriod=7,          # Retención de backups por 7 días
            Tags=[
                {'Key': 'Name', 'Value': DB_INSTANCE_ID},
                {'Key': 'Application', 'Value': 'Recursos Humanos'},
                {'Key': 'Layer', 'Value': 'Database'}
            ]
        )
        print(f"✓ Instancia RDS creada: {DB_INSTANCE_ID}")
        print(f"  - Security Group asociado: {sg_rds_id}")
        print(f"  - Encriptación en reposo: Habilitada")
        print(f"  - Acceso público: Deshabilitado")
        
        # Espera a que la instancia RDS cambie a estado 'available'
        print("  Esperando a que RDS esté disponible (esto puede tomar varios minutos)...")
        waiter = rds.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=DB_INSTANCE_ID, WaiterConfig={'Delay': 30, 'MaxAttempts': 40})
        
        # Una vez disponible, se obtiene su endpoint
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

# Si no se tiene un endpoint válido, se usa "localhost" como placeholder
if not db_endpoint:
    db_endpoint = "localhost"
    print(f"⚠ Usando placeholder para RDS endpoint. Configura manualmente después.")

# ---------------------------
# PASO 4: CREAR INSTANCIA EC2 (WEB SERVER CON APACHE)
# ---------------------------
print("\n[4/7] Creando instancia EC2 (Web Server con Apache)...")

# USER DATA mínimo - La configuración principal se hará via SSM
user_data = '''#!/bin/bash
# Script mínimo de inicialización
# La configuración del servidor web se realizará via SSM
echo "Instancia EC2 iniciada - $(date)" > /tmp/startup.log
'''

try:
    # Parámetros para crear la instancia EC2
    instance_params = {
        'ImageId': AMI_ID,
        'MinCount': 1,
        'MaxCount': 1,
        'InstanceType': INSTANCE_TYPE,
        'IamInstanceProfile': {'Name': 'LabInstanceProfile'},
        'UserData': user_data,
        'SecurityGroupIds': [sg_ec2_id],  # Security Group que permite HTTP
        'TagSpecifications': [
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': APP_NAME},
                    {'Key': 'Application', 'Value': 'Recursos Humanos'},
                    {'Key': 'Layer', 'Value': 'Web Server'}
                ]
            }
        ]
    }
    
    # Creación de la instancia EC2
    response = ec2.run_instances(**instance_params)
    instance_id = response['Instances'][0]['InstanceId']
    print(f"✓ Instancia EC2 creada: {instance_id}")
    print(f"  - Security Group asociado: {sg_ec2_id}")
    
    # ---------------------------
    # ESPERAR A QUE LA INSTANCIA ESTÉ LISTA PARA SSM
    # ---------------------------
    print("\n[5/7] Esperando a que la instancia EC2 esté en estado 'running'...")
    
    # Primero esperar a que la instancia esté running
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(
        InstanceIds=[instance_id],
        WaiterConfig={
            'Delay': 5,
            'MaxAttempts': 60
        }
    )
    print(f"✓ Instancia EC2 en estado 'running'")
    
    # Esperar a que las verificaciones de estado pasen (necesario para SSM)
    print("\n[6/7] Esperando verificaciones de estado de la instancia (instance_status_ok)...")
    ec2.get_waiter('instance_status_ok').wait(InstanceIds=[instance_id])
    print(f"✓ Verificaciones de estado completadas - Instancia lista para SSM")
    
    # Obtener información de la instancia
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance_info = response['Reservations'][0]['Instances'][0]
    public_ip = instance_info.get('PublicIpAddress', 'N/A')
    private_ip = instance_info.get('PrivateIpAddress', 'N/A')
    
    print(f"  - IP pública: {public_ip}")
    print(f"  - IP privada: {private_ip}")
    
    # ---------------------------
    # PARTE 2: ENVIAR COMANDO VIA SSM Y EXTRAER RESULTADO
    # ---------------------------
    print("\n[7/7] Configurando servidor web via SSM...")
    
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
name: 'Obligatorio para DevOps',
repo: 'https://github.com/Diegogar8/Obligatorio-DevOps-2025'
}
</script>
<!-- Docsify v4 -->
<script src="//cdn.jsdelivr.net/npm/docsify@4"></script>
</body>
</html>'''
    
    # Comando para crear el archivo index.html, instalar Apache y levantar el servidor
    command = f'''#!/bin/bash
# Crear directorio si no existe
mkdir -p /var/www/html

# Crear archivo index.html
cat > /var/www/html/index.html << 'EOFHTML'
{index_html_content}
EOFHTML

# Instalar Apache
yum update -y
yum install -y httpd

# Configurar permisos
chown -R apache:apache /var/www/html

# Habilitar y arrancar Apache
systemctl enable httpd
systemctl start httpd

# Verificar estado
systemctl status httpd
echo "Configuración completada - $(date)"
'''
    
    print("  Enviando comando SSM para configurar el servidor web...")
    
    # Enviar comando via SSM
    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={'commands': [command]}
    )
    command_id = response['Command']['CommandId']
    print(f"  - Command ID: {command_id}")
    
    # Esperar resultado del comando SSM
    print("  Esperando resultado del comando SSM...")
    while True:
        output = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        if output['Status'] in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
            break
        time.sleep(2)
    
    print(f"\n  Estado del comando: {output['Status']}")
    print("\nOutput:")
    print(output['StandardOutputContent'])
    
    if output['StandardErrorContent']:
        print("\nErrores (si hay):")
        print(output['StandardErrorContent'])
    
    if output['Status'] == 'Success':
        print("✓ Servidor web configurado correctamente via SSM")
    else:
        print(f"⚠ El comando SSM terminó con estado: {output['Status']}")
    
except ClientError as e:
    print(f"✗ Error creando instancia EC2: {e}", file=sys.stderr)
    sys.exit(1)


