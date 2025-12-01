# -------------------------------------------------------------
# Script de automatización de infraestructura en AWS
# -------------------------------------------------------------
# Importa librerías necesarias
import boto3   # SDK de AWS para Python
import os      # Manejo de variables de entorno y archivos
from dotenv import load_dotenv   # Carga variables desde archivo .env

# -------------------------------------------------------------
# Carga las variables de entorno definidas en .env
load_dotenv()

# Definición de variables globales que se leen desde .env
# Incluyen credenciales, nombres de recursos, parámetros de EC2 y RDS, etc.
KEY_NAME = os.getenv('KEY_NAME')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_SESSION_TOKEN = os.getenv('AWS_SESSION_TOKEN')
AWS_REGION = os.getenv('AWS_REGION')
AWS_IMAGE_ID = os.getenv('AWS_IMAGE_ID')
AWS_INSTANCE_TYPE = os.getenv('AWS_INSTANCE_TYPE')
AWS_S3_NAME = os.getenv('AWS_S3_NAME')
AWS_EC2_NAME = os.getenv('AWS_EC2_NAME')
SG_EC2_NAME = os.getenv('SG_EC2_NAME')
SG_DB_NAME = os.getenv('SG_DB_NAME')
DB_IDENTIFIER = os.getenv('DB_IDENTIFIER')
DB_INSTANCE_CLASS = os.getenv('DB_INSTANCE_CLASS')
DB_ENGINE = os.getenv('DB_ENGINE')
DB_MASTER_USER_NAME = os.getenv('DB_MASTER_USER_NAME')
DB_MASTER_PASSWORD = os.getenv('DB_MASTER_PASSWORD')
EC2_APP_USER = os.getenv('EC2_APP_USER')
EC2_APP_GROUP = os.getenv('EC2_APP_GROUP')
APP_REPO_URL = os.getenv('APP_REPO_URL')
APP_DIR = os.getenv('APP_DIR')
APP_PORT = os.getenv('APP_PORT')
DB_PORT = os.getenv('DB_PORT')
DB_APP_USER = os.getenv('DB_APP_USER')
DB_APP_PASSWORD = os.getenv('DB_APP_PASSWORD')
DB_NAME = os.getenv('DB_APP_NAME') 
APP_ADMIN_PASSWORD = os.getenv('APP_ADMIN_PASSWORD')
APP_ADMIN_USER = os.getenv('APP_ADMIN_USER')

# -------------------------------------------------------------
# Función para crear par de claves EC2 y guardarlo como archivo .pem
def crear_par_claves(nombre):
    ec2 = boto3.client('ec2')
    key_name = nombre
    try:
        # Intenta crear un nuevo par de claves en AWS
        key_pair = ec2.create_key_pair(KeyName=key_name)
        # Si se crea correctamente, guarda la clave privada en un archivo .pem
        with open(f'{key_name}.pem', 'w') as file:
            file.write(key_pair['KeyMaterial'])
        os.chmod(f'{key_name}.pem', 0o400)  # Permisos seguros (solo lectura)
        print(f"Par de claves creado y guardado como {key_name}.pem")
    except ec2.exceptions.ClientError as e:
        # Si la clave ya existe, AWS devuelve el error InvalidKeyPair.Duplicate
        if 'InvalidKeyPair.Duplicate' in str(e):
            print(f"La clave {key_name} ya existe")
        else:
            # Si ocurre otro error, se relanza para no ocultarlo
            raise

# -------------------------------------------------------------
# Función para crear un Security Group para EC2 o RDS
def crear_grupo_seguridad(nombre, desc):
    ec2 = boto3.client('ec2')
    sg_id = None
    try:
        # Intenta crear un nuevo Security Group
        response = ec2.create_security_group(GroupName=nombre, Description=desc)
        sg_id = response['GroupId']
        print(f"Grupo de seguridad creado con el id: {sg_id}")
    except ec2.exceptions.ClientError as e:
        # Si el grupo ya existe, AWS devuelve InvalidGroup.Duplicate
        if 'InvalidGroup.Duplicate' in str(e):
            print(f"El grupo de seguridad {nombre} ya existe")
            # En ese caso, se busca el ID del grupo existente
            response = ec2.describe_security_groups(
                Filters=[{'Name': 'group-name','Values': [nombre]}])
            if response['SecurityGroups']:
                for sg in response['SecurityGroups']:
                    sg_id = sg['GroupId']
                    print(f"ID del grupo de seguridad: {sg_id}")
            else:
                # Si no se encuentra, se informa
                print("No se encontraron grupos de seguridad con los filtros especificados.")
        else:
            # Si ocurre otro error distinto, se relanza
            raise
    return sg_id

# -------------------------------------------------------------
# Función para crear reglas de ingreso en Security Groups
def crear_reglas(sg_id, sg_ec2_id, puerto, nombre, instancia):
    ec2 = boto3.client('ec2')
    if instancia == "ec2":
        # Para EC2: abre el puerto a todo Internet
        IpPermissions=[{
            'IpProtocol': 'tcp','FromPort': puerto,'ToPort': puerto,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    else:
        # Para RDS: permite acceso solo desde el SG de la EC2
        IpPermissions=[{
            'IpProtocol': 'tcp','FromPort': puerto,'ToPort': puerto,
            'UserIdGroupPairs': [{'GroupId': sg_ec2_id}]}]
    try:
        # Intenta agregar la regla al SG
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=IpPermissions)
        print(f"Regla para {nombre} creada")
    except ec2.exceptions.ClientError as e:
        # Si la regla ya existe, AWS devuelve InvalidPermission.Duplicate
        if "InvalidPermission.Duplicate" in str(e):
            print(f"La regla para {nombre} ya existe.")
        else:
            # Si ocurre otro error, se relanza
            raise

# -------------------------------------------------------------
# Función para crear instancia RDS
def crear_rds():
    rds = boto3.client("rds")
    db_identifier = DB_IDENTIFIER
    ENGINE = DB_ENGINE 
    USER_NAME = DB_MASTER_USER_NAME
    DB_PASSWORD = DB_MASTER_PASSWORD
    DB_ENDPOINT = None
    db_existe = False
    try:
        # Verifica si la instancia RDS ya existe
        response = rds.describe_db_instances(DBInstanceIdentifier=db_identifier)
        print(f"La instancia de rds ya existe")
        db_existe = True
        db = response["DBInstances"][0]
        DB_ENDPOINT = db["Endpoint"]["Address"]
        print(f"El ENDPOINT de la base de datos es {DB_ENDPOINT}")
    except rds.exceptions.ClientError as e:
        # Si el error es DBInstanceNotFound, significa que no existe
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            db_existe = False
        else:
            # Si ocurre otro error, se relanza
            raise
    if not db_existe:
        # Crea la instancia RDS si no existe
        response = rds.create_db_instance(
            DBInstanceIdentifier=db_identifier,
            AllocatedStorage=20,
            DBInstanceClass=DB_INSTANCE_CLASS,
            Engine=ENGINE,
            MasterUsername=USER_NAME,
            MasterUserPassword=DB_PASSWORD,
            VpcSecurityGroupIds=[sg_db_id]
        )
        print("Instancia rds creada")
        print("Esperando que quede disponible ...")
        # Espera hasta que la instancia esté en estado available
        waiter = rds.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=db_identifier)
        # Una vez disponible, obtiene el endpoint
        response = rds.describe_db_instances(DBInstanceIdentifier=db_identifier)
        db = response["DBInstances"][0]
        DB_ENDPOINT = db["Endpoint"]["Address"]
        print(f"El ENDPOINT de la base de datos es {DB_ENDPOINT}")
    return DB_ENDPOINT

# -------------------------------------------------------------
# Función para crear instancia EC2
def crear_ec2(DB_ENDPOINT):
    ec2_resource = boto3.resource('ec2')
    EC2_INSTANCE_ID = None
    EC2_INSTANCE = None
    DB_HOST = DB_ENDPOINT

    # Busca si ya existe una EC2 con el mismo nombre (idempotencia)
    instances = ec2_resource.instances.filter(
        Filters=[
            {"Name": "tag:Name", "Values": [AWS_EC2_NAME]},
            {"Name": "instance-state-name","Values": ["pending","running","stopping","stopped"]}
        ]
    )
    for instance in instances:
        EC2_INSTANCE = instance
        EC2_INSTANCE_ID = EC2_INSTANCE.instance_id
        break

    # Carga el script de inicialización (user_data) y reemplaza variables
    with open("user_data_socios.sh", "r") as f:
        user_data_template = f.read()
    user_data = (
        user_data_template
            .replace("__EC2_APP_USER__", EC2_APP_USER)
            .replace("__EC2_APP_GROUP__", EC2_APP_GROUP)
            .replace("__APP_REPO_URL__", APP_REPO_URL)
            .replace("__APP_DIR__", APP_DIR)
            .replace("__APP_PORT__", APP_PORT)
            .replace("__DB_HOST__", DB_HOST) 
            .replace("__DB_PORT__", DB_PORT) 
            .replace("__DB_APP_USER__", DB_APP_USER) 
            .replace("__DB_APP_PASSWORD__", DB_APP_PASSWORD) 
            .replace("__DB_MASTER_USER__", DB_MASTER_USER_NAME)
            .replace("__DB_MASTER_PASSWORD__", DB_MASTER_PASSWORD)
            .replace("__APP_ADMIN_PASSWORD__", APP_ADMIN_PASSWORD)
            .replace("__APP_ADMIN_USER__", APP_ADMIN_USER)
            .replace("__DB_APP_NAME__", DB_NAME)
    )

    if not EC2_INSTANCE_ID:
        # Si no existe una instancia previa, crea una nueva
        instances = ec2_resource.create_instances(
            ImageId=AWS_IMAGE_ID,
            MinCount=1, MaxCount=1,
            InstanceType=AWS_INSTANCE_TYPE, 
            KeyName=KEY_NAME,
            SecurityGroupIds=[sg_ec2_id],
            UserData=user_data,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name','Value': AWS_EC2_NAME}]
            }]
        )
        EC2_INSTANCE = instances[0]
        EC2_INSTANCE_ID = EC2_INSTANCE.id
        print(f"Instancia creada con ID: {EC2_INSTANCE_ID}")
        print(f"Esperando a que la instancia quede en estado running")

        # Espera hasta que la instancia esté en estado running
        EC2_INSTANCE.wait_until_running()
        EC2_INSTANCE.reload()
    else:
        # Si ya existe, informa y recarga el estado
        print(f"La EC2 con el nombre {AWS_EC2_NAME} ya existe y tiene el id: {EC2_INSTANCE_ID}")
        EC2_INSTANCE.reload()

    # Obtiene y muestra la IP pública de la instancia
    public_ip = EC2_INSTANCE.public_ip_address
    print(f"La IP publica de la instancia es: {public_ip}")

# -------------------------------------------------------------
# Bloque principal: orquesta la creación de todos los recursos
if __name__ == "__main__":
    # 1. Crea el par de claves para SSH (maneja duplicados)
    crear_par_claves(KEY_NAME)

    # 2. Crea los Security Groups (EC2 y RDS) o reutiliza los existentes
    sg_ec2_id = crear_grupo_seguridad(SG_EC2_NAME, "SG de la ec2")
    sg_db_id = crear_grupo_seguridad(SG_DB_NAME, "SG de la rds")

    # 3. Crea reglas de ingreso:
    #    - SSH (22) y HTTP (80) abiertos a Internet para EC2
    #    - DB (3306) accesible solo desde el SG de la EC2 para RDS
    crear_reglas(sg_ec2_id, sg_ec2_id, 22, "SSH", "ec2")
    crear_reglas(sg_ec2_id, sg_ec2_id, 80, "HTTP", "ec2")
    crear_reglas(sg_db_id, sg_ec2_id, 3306, "DB", "rds")

    # 4. Crea la instancia RDS (si no existe) y obtiene su endpoint
    db_endpoint = crear_rds()

    # 5. Crea la instancia EC2 (si no existe) usando el endpoint de la DB
    crear_ec2(db_endpoint)
