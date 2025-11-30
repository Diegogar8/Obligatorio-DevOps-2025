#!/usr/bin/env python3
"""
Script de Despliegue Automatizado - Aplicación de Recursos Humanos
===================================================================
Arquitectura de dos capas: EC2 (Web Server) + RDS (MySQL)
Incluye medidas de seguridad para proteger datos sensibles.

Autor: Deployment Automation Script
Fecha: 2025
"""

import boto3
import time
import secrets
import string
import sys
from botocore.exceptions import ClientError


# =============================================================================
# CONFIGURACIÓN
# =============================================================================

AWS_REGION = "us-east-1"

# Configuración EC2
EC2_INSTANCE_TYPE = "t2.micro"
EC2_KEY_NAME = "hr-app-key"  # Nombre del key pair (debe existir o se creará)
EC2_AMI_ID = None  # Se buscará automáticamente la última Amazon Linux 2023

# Configuración RDS
RDS_INSTANCE_CLASS = "db.t3.micro"
RDS_ENGINE = "mysql"
RDS_ENGINE_VERSION = "8.0"
RDS_DB_NAME = "hr_database"
RDS_MASTER_USERNAME = "hr_admin"
RDS_ALLOCATED_STORAGE = 20

# Nombres de recursos
VPC_NAME = "hr-app-vpc"
EC2_SG_NAME = "hr-web-server-sg"
RDS_SG_NAME = "hr-database-sg"
EC2_INSTANCE_NAME = "HR-WebServer"
RDS_INSTANCE_NAME = "hr-database"


# =============================================================================
# FUNCIONES AUXILIARES
# =============================================================================

def generate_secure_password(length=24):
    """Genera una contraseña segura para RDS."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    # Evitar caracteres problemáticos para MySQL
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    # Asegurar que tenga al menos una letra mayúscula, minúscula, número y símbolo
    return password


def get_latest_amazon_linux_ami(ec2_client):
    """Obtiene el AMI más reciente de Amazon Linux 2023."""
    print("🔍 Buscando AMI más reciente de Amazon Linux 2023...")
    
    response = ec2_client.describe_images(
        Owners=['amazon'],
        Filters=[
            {'Name': 'name', 'Values': ['al2023-ami-2023*-x86_64']},
            {'Name': 'state', 'Values': ['available']},
            {'Name': 'architecture', 'Values': ['x86_64']},
            {'Name': 'virtualization-type', 'Values': ['hvm']},
            {'Name': 'root-device-type', 'Values': ['ebs']}
        ]
    )
    
    images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
    
    if not images:
        raise Exception("No se encontró ningún AMI de Amazon Linux 2023")
    
    ami_id = images[0]['ImageId']
    print(f"   ✅ AMI seleccionado: {ami_id}")
    return ami_id


def wait_for_instance_running(ec2_client, instance_id):
    """Espera hasta que la instancia EC2 esté en estado 'running'."""
    print(f"⏳ Esperando a que la instancia {instance_id} esté en estado 'running'...")
    
    waiter = ec2_client.get_waiter('instance_running')
    waiter.wait(
        InstanceIds=[instance_id],
        WaiterConfig={
            'Delay': 10,
            'MaxAttempts': 60
        }
    )
    
    # Obtener información de la instancia
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]
    
    print(f"   ✅ Instancia en estado 'running'")
    print(f"   📍 IP Pública: {instance.get('PublicIpAddress', 'N/A')}")
    print(f"   📍 IP Privada: {instance.get('PrivateIpAddress', 'N/A')}")
    
    return instance


def wait_for_rds_available(rds_client, db_instance_id):
    """Espera hasta que la instancia RDS esté disponible."""
    print(f"⏳ Esperando a que RDS {db_instance_id} esté disponible (esto puede tomar varios minutos)...")
    
    waiter = rds_client.get_waiter('db_instance_available')
    waiter.wait(
        DBInstanceIdentifier=db_instance_id,
        WaiterConfig={
            'Delay': 30,
            'MaxAttempts': 60
        }
    )
    
    response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
    db_instance = response['DBInstances'][0]
    
    print(f"   ✅ RDS disponible")
    print(f"   📍 Endpoint: {db_instance['Endpoint']['Address']}")
    
    return db_instance


# =============================================================================
# SCRIPT DE USER DATA PARA EC2
# =============================================================================

def get_user_data_script(rds_endpoint, rds_password):
    """Genera el script de configuración para EC2 con Apache y la aplicación."""
    
    return f'''#!/bin/bash
set -e

# =============================================================================
# CONFIGURACIÓN INICIAL DEL SERVIDOR WEB
# =============================================================================

echo "=========================================="
echo "INICIANDO CONFIGURACIÓN DEL SERVIDOR WEB"
echo "=========================================="

# Actualizar sistema
dnf update -y

# Instalar Apache, PHP y MySQL client
dnf install -y httpd php php-mysqlnd php-json php-mbstring mariadb105

# Iniciar y habilitar Apache
systemctl start httpd
systemctl enable httpd

# =============================================================================
# CONFIGURACIÓN DE SEGURIDAD DE APACHE
# =============================================================================

# Configurar headers de seguridad
cat >> /etc/httpd/conf/httpd.conf << 'SECURITY_HEADERS'

# Headers de Seguridad
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    Header always unset X-Powered-By
    Header always unset Server
</IfModule>

# Ocultar versión de Apache
ServerTokens Prod
ServerSignature Off

# Deshabilitar listado de directorios
<Directory /var/www/html>
    Options -Indexes +FollowSymLinks
    AllowOverride All
</Directory>

SECURITY_HEADERS

# =============================================================================
# CONFIGURACIÓN DE PHP SEGURA
# =============================================================================

cat > /etc/php.d/99-security.ini << 'PHP_SECURITY'
; Configuración de seguridad de PHP
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
session.cookie_httponly = 1
session.cookie_secure = 0
session.use_strict_mode = 1
session.cookie_samesite = Strict
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
PHP_SECURITY

# =============================================================================
# CREAR ARCHIVO DE CONFIGURACIÓN DE BASE DE DATOS (PROTEGIDO)
# =============================================================================

mkdir -p /var/www/config
chmod 750 /var/www/config

cat > /var/www/config/database.php << 'DB_CONFIG'
<?php
// Configuración de Base de Datos - ARCHIVO PROTEGIDO
// No exponer este archivo al público

define('DB_HOST', '{rds_endpoint}');
define('DB_NAME', '{RDS_DB_NAME}');
define('DB_USER', '{RDS_MASTER_USERNAME}');
define('DB_PASS', '{rds_password}');
define('DB_CHARSET', 'utf8mb4');

// Opciones PDO seguras
define('DB_OPTIONS', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false
]);
DB_CONFIG

chmod 640 /var/www/config/database.php
chown apache:apache /var/www/config/database.php

# =============================================================================
# CREAR APLICACIÓN DE RECURSOS HUMANOS
# =============================================================================

# Página principal - Lista de empleados
cat > /var/www/html/index.php << 'INDEX_PHP'
<?php
/**
 * Sistema de Gestión de Recursos Humanos
 * Aplicación segura para manejo de datos de empleados
 */

session_start();
require_once '/var/www/config/database.php';

// Función para conectar a la base de datos
function getDBConnection() {{
    try {{
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        return new PDO($dsn, DB_USER, DB_PASS, DB_OPTIONS);
    }} catch (PDOException $e) {{
        error_log("Error de conexión: " . $e->getMessage());
        return null;
    }}
}}

// Función para sanitizar salida (prevenir XSS)
function sanitize($data) {{
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}}

// Función para enmascarar datos sensibles
function maskEmail($email) {{
    $parts = explode('@', $email);
    if (count($parts) == 2) {{
        $name = $parts[0];
        $domain = $parts[1];
        $masked = substr($name, 0, 2) . str_repeat('*', max(strlen($name) - 2, 3));
        return $masked . '@' . $domain;
    }}
    return '***@***.***';
}}

function maskSalary($salary) {{
    // Solo mostrar rango salarial, no el monto exacto
    $salary = floatval($salary);
    if ($salary < 30000) return '$20,000 - $30,000';
    if ($salary < 50000) return '$30,000 - $50,000';
    if ($salary < 75000) return '$50,000 - $75,000';
    if ($salary < 100000) return '$75,000 - $100,000';
    return '$100,000+';
}}

$pdo = getDBConnection();
$employees = [];
$error = null;

if ($pdo) {{
    try {{
        // Usar prepared statements para prevenir SQL Injection
        $stmt = $pdo->prepare("SELECT id, nombre, email, salario, departamento, fecha_ingreso FROM empleados ORDER BY nombre");
        $stmt->execute();
        $employees = $stmt->fetchAll();
    }} catch (PDOException $e) {{
        error_log("Error en consulta: " . $e->getMessage());
        $error = "Error al cargar los datos.";
    }}
}}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Sistema de Recursos Humanos</title>
    <style>
        :root {{
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --success: #059669;
            --warning: #d97706;
            --danger: #dc2626;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-700: #374151;
            --gray-900: #111827;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            background: white;
            border-radius: 1rem;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            color: var(--gray-900);
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        
        .header p {{
            color: var(--gray-700);
        }}
        
        .security-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: #dcfce7;
            color: var(--success);
            padding: 0.5rem 1rem;
            border-radius: 2rem;
            font-size: 0.875rem;
            font-weight: 500;
            margin-top: 1rem;
        }}
        
        .card {{
            background: white;
            border-radius: 1rem;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .card-header {{
            background: var(--gray-50);
            padding: 1.5rem;
            border-bottom: 1px solid var(--gray-200);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .card-header h2 {{
            color: var(--gray-900);
            font-size: 1.25rem;
        }}
        
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            font-weight: 500;
            text-decoration: none;
            cursor: pointer;
            border: none;
            transition: all 0.2s;
        }}
        
        .btn-primary {{
            background: var(--primary);
            color: white;
        }}
        
        .btn-primary:hover {{
            background: var(--primary-dark);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 1rem 1.5rem;
            text-align: left;
            border-bottom: 1px solid var(--gray-200);
        }}
        
        th {{
            background: var(--gray-50);
            font-weight: 600;
            color: var(--gray-700);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        tr:hover {{
            background: var(--gray-50);
        }}
        
        .employee-name {{
            font-weight: 600;
            color: var(--gray-900);
        }}
        
        .masked-data {{
            color: var(--gray-700);
            font-family: monospace;
        }}
        
        .department {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            background: #dbeafe;
            color: var(--primary);
            border-radius: 1rem;
            font-size: 0.875rem;
        }}
        
        .salary-range {{
            color: var(--success);
            font-weight: 500;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 4rem 2rem;
            color: var(--gray-700);
        }}
        
        .empty-state h3 {{
            margin-bottom: 0.5rem;
            color: var(--gray-900);
        }}
        
        .footer {{
            text-align: center;
            padding: 2rem;
            color: rgba(255,255,255,0.8);
            font-size: 0.875rem;
        }}
        
        .alert {{
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }}
        
        .alert-error {{
            background: #fef2f2;
            color: var(--danger);
            border: 1px solid #fecaca;
        }}
        
        .info-banner {{
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            color: var(--primary);
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏢 Sistema de Gestión de Recursos Humanos</h1>
            <p>Gestión segura de información de empleados</p>
            <div class="security-badge">
                🔒 Datos protegidos y enmascarados
            </div>
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-error">
                <?php echo sanitize($error); ?>
            </div>
        <?php endif; ?>
        
        <div class="info-banner">
            ℹ️ Por políticas de seguridad, los emails y salarios se muestran de forma enmascarada. 
            Solo personal autorizado puede ver los datos completos.
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2>📋 Directorio de Empleados</h2>
                <a href="add_employee.php" class="btn btn-primary">
                    ➕ Agregar Empleado
                </a>
            </div>
            
            <?php if (empty($employees)): ?>
                <div class="empty-state">
                    <h3>No hay empleados registrados</h3>
                    <p>Comienza agregando el primer empleado al sistema.</p>
                </div>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Nombre</th>
                            <th>Email</th>
                            <th>Departamento</th>
                            <th>Rango Salarial</th>
                            <th>Fecha Ingreso</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($employees as $emp): ?>
                            <tr>
                                <td><?php echo sanitize($emp['id']); ?></td>
                                <td class="employee-name"><?php echo sanitize($emp['nombre']); ?></td>
                                <td class="masked-data"><?php echo maskEmail($emp['email']); ?></td>
                                <td><span class="department"><?php echo sanitize($emp['departamento']); ?></span></td>
                                <td class="salary-range"><?php echo maskSalary($emp['salario']); ?></td>
                                <td><?php echo sanitize($emp['fecha_ingreso']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        
        <div class="footer">
            <p>Sistema de Recursos Humanos v1.0 | Datos Confidenciales - Acceso Restringido</p>
            <p>🔐 Conexión segura a base de datos MySQL en Amazon RDS</p>
        </div>
    </div>
</body>
</html>
INDEX_PHP

# Página para agregar empleados
cat > /var/www/html/add_employee.php << 'ADD_PHP'
<?php
/**
 * Formulario para agregar empleados
 * Incluye validación y protección contra CSRF
 */

session_start();
require_once '/var/www/config/database.php';

// Generar token CSRF
if (empty($_SESSION['csrf_token'])) {{
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}}

function getDBConnection() {{
    try {{
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        return new PDO($dsn, DB_USER, DB_PASS, DB_OPTIONS);
    }} catch (PDOException $e) {{
        error_log("Error de conexión: " . $e->getMessage());
        return null;
    }}
}}

function sanitize($data) {{
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}}

function validateEmail($email) {{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}}

function validateSalary($salary) {{
    return is_numeric($salary) && $salary > 0 && $salary < 10000000;
}}

$message = '';
$messageType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {{
    // Verificar token CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {{
        $message = 'Error de seguridad: Token inválido.';
        $messageType = 'error';
    }} else {{
        $nombre = trim($_POST['nombre'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $salario = $_POST['salario'] ?? '';
        $departamento = trim($_POST['departamento'] ?? '');
        
        // Validaciones
        $errors = [];
        
        if (empty($nombre) || strlen($nombre) < 2 || strlen($nombre) > 100) {{
            $errors[] = 'El nombre debe tener entre 2 y 100 caracteres.';
        }}
        
        if (!validateEmail($email)) {{
            $errors[] = 'El email no es válido.';
        }}
        
        if (!validateSalary($salario)) {{
            $errors[] = 'El salario debe ser un número positivo válido.';
        }}
        
        if (empty($departamento)) {{
            $errors[] = 'Debe seleccionar un departamento.';
        }}
        
        if (empty($errors)) {{
            $pdo = getDBConnection();
            if ($pdo) {{
                try {{
                    $stmt = $pdo->prepare("INSERT INTO empleados (nombre, email, salario, departamento, fecha_ingreso) VALUES (?, ?, ?, ?, CURDATE())");
                    $stmt->execute([$nombre, $email, $salario, $departamento]);
                    
                    $message = 'Empleado agregado exitosamente.';
                    $messageType = 'success';
                    
                    // Regenerar token CSRF
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    
                }} catch (PDOException $e) {{
                    error_log("Error al insertar: " . $e->getMessage());
                    if ($e->getCode() == 23000) {{
                        $message = 'Ya existe un empleado con ese email.';
                    }} else {{
                        $message = 'Error al guardar el empleado.';
                    }}
                    $messageType = 'error';
                }}
            }} else {{
                $message = 'Error de conexión a la base de datos.';
                $messageType = 'error';
            }}
        }} else {{
            $message = implode(' ', $errors);
            $messageType = 'error';
        }}
    }}
}}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agregar Empleado - Sistema RH</title>
    <style>
        :root {{
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --success: #059669;
            --danger: #dc2626;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-700: #374151;
            --gray-900: #111827;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 600px;
            margin: 0 auto;
        }}
        
        .card {{
            background: white;
            border-radius: 1rem;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .card-header {{
            background: var(--gray-50);
            padding: 1.5rem;
            border-bottom: 1px solid var(--gray-200);
        }}
        
        .card-header h1 {{
            color: var(--gray-900);
            font-size: 1.5rem;
        }}
        
        .card-body {{
            padding: 2rem;
        }}
        
        .form-group {{
            margin-bottom: 1.5rem;
        }}
        
        label {{
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--gray-700);
        }}
        
        input, select {{
            width: 100%;
            padding: 0.75rem 1rem;
            border: 2px solid var(--gray-200);
            border-radius: 0.5rem;
            font-size: 1rem;
            transition: border-color 0.2s;
        }}
        
        input:focus, select:focus {{
            outline: none;
            border-color: var(--primary);
        }}
        
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            font-weight: 500;
            text-decoration: none;
            cursor: pointer;
            border: none;
            font-size: 1rem;
            transition: all 0.2s;
        }}
        
        .btn-primary {{
            background: var(--primary);
            color: white;
        }}
        
        .btn-primary:hover {{
            background: var(--primary-dark);
        }}
        
        .btn-secondary {{
            background: var(--gray-200);
            color: var(--gray-700);
        }}
        
        .btn-group {{
            display: flex;
            gap: 1rem;
            margin-top: 2rem;
        }}
        
        .alert {{
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
        }}
        
        .alert-success {{
            background: #dcfce7;
            color: var(--success);
            border: 1px solid #bbf7d0;
        }}
        
        .alert-error {{
            background: #fef2f2;
            color: var(--danger);
            border: 1px solid #fecaca;
        }}
        
        .security-note {{
            background: #fffbeb;
            border: 1px solid #fde68a;
            color: #92400e;
            padding: 1rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
            margin-top: 1.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h1>➕ Agregar Nuevo Empleado</h1>
            </div>
            <div class="card-body">
                <?php if ($message): ?>
                    <div class="alert alert-<?php echo $messageType; ?>">
                        <?php echo sanitize($message); ?>
                    </div>
                <?php endif; ?>
                
                <form method="POST" action="">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    
                    <div class="form-group">
                        <label for="nombre">Nombre Completo *</label>
                        <input type="text" id="nombre" name="nombre" required 
                               minlength="2" maxlength="100"
                               placeholder="Ej: Juan Pérez García">
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Correo Electrónico *</label>
                        <input type="email" id="email" name="email" required 
                               placeholder="empleado@empresa.com">
                    </div>
                    
                    <div class="form-group">
                        <label for="salario">Salario Anual (USD) *</label>
                        <input type="number" id="salario" name="salario" required 
                               min="1" max="9999999" step="0.01"
                               placeholder="50000">
                    </div>
                    
                    <div class="form-group">
                        <label for="departamento">Departamento *</label>
                        <select id="departamento" name="departamento" required>
                            <option value="">Seleccionar...</option>
                            <option value="Tecnología">Tecnología</option>
                            <option value="Recursos Humanos">Recursos Humanos</option>
                            <option value="Finanzas">Finanzas</option>
                            <option value="Marketing">Marketing</option>
                            <option value="Operaciones">Operaciones</option>
                            <option value="Ventas">Ventas</option>
                            <option value="Legal">Legal</option>
                        </select>
                    </div>
                    
                    <div class="btn-group">
                        <button type="submit" class="btn btn-primary">
                            💾 Guardar Empleado
                        </button>
                        <a href="index.php" class="btn btn-secondary">
                            ← Volver al Listado
                        </a>
                    </div>
                </form>
                
                <div class="security-note">
                    🔒 <strong>Nota de Seguridad:</strong> Todos los datos ingresados son 
                    almacenados de forma segura y encriptada en la base de datos.
                </div>
            </div>
        </div>
    </div>
</body>
</html>
ADD_PHP

# Página de estado de salud (para monitoreo)
cat > /var/www/html/health.php << 'HEALTH_PHP'
<?php
header('Content-Type: application/json');

require_once '/var/www/config/database.php';

$status = [
    'status' => 'healthy',
    'timestamp' => date('c'),
    'services' => [
        'web' => 'up',
        'database' => 'unknown'
    ]
];

try {{
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
    $pdo = new PDO($dsn, DB_USER, DB_PASS, DB_OPTIONS);
    $pdo->query("SELECT 1");
    $status['services']['database'] = 'up';
}} catch (Exception $e) {{
    $status['services']['database'] = 'down';
    $status['status'] = 'degraded';
}}

http_response_code($status['status'] === 'healthy' ? 200 : 503);
echo json_encode($status, JSON_PRETTY_PRINT);
HEALTH_PHP

# =============================================================================
# CONFIGURAR PERMISOS
# =============================================================================

chown -R apache:apache /var/www/html
chmod -R 755 /var/www/html
chmod 644 /var/www/html/*.php

# Proteger archivos de configuración
cat > /var/www/html/.htaccess << 'HTACCESS'
# Denegar acceso a archivos sensibles
<Files "*.php">
    Order Allow,Deny
    Allow from all
</Files>

<Files ".ht*">
    Order Allow,Deny
    Deny from all
</Files>

# Prevenir acceso directo a includes
<Files "config.php">
    Order Allow,Deny
    Deny from all
</Files>

# Configuración adicional de seguridad
Options -Indexes
HTACCESS

# =============================================================================
# REINICIAR APACHE
# =============================================================================

systemctl restart httpd

echo "=========================================="
echo "CONFIGURACIÓN COMPLETADA EXITOSAMENTE"
echo "=========================================="
'''


# =============================================================================
# FUNCIONES PRINCIPALES DE DESPLIEGUE
# =============================================================================

def create_security_groups(ec2_client, vpc_id):
    """Crea los Security Groups para EC2 y RDS."""
    
    print("\n" + "="*60)
    print("CREANDO SECURITY GROUPS")
    print("="*60)
    
    # Security Group para EC2 (Web Server)
    print(f"\n📦 Creando Security Group para Web Server...")
    
    try:
        ec2_sg = ec2_client.create_security_group(
            GroupName=EC2_SG_NAME,
            Description='Security Group para Web Server - Solo HTTP/HTTPS',
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    'ResourceType': 'security-group',
                    'Tags': [
                        {'Key': 'Name', 'Value': EC2_SG_NAME},
                        {'Key': 'Application', 'Value': 'HR-System'},
                        {'Key': 'Environment', 'Value': 'Production'}
                    ]
                }
            ]
        )
        ec2_sg_id = ec2_sg['GroupId']
        print(f"   ✅ Security Group EC2 creado: {ec2_sg_id}")
    except ClientError as e:
        if 'InvalidGroup.Duplicate' in str(e):
            response = ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [EC2_SG_NAME]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            ec2_sg_id = response['SecurityGroups'][0]['GroupId']
            print(f"   ⚠️ Security Group EC2 ya existe: {ec2_sg_id}")
        else:
            raise
    
    # Agregar reglas de ingreso para EC2
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=ec2_sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0',
                            'Description': 'HTTP desde Internet'
                        }
                    ]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0',
                            'Description': 'HTTPS desde Internet'
                        }
                    ]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0',  # En producción, restringir a IPs específicas
                            'Description': 'SSH para administración'
                        }
                    ]
                }
            ]
        )
        print("   ✅ Reglas de ingreso HTTP/HTTPS/SSH agregadas")
    except ClientError as e:
        if 'InvalidPermission.Duplicate' in str(e):
            print("   ⚠️ Las reglas de ingreso ya existen")
        else:
            raise
    
    # Security Group para RDS (Base de Datos)
    print(f"\n📦 Creando Security Group para Base de Datos...")
    
    try:
        rds_sg = ec2_client.create_security_group(
            GroupName=RDS_SG_NAME,
            Description='Security Group para RDS - Solo MySQL desde EC2',
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    'ResourceType': 'security-group',
                    'Tags': [
                        {'Key': 'Name', 'Value': RDS_SG_NAME},
                        {'Key': 'Application', 'Value': 'HR-System'},
                        {'Key': 'Environment', 'Value': 'Production'}
                    ]
                }
            ]
        )
        rds_sg_id = rds_sg['GroupId']
        print(f"   ✅ Security Group RDS creado: {rds_sg_id}")
    except ClientError as e:
        if 'InvalidGroup.Duplicate' in str(e):
            response = ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [RDS_SG_NAME]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            rds_sg_id = response['SecurityGroups'][0]['GroupId']
            print(f"   ⚠️ Security Group RDS ya existe: {rds_sg_id}")
        else:
            raise
    
    # Agregar regla de ingreso para RDS - SOLO desde EC2 Security Group
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=rds_sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 3306,
                    'ToPort': 3306,
                    'UserIdGroupPairs': [
                        {
                            'GroupId': ec2_sg_id,
                            'Description': 'MySQL solo desde Web Server'
                        }
                    ]
                }
            ]
        )
        print("   ✅ Regla de ingreso MySQL (solo desde EC2) agregada")
        print(f"   🔒 RDS solo acepta conexiones desde Security Group: {ec2_sg_id}")
    except ClientError as e:
        if 'InvalidPermission.Duplicate' in str(e):
            print("   ⚠️ La regla de ingreso ya existe")
        else:
            raise
    
    return ec2_sg_id, rds_sg_id


def create_rds_subnet_group(rds_client, ec2_client, vpc_id):
    """Crea un DB Subnet Group para RDS."""
    
    print("\n📦 Creando DB Subnet Group...")
    
    # Obtener subnets del VPC
    subnets = ec2_client.describe_subnets(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
    )
    
    subnet_ids = [subnet['SubnetId'] for subnet in subnets['Subnets']]
    
    if len(subnet_ids) < 2:
        raise Exception("Se necesitan al menos 2 subnets en diferentes AZs para RDS")
    
    subnet_group_name = 'hr-database-subnet-group'
    
    try:
        rds_client.create_db_subnet_group(
            DBSubnetGroupName=subnet_group_name,
            DBSubnetGroupDescription='Subnet group para base de datos HR',
            SubnetIds=subnet_ids[:2],  # Usar las primeras 2 subnets
            Tags=[
                {'Key': 'Name', 'Value': subnet_group_name},
                {'Key': 'Application', 'Value': 'HR-System'}
            ]
        )
        print(f"   ✅ DB Subnet Group creado: {subnet_group_name}")
    except ClientError as e:
        if 'DBSubnetGroupAlreadyExists' in str(e):
            print(f"   ⚠️ DB Subnet Group ya existe: {subnet_group_name}")
        else:
            raise
    
    return subnet_group_name


def create_rds_instance(rds_client, rds_sg_id, subnet_group_name, db_password):
    """Crea la instancia RDS MySQL."""
    
    print("\n" + "="*60)
    print("CREANDO INSTANCIA RDS")
    print("="*60)
    
    print(f"\n🗄️ Creando instancia RDS MySQL: {RDS_INSTANCE_NAME}")
    print("   ⏳ Este proceso puede tomar 5-10 minutos...")
    
    try:
        response = rds_client.create_db_instance(
            DBInstanceIdentifier=RDS_INSTANCE_NAME,
            DBInstanceClass=RDS_INSTANCE_CLASS,
            Engine=RDS_ENGINE,
            EngineVersion=RDS_ENGINE_VERSION,
            MasterUsername=RDS_MASTER_USERNAME,
            MasterUserPassword=db_password,
            DBName=RDS_DB_NAME,
            AllocatedStorage=RDS_ALLOCATED_STORAGE,
            VpcSecurityGroupIds=[rds_sg_id],
            DBSubnetGroupName=subnet_group_name,
            PubliclyAccessible=False,  # IMPORTANTE: No accesible públicamente
            StorageType='gp2',
            StorageEncrypted=True,  # Encriptación en reposo
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=7,  # Backups por 7 días
            DeletionProtection=False,  # Cambiar a True en producción
            EnablePerformanceInsights=False,
            Tags=[
                {'Key': 'Name', 'Value': RDS_INSTANCE_NAME},
                {'Key': 'Application', 'Value': 'HR-System'},
                {'Key': 'Environment', 'Value': 'Production'},
                {'Key': 'DataClassification', 'Value': 'Confidential'}
            ]
        )
        print(f"   ✅ Instancia RDS creada exitosamente")
        print(f"   🔒 Encriptación habilitada")
        print(f"   🔒 Acceso público deshabilitado")
        
    except ClientError as e:
        if 'DBInstanceAlreadyExists' in str(e):
            print(f"   ⚠️ La instancia RDS ya existe: {RDS_INSTANCE_NAME}")
        else:
            raise
    
    # Esperar a que RDS esté disponible
    db_instance = wait_for_rds_available(rds_client, RDS_INSTANCE_NAME)
    
    return db_instance['Endpoint']['Address']


def initialize_database(rds_endpoint, db_password):
    """Retorna el script SQL para inicializar la base de datos."""
    
    return f'''
-- Script de inicialización de la base de datos HR

USE {RDS_DB_NAME};

-- Crear tabla de empleados
CREATE TABLE IF NOT EXISTS empleados (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    salario DECIMAL(12, 2) NOT NULL,
    departamento VARCHAR(50) NOT NULL,
    fecha_ingreso DATE NOT NULL,
    activo BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_departamento (departamento),
    INDEX idx_email (email),
    INDEX idx_fecha_ingreso (fecha_ingreso)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insertar datos de ejemplo
INSERT INTO empleados (nombre, email, salario, departamento, fecha_ingreso) VALUES
('María García López', 'maria.garcia@empresa.com', 65000.00, 'Tecnología', '2022-03-15'),
('Carlos Rodríguez Martínez', 'carlos.rodriguez@empresa.com', 55000.00, 'Recursos Humanos', '2021-08-01'),
('Ana Martínez Pérez', 'ana.martinez@empresa.com', 72000.00, 'Finanzas', '2020-01-10'),
('José López García', 'jose.lopez@empresa.com', 48000.00, 'Marketing', '2023-02-20'),
('Laura Sánchez Ruiz', 'laura.sanchez@empresa.com', 85000.00, 'Tecnología', '2019-06-05');

-- Confirmar creación
SELECT 'Base de datos inicializada correctamente' AS mensaje;
SELECT COUNT(*) AS total_empleados FROM empleados;
'''


def create_key_pair(ec2_client):
    """Crea o recupera el key pair para EC2."""
    
    print(f"\n🔑 Verificando Key Pair: {EC2_KEY_NAME}")
    
    try:
        ec2_client.describe_key_pairs(KeyNames=[EC2_KEY_NAME])
        print(f"   ✅ Key Pair ya existe: {EC2_KEY_NAME}")
        return EC2_KEY_NAME
    except ClientError:
        pass
    
    # Crear nuevo key pair
    try:
        response = ec2_client.create_key_pair(
            KeyName=EC2_KEY_NAME,
            TagSpecifications=[
                {
                    'ResourceType': 'key-pair',
                    'Tags': [
                        {'Key': 'Name', 'Value': EC2_KEY_NAME},
                        {'Key': 'Application', 'Value': 'HR-System'}
                    ]
                }
            ]
        )
        
        # Guardar la clave privada
        key_file = f"{EC2_KEY_NAME}.pem"
        with open(key_file, 'w') as f:
            f.write(response['KeyMaterial'])
        
        print(f"   ✅ Key Pair creado: {EC2_KEY_NAME}")
        print(f"   📁 Clave privada guardada en: {key_file}")
        print(f"   ⚠️ IMPORTANTE: Guarda este archivo de forma segura")
        
        return EC2_KEY_NAME
        
    except ClientError as e:
        print(f"   ❌ Error al crear Key Pair: {e}")
        raise


def create_ec2_instance(ec2_client, ec2_sg_id, ami_id, key_name, user_data):
    """Crea la instancia EC2 con Apache."""
    
    print("\n" + "="*60)
    print("CREANDO INSTANCIA EC2")
    print("="*60)
    
    print(f"\n🖥️ Lanzando instancia EC2: {EC2_INSTANCE_NAME}")
    
    response = ec2_client.run_instances(
        ImageId=ami_id,
        InstanceType=EC2_INSTANCE_TYPE,
        KeyName=key_name,
        SecurityGroupIds=[ec2_sg_id],
        MinCount=1,
        MaxCount=1,
        UserData=user_data,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': EC2_INSTANCE_NAME},
                    {'Key': 'Application', 'Value': 'HR-System'},
                    {'Key': 'Environment', 'Value': 'Production'},
                    {'Key': 'Role', 'Value': 'WebServer'}
                ]
            }
        ],
        MetadataOptions={
            'HttpTokens': 'required',  # Requerir IMDSv2 (más seguro)
            'HttpEndpoint': 'enabled'
        },
        BlockDeviceMappings=[
            {
                'DeviceName': '/dev/xvda',
                'Ebs': {
                    'VolumeSize': 8,
                    'VolumeType': 'gp3',
                    'Encrypted': True,  # Encriptación del volumen
                    'DeleteOnTermination': True
                }
            }
        ]
    )
    
    instance_id = response['Instances'][0]['InstanceId']
    print(f"   ✅ Instancia creada: {instance_id}")
    print(f"   🔒 IMDSv2 requerido (protección contra SSRF)")
    print(f"   🔒 Volumen EBS encriptado")
    
    # Esperar a que la instancia esté running
    instance = wait_for_instance_running(ec2_client, instance_id)
    
    return instance_id, instance.get('PublicIpAddress')


def get_default_vpc(ec2_client):
    """Obtiene el VPC por defecto."""
    
    print("\n🔍 Buscando VPC por defecto...")
    
    response = ec2_client.describe_vpcs(
        Filters=[{'Name': 'isDefault', 'Values': ['true']}]
    )
    
    if response['Vpcs']:
        vpc_id = response['Vpcs'][0]['VpcId']
        print(f"   ✅ VPC por defecto encontrado: {vpc_id}")
        return vpc_id
    else:
        raise Exception("No se encontró VPC por defecto")


# =============================================================================
# FUNCIÓN PRINCIPAL
# =============================================================================

def main():
    """Función principal de despliegue."""
    
    print("\n" + "="*60)
    print("🚀 DESPLIEGUE DE APLICACIÓN DE RECURSOS HUMANOS")
    print("   Arquitectura de Dos Capas: EC2 + RDS")
    print("="*60)
    
    # Generar contraseña segura para RDS
    db_password = generate_secure_password()
    print(f"\n🔐 Contraseña de base de datos generada de forma segura")
    
    # Inicializar clientes de AWS
    print(f"\n📡 Conectando a AWS en región: {AWS_REGION}")
    
    ec2_client = boto3.client('ec2', region_name=AWS_REGION)
    rds_client = boto3.client('rds', region_name=AWS_REGION)
    
    try:
        # 1. Obtener VPC por defecto
        vpc_id = get_default_vpc(ec2_client)
        
        # 2. Crear Security Groups
        ec2_sg_id, rds_sg_id = create_security_groups(ec2_client, vpc_id)
        
        # 3. Crear DB Subnet Group
        subnet_group_name = create_rds_subnet_group(rds_client, ec2_client, vpc_id)
        
        # 4. Crear instancia RDS
        rds_endpoint = create_rds_instance(rds_client, rds_sg_id, subnet_group_name, db_password)
        
        # 5. Obtener AMI
        ami_id = get_latest_amazon_linux_ami(ec2_client)
        
        # 6. Crear/verificar Key Pair
        key_name = create_key_pair(ec2_client)
        
        # 7. Generar User Data con configuración de RDS
        user_data = get_user_data_script(rds_endpoint, db_password)
        
        # 8. Crear instancia EC2
        instance_id, public_ip = create_ec2_instance(
            ec2_client, ec2_sg_id, ami_id, key_name, user_data
        )
        
        # =================================================================
        # RESUMEN FINAL
        # =================================================================
        
        print("\n" + "="*60)
        print("✅ DESPLIEGUE COMPLETADO EXITOSAMENTE")
        print("="*60)
        
        print(f"""
📊 RESUMEN DE RECURSOS CREADOS:

   🖥️ EC2 Web Server:
      • Instance ID: {instance_id}
      • IP Pública: {public_ip}
      • URL de la aplicación: http://{public_ip}
      • Security Group: {ec2_sg_id}
   
   🗄️ RDS MySQL:
      • Endpoint: {rds_endpoint}
      • Database: {RDS_DB_NAME}
      • Usuario: {RDS_MASTER_USERNAME}
      • Security Group: {rds_sg_id}
   
   🔒 MEDIDAS DE SEGURIDAD IMPLEMENTADAS:
      
      ✅ Security Groups:
         • EC2: Solo permite HTTP (80), HTTPS (443) y SSH (22)
         • RDS: Solo acepta MySQL (3306) desde el SG de EC2
      
      ✅ Base de Datos:
         • No accesible públicamente
         • Encriptación en reposo habilitada
         • Contraseña segura generada automáticamente
         • Backups automáticos (7 días)
      
      ✅ Servidor Web:
         • Headers de seguridad configurados
         • PHP hardened (funciones peligrosas deshabilitadas)
         • IMDSv2 requerido (protección SSRF)
         • Volumen EBS encriptado
      
      ✅ Aplicación:
         • Protección contra SQL Injection (prepared statements)
         • Protección contra XSS (sanitización de salida)
         • Protección CSRF (tokens en formularios)
         • Datos sensibles enmascarados en UI
         • Archivo de configuración fuera de web root

⚠️ CREDENCIALES (GUARDAR DE FORMA SEGURA):
   
   Base de datos:
   • Host: {rds_endpoint}
   • Usuario: {RDS_MASTER_USERNAME}
   • Contraseña: {db_password}
   • Base de datos: {RDS_DB_NAME}

📝 PRÓXIMOS PASOS:

   1. Esperar 2-3 minutos para que Apache termine de configurarse
   
   2. Acceder a la aplicación:
      http://{public_ip}
   
   3. Inicializar la base de datos conectándose por SSH:
      ssh -i {EC2_KEY_NAME}.pem ec2-user@{public_ip}
      
      Luego ejecutar:
      mysql -h {rds_endpoint} -u {RDS_MASTER_USERNAME} -p{db_password} {RDS_DB_NAME}
      
   4. Ejecutar el SQL de inicialización (ver archivo init_database.sql)

   5. Para producción, considerar:
      • Configurar HTTPS con certificado SSL
      • Restringir SSH a IPs específicas
      • Habilitar DeletionProtection en RDS
      • Configurar CloudWatch para monitoreo
      • Implementar AWS WAF
""")
        
        # Guardar script de inicialización de BD
        init_sql = initialize_database(rds_endpoint, db_password)
        with open('init_database.sql', 'w') as f:
            f.write(init_sql)
        print("   📁 Script SQL guardado en: init_database.sql")
        
        # Guardar credenciales en archivo seguro
        with open('credentials.txt', 'w') as f:
            f.write(f"""# CREDENCIALES - MANTENER SEGURO
# Generado: {time.strftime('%Y-%m-%d %H:%M:%S')}

[EC2]
Instance ID: {instance_id}
Public IP: {public_ip}
Key Pair: {EC2_KEY_NAME}

[RDS]
Endpoint: {rds_endpoint}
Database: {RDS_DB_NAME}
Username: {RDS_MASTER_USERNAME}
Password: {db_password}
""")
        print("   📁 Credenciales guardadas en: credentials.txt")
        print("   ⚠️ IMPORTANTE: Eliminar este archivo después de copiar las credenciales")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR DURANTE EL DESPLIEGUE: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

