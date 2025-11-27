#!/bin/bash

# Script para crear usuarios en el sistema a partir de un archivo de texto.
# Permite:
#  - Mostrar info detallada de cada creación (-i)
#  - Asignar una misma contraseña a todos (-c contraseña)
#  - Leer un archivo con formato: usuario:comentario:directorio_home:crear_home(SI/NO):shell

# Códigos de error (para salir con distintos códigos según el problema)
ERROR_ARCHIVO_NO_EXISTE=1        # El archivo de usuarios no existe
ERROR_ARCHIVO_NO_REGULAR=2       # El archivo no es regular
ERROR_SIN_PERMISOS_LECTURA=3     # No hay permisos de lectura sobre el archivo
ERROR_SINTAXIS_ARCHIVO=4         # Error de formato/sintaxis en alguna línea del archivo
ERROR_PARAMETRO_INCORRECTO=5     # Error en el uso de opciones (parámetros incorrectos)
ERROR_NUMERO_PARAMETROS=6        # Error en la cantidad/lógica de parámetros
ERROR_OTRO=7                     # Otros errores (genérico)

# Variables principales
ARCHIVO_USUARIOS=""              # Ruta del archivo con la lista de usuarios
PASSWORD=""                      # Contraseña a asignar si se usa -c
MOSTRAR_INFO=false               # Indica si se muestra info detallada (-i)
usuarios_creados=0               # Contador de usuarios creados

# Verificar que el script se ejecute como root (uid 0)
if [[ "$EUID" -ne 0 ]]; then
    echo "Error: Este script debe ejecutarse como root (usar sudo)" >&2
    exit $ERROR_OTRO
fi

# Flag para saber si ya se especificó un archivo de usuarios
tiene_archivo=false

# Bucle para procesar todos los parámetros recibidos ($@)
while [[ $# -gt 0 ]]; do
    case $1 in
        -i)
            # Opción -i: activar la salida informativa
            MOSTRAR_INFO=true
            shift   
            ;;
        -c)
            # Opción -c: siguiente parámetro debe ser la contraseña
            if [[ -z "$2" ]]; then
                echo "Error: La opción -c requiere un argumento (contraseña)" >&2
                exit $ERROR_PARAMETRO_INCORRECTO
            fi
            PASSWORD="$2"  # Guardamos la contraseña
            shift 2        # Consumimos '-c' y el valor de la contraseña
            ;;
        -*)
            # Cualquier otra opción que empiece con '-' se considera inválida
            echo "Error: Modificador inválido: $1" >&2
            exit $ERROR_PARAMETRO_INCORRECTO
            ;;
        *)
            # Cualquier cosa que no empiece con '-' se toma como archivo de usuarios
            if [[ "$tiene_archivo" == true ]]; then
                # Si ya teníamos un archivo, significa que pasaron más de un error
                echo "Error: Se especificó más de un archivo" >&2
                exit $ERROR_NUMERO_PARAMETROS
            fi
            ARCHIVO_USUARIOS="$1"  # Guardamos el nombre del archivo
            tiene_archivo=true     # Marcamos que ya se especificó archivo
            shift                  # Consumimos este parámetro
            ;;
    esac
done

# Verificar que se haya pasado un archivo de usuarios
if [[ "$tiene_archivo" == false ]]; then
    echo "Error: Debe especificar un archivo con los usuarios a crear" >&2
    echo "Uso: $0 [-i] [-c contraseña] Archivo_con_los_usuarios_a_crear" >&2
    echo "" >&2
    echo "Opciones:" >&2
    echo "  -i              Muestra información sobre la creación de cada usuario" >&2
    echo "  -c contraseña    Asigna la contraseña especificada a todos los usuarios creados" >&2
    echo "  Archivo         Archivo con la información de usuarios (obligatorio)" >&2
    echo "" >&2
    echo "Formato del archivo (campos separados por :):" >&2
    echo "  usuario:comentario:directorio_home:crear_home(SI/NO):shell" >&2
    exit $ERROR_NUMERO_PARAMETROS
fi

# Verificar que el archivo exista
if [[ ! -e "$ARCHIVO_USUARIOS" ]]; then
    echo "Error: El archivo '$ARCHIVO_USUARIOS' no existe" >&2
    exit $ERROR_ARCHIVO_NO_EXISTE
fi

# Verificar que sea un archivo regular
if [[ ! -f "$ARCHIVO_USUARIOS" ]]; then
    echo "Error: '$ARCHIVO_USUARIOS' no es un archivo regular" >&2
    exit $ERROR_ARCHIVO_NO_REGULAR
fi

# Verificar permisos de lectura
if [[ ! -r "$ARCHIVO_USUARIOS" ]]; then
    echo "Error: No se tienen permisos de lectura para '$ARCHIVO_USUARIOS'" >&2
    exit $ERROR_SIN_PERMISOS_LECTURA
fi

# Variables para control de lectura de líneas y errores
num_linea=0             # Lleva el número de línea actual del archivo
errores_sintaxis=false  # Indica si hubo errores de formato
errores_creacion=false  # Indica si hubo errores al crear usuarios

# Leer el archivo línea por línea
# IFS= read -r linea   → lee la línea respetando espacios
# || [[ -n "$linea" ]] → asegura leer la última línea aunque no termine en '\n'
while IFS= read -r linea || [[ -n "$linea" ]]; do
    num_linea=$((num_linea + 1))  # Incrementar número de línea
    
    # Quitar espacios en blanco al inicio y al final de la línea
    linea_trimmed=$(echo "$linea" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    # Saltar líneas vacías o que comiencen con '#'
    if [[ -z "$linea_trimmed" ]] || [[ "$linea_trimmed" =~ ^# ]]; then
        continue
    fi
    
    # Contar cuántos ':' tiene la línea.
    # Si tiene 4 ':' → 5 campos: usuario:comentario:home:crear_home:shell
    num_campos=$(echo "$linea_trimmed" | tr -cd ':' | wc -c)
    
    if [[ $num_campos -ne 4 ]]; then
        echo "Error: Línea $num_linea no contiene exactamente 5 campos separados por ':'" >&2
        echo "  Línea: $linea_trimmed" >&2
        errores_sintaxis=true
        continue
    fi
    
    # Separar la línea en variables usando ':' como separador
    IFS=':' read -r usuario comentario home_dir crear_home shell <<< "$linea_trimmed"
    
    # Validar que el nombre de usuario no esté vacío
    if [[ -z "$usuario" ]]; then
        echo "Error: Línea $num_linea - El nombre de usuario no puede estar vacío" >&2
        errores_sintaxis=true
        continue
    fi
    
    # Verificar si el usuario ya existe en el sistema
    if id "$usuario" &>/dev/null; then
        if [[ "$MOSTRAR_INFO" == true ]]; then
            echo "Usuario '$usuario' (línea $num_linea): Ya existe, se omite"
        fi
        continue  # No lo crea de nuevo, sigue con la siguiente línea
    fi
    
    # Array para ir armando los parámetros a pasar a useradd
    args=()
    
    # Si hay comentario, agregar opción -c "comentario"
    if [[ -n "$comentario" ]]; then
        args+=(-c "$comentario")
    fi
    
    # Si hay directorio home (campo no vacío), agregar opción -d
    if [[ -n "$home_dir" ]]; then
        args+=(-d "$home_dir")
    fi
    
    # Según el valor SI/NO, decidir si crear o no el home (-m o -M)
    if [[ "$crear_home" == "SI" ]] || [[ "$crear_home" == "si" ]] || [[ "$crear_home" == "Si" ]]; then
        args+=(-m)   # Crear el home
    elif [[ "$crear_home" == "NO" ]] || [[ "$crear_home" == "no" ]] || [[ "$crear_home" == "No" ]]; then
        args+=(-M)   # No crear el home
    fi
    
    # Si el campo de shell no está vacío, verificar que el archivo exista
    if [[ -n "$shell" ]]; then
        if [[ ! -f "$shell" ]]; then
            # La shell no existe, marcamos error pero no detenemos todo el script
            if [[ "$MOSTRAR_INFO" == true ]]; then
                echo "Usuario '$usuario' (línea $num_linea): ERROR - Shell '$shell' no existe"
            fi
            errores_creacion=true
            continue
        fi
        # Si existe, se agrega la opción -s
        args+=(-s "$shell")
    fi
    
    # Finalmente, agregar el nombre de usuario como último argumento
    args+=("$usuario")
    
    # Intentar crear el usuario con useradd y los argumentos armados
    if useradd "${args[@]}" 2>/dev/null; then
        # Si se creó correctamente y se definió una contraseña general
        if [[ -n "$PASSWORD" ]]; then
            # Asignar contraseña con chpasswd
            if ! echo "$usuario:$PASSWORD" | chpasswd 2>/dev/null; then
                # Si no se pudo asignar la contraseña, marcar el error
                if [[ "$MOSTRAR_INFO" == true ]]; then
                    echo "Usuario '$usuario' (línea $num_linea): Creado pero no se pudo asignar contraseña"
                fi
                errores_creacion=true
                continue
            fi
        fi
        
        # Mensaje de éxito si corresponde mostrar info
        if [[ "$MOSTRAR_INFO" == true ]]; then
            echo "Usuario '$usuario' (línea $num_linea): Creado exitosamente"
        fi
        # Incrementar contador de usuarios creados
        usuarios_creados=$((usuarios_creados + 1))
    else
        # useradd falló por algún motivo (uid, grupos, etc.)
        if [[ "$MOSTRAR_INFO" == true ]]; then
            echo "Usuario '$usuario' (línea $num_linea): ERROR - No se pudo crear"
        fi
        errores_creacion=true
    fi
    
# Redirección final: todo el while lee desde el archivo de usuarios
done < "$ARCHIVO_USUARIOS"

# Al final, si se pidió info, mostrar el total de usuarios creados
if [[ "$MOSTRAR_INFO" == true ]]; then
    echo ""
    echo "Total de usuarios creados exitosamente: $usuarios_creados"
fi

# Decidir código de salida según los errores ocurridos
if [[ "$errores_sintaxis" == true ]]; then
    # Hubo al menos un error de formato en el archivo
    exit $ERROR_SINTAXIS_ARCHIVO
elif [[ "$errores_creacion" == true ]]; then
    # Hubo problemas al crear usuarios (shell no existe, useradd falló, etc.)
    exit $ERROR_OTRO
fi

# Si todo fue bien, devolver 0 (éxito)
exit 0
