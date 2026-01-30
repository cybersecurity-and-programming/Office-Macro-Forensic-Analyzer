#!/usr/bin/python3
from oletools.olevba import VBA_Parser
from argparse import ArgumentParser

BANNER = r"""
███╗   ███╗ █████╗  ██████╗██████╗  ██████═╗
████╗ ████║██╔══██╗██╔════╝██╔══██╗██╔═══██║
██╔████╔██║███████║██║     ██████╔╝██║   ██║
██║╚██╔╝██║██╔══██║██║     ██╔══██╗██║   ██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║╚██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝

        [ MACRO ANALYZER v1.0 ]
        ------------------------
        System online...
        Loading VBA signatures...
        Parsing IOC matrix...

        Advanced Macro Forensics & IOC Analysis
        Inspecting the unseen. Revealing the hidden.
"""

# Tabla de severidad extensible
SEVERITY_MAP = {
    "AutoExec": "alta",
    "Suspicious": "alta",
    "IOC": "alta",
    "VBA obfuscation": "media",
    "Hex": "media",
    "Base64": "media",
    "String": "baja",
}

def print_banner():
    print(BANNER)

def clasificar_severidad(kw_type, keyword, description):
    """
    Clasifica la severidad de un indicador detectado por oletools.

    Parámetros:
        kw_type (str): Tipo de indicador devuelto por analyze_macros()
                       (por ejemplo: 'Suspicious', 'AutoExec', 'IOC', etc.)
        keyword (str): Palabra clave detectada en el análisis.
        description (str): Descripción del indicador proporcionada por oletools.

    Retorna:
        str: Nivel de severidad ('alta', 'media' o 'baja') según reglas
             predefinidas y heurísticas adicionales basadas en contenido.
    """

    # 1) Regla por tipo
    if kw_type in SEVERITY_MAP:
        return SEVERITY_MAP[kw_type]

    # 2) Reglas adicionales por contenido
    keyword_lower = keyword.lower()
    desc_lower = description.lower()

    if any(x in keyword_lower for x in ["shell", "powershell", "wscript", "createobject"]):
        return "alta"

    if "http" in keyword_lower or "url" in desc_lower:
        return "alta"

    if "encode" in desc_lower or "obfus" in desc_lower:
        return "media"

    # 3) Por defecto
    return "baja"


def analisis_macros(ruta):
    """
    Analiza las macros de un documento en busca de indicadores sospechosos.

    Esta función utiliza oletools para:
      - Detectar si el archivo contiene macros.
      - Ejecutar el análisis heurístico de oletools (analyze_macros).
      - Clasificar cada indicador según su severidad (alta, media, baja).
      - Ordenar los resultados por nivel de severidad.
      - Mostrar los resultados en una tabla formateada.

    Parámetros:
        ruta (str): Ruta al archivo DOCM/DOC/XLSM/PPTM que se desea analizar.

    Salida:
        No retorna valores. Imprime una tabla con:
            - Severidad
            - Tipo de indicador
            - Palabra clave detectada
            - Descripción del indicador
    """

    list_information = []  # Lista donde se almacenarán los indicadores detectados

    try:
        vba = VBA_Parser(ruta)

        # Comprobar si el documento contiene macros
        if vba.detect_vba_macros():
            analysis = vba.analyze_macros()

            # Recorrer cada indicador detectado por oletools
            for kw_type, keyword, description in analysis:
                severidad = clasificar_severidad(kw_type, keyword, description)

                # Guardar la información en formato tabular
                list_information.append([severidad.upper(), kw_type, keyword, description])
        else:
            print("El documento no contiene macros.")

    finally:
        # Asegurar que el parser se cierra incluso si ocurre una excepción
        vba.close()

    # Ordenar los resultados por severidad (ALTA → MEDIA → BAJA)
    prioridad = {"ALTA": 0, "MEDIA": 1, "BAJA": 2}
    list_information.sort(key=lambda x: prioridad.get(x[0], 3))

    # Mostrar los resultados en formato tabla
    print_table(list_information)



def print_table(datos):
    """
    Imprime una tabla formateada en texto plano a partir de una lista de filas.

    Esta función:
      - Calcula automáticamente el ancho necesario para cada columna.
      - Genera bordes y separadores al estilo de tablas ASCII.
      - Alinea el contenido para que la salida sea legible y profesional.

    Parámetros:
        datos (list[list[str]]): Lista de filas, donde cada fila contiene:
            [Severity, Type, Keyword, Description]

    Salida:
        No retorna valores. Imprime la tabla directamente por consola.
    """

    columnas = ['Severity', 'Type', 'Keyword', 'Description']

    # Calcular la longitud máxima de cada columna considerando cabecera + datos
    longitudes_maximas = [
        max(len(str(x)) for x in col)
        for col in zip(*([columnas] + datos))
    ]

    # Línea superior de la tabla
    print('+-' + '-+-'.join('-' * l for l in longitudes_maximas) + '-+')

    # Cabecera con nombres de columnas alineados
    print('| ' + ' | '.join(str(x).ljust(l) for x, l in zip(columnas, longitudes_maximas)) + ' |')

    # Separador entre cabecera y contenido
    print('+-' + '-+-'.join('-' * l for l in longitudes_maximas) + '-+')

    # Filas de datos
    for fila in datos:
        print('| ' + ' | '.join(str(x).ljust(l) for x, l in zip(fila, longitudes_maximas)) + ' |')
        print('+-' + '-+-'.join('-' * l for l in longitudes_maximas) + '-+')

def read_file(ruta):
    """
    Lee un archivo de Office habilitado para macros (DOCM, DOTM, XLSM, PPTM, etc.),
    extrae su código VBA y posteriormente ejecuta el análisis de indicadores sospechosos.

    Esta función:
      - Abre el archivo con VBA_Parser.
      - Comprueba si contiene macros.
      - Extrae y muestra cada macro encontrada (nombre, stream y código).
      - Cierra el parser de forma segura.
      - Llama a analisis_macros() para evaluar posibles comportamientos maliciosos.

    Parámetros:
        ruta (str): Ruta al archivo que se desea procesar.

    Salida:
        No retorna valores. Imprime:
            - El contenido de las macros extraídas.
            - Un análisis tabulado de indicadores sospechosos.
    """

    try:
        vba = VBA_Parser(ruta)

        # Comprobar si el documento contiene macros
        if vba.detect_vba_macros():
            # Extraer cada macro y mostrar su contenido
            for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                print("=" * 60)
                print(f"Archivo: {filename}")
                print(f"Stream: {stream_path}")
                print(f"Nombre VBA: {vba_filename}")
                print("-" * 60)
                print(vba_code)
        else:
            print("El documento no contiene macros.")

    finally:
        # Garantizar que el parser se cierra incluso si ocurre un error
        vba.close()

    print("\n[+] Analizando macros en busca de código malicioso\n")

    # Ejecutar el análisis heurístico de indicadores sospechosos
    analisis_macros(ruta)

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", help="archivo a leer", required=True)
    args = parser.parse_args()

    print_banner()

    read_file(args.file)
