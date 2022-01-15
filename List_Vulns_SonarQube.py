import requests, json, csv, os
from datetime import datetime
from enviar_email import email
import zipfile
import shutil
import pathlib

dt = datetime.now()
fecha_hora = (dt.strftime('%d%m%Y_%H%M%S'))

URL = "https://sonarqube.gscorp.ad/api/issues/search"
TOKEN = "colocar token de sonarqube"

projects_list = {}

#Lugar donde se encuentra el script List_VUlns_SonarQube.py  Ej: C:\\Users\\usuario\\Downloads\\SonarScript
ubicacion_absoluta = "Colocar la ruta aca"

def Consulta():
    #cantidad de registros por página. Máximo: 500
    ps = 500
    DATA = {'p':1,'ps':ps,'facets': 'severities', 'types': 'VULNERABILITY', 'severities': ['BLOCKER,CRITICAL'], 'statuses': ['OPEN', 'REOPENED', 'TO_REVIEW', 'IN_REVIEW', 'REVIEWED', 'CONFIRMED']}
    requests.packages.urllib3.disable_warnings()
    r = requests.get(url = URL, params = DATA, headers={"Accept": "*/*"}, auth=(TOKEN, ''), verify=False)
    response = r.json()
    # cantidad registros
    q = response["total"]
    pages = 1
    output = []

    while (q > 0):
        pages+=1
        #saco el page size a la cantidad de registros. 
        q -= ps
    #creo un objeto iterable, con un rango entre uno y la cantidad de páginas previamente obtenida.
    pages = range(1,pages)
    for page in pages:
        DATA = {'p':page,'ps':ps,'facets': 'severities', 'types': 'VULNERABILITY', 'severities': ['BLOCKER,CRITICAL'], 'statuses': ['OPEN', 'REOPENED', 'TO_REVIEW', 'IN_REVIEW', 'REVIEWED', 'CONFIRMED']}
        r = requests.get(url = URL, params = DATA, headers={"Accept": "*/*"}, auth=(TOKEN, ''), verify=False)
        response = r.json()
        issues = ''
        issues = response.get('issues')
        for issue in issues:
            o = {}
            o["key"]=issue["key"]
            o["rule"]=issue["rule"]
            o["severity"]=issue["severity"]
            o["component"]=issue["component"]
            o["project"]=issue["project"]
            o["line"]=issue["line"]
            o["status"]=issue["status"]
            o["message"]=issue["message"]
            try:
                o["effort"]=issue["effort"]
            except:
                o["effort"]=""
            o["creationDate"]=issue["creationDate"]
            o["updateDate"]=issue["updateDate"]
            o["type"]=issue["type"]
            output.append(o)
    return output



def listado_proyectos():
    #cantidad de registros por página. Máximo: 500
    ps = 500
    DATA = {'p':1,'ps':ps,'facets': 'severities', 'types': 'VULNERABILITY', 'severities': ['BLOCKER,CRITICAL'], 'statuses': ['OPEN', 'REOPENED', 'TO_REVIEW', 'IN_REVIEW', 'REVIEWED', 'CONFIRMED']}
    requests.packages.urllib3.disable_warnings()
    r = requests.get(url = URL, params = DATA, headers={"Accept": "*/*"}, auth=(TOKEN, ''), verify=False)
    response = r.json()
    # cantidad registros
    q = response["total"]
    pages = 1
    output = []

    while (q > 0):
        pages+=1
        #saco el page size a la cantidad de registros. 
        q -= ps
    #creo un objeto iterable, con un rango entre uno y la cantidad de páginas previamente obtenida.
    pages = range(1,pages)
    for page in pages:
        DATA = {'p':page,'ps':ps,'facets': 'severities', 'types': 'VULNERABILITY', 'severities': ['BLOCKER,CRITICAL'], 'statuses': ['OPEN', 'REOPENED', 'TO_REVIEW', 'IN_REVIEW', 'REVIEWED', 'CONFIRMED']}
        r = requests.get(url = URL, params = DATA, headers={"Accept": "*/*"}, auth=(TOKEN, ''), verify=False)
        response = r.json()
        issues = ''
        issues = response.get('issues')
        for issue in issues:
            o = {}
            o["project"]=issue["project"]
            output.append(o)

    result = []

    for item in output:
        if item not in result:
            result.append(item)    
    
    return result



def consulta_por_proyecto(proyectos,indice_proyecto):

    #cantidad de registros por página. Máximo: 500
    ps = 500
    DATA = {'p':1,'ps':ps,'facets': 'severities', 'types': 'VULNERABILITY', 'severities': ['BLOCKER,CRITICAL'], 'statuses': ['OPEN', 'REOPENED', 'TO_REVIEW', 'IN_REVIEW', 'REVIEWED', 'CONFIRMED']}
    requests.packages.urllib3.disable_warnings()
    r = requests.get(url = URL, params = DATA, headers={"Accept": "*/*"}, auth=(TOKEN, ''), verify=False)
    response = r.json()
    # cantidad registros
    q = response["total"]
    pages = 1
    output = []


    while (q > 0):
        pages+=1
        #saco el page size a la cantidad de registros. 
        q -= ps
    #creo un objeto iterable, con un rango entre uno y la cantidad de páginas previamente obtenida.
    pages = range(1,pages)


    
    for page in pages:
        DATA = {'p':page,'ps':ps,'facets': 'severities', 'types': 'VULNERABILITY', 'severities': ['BLOCKER,CRITICAL'], 'statuses': ['OPEN', 'REOPENED', 'TO_REVIEW', 'IN_REVIEW', 'REVIEWED', 'CONFIRMED']}
        r = requests.get(url = URL, params = DATA, headers={"Accept": "*/*"}, auth=(TOKEN, ''), verify=False)
        response = r.json()
        issues = ''
        issues = response.get('issues')


        for issue in issues:
            if issue["project"] == proyectos[indice_proyecto]["project"]:
                o = {}
                o["key"]=issue["key"]
                o["rule"]=issue["rule"]
                o["severity"]=issue["severity"]
                o["component"]=issue["component"]
                o["project"]=issue["project"]
                o["line"]=issue["line"]
                o["status"]=issue["status"]
                o["message"]=issue["message"]
                try:
                    o["effort"]=issue["effort"]
                except:
                    o["effort"]=""
                o["creationDate"]=issue["creationDate"]
                o["updateDate"]=issue["updateDate"]
                o["type"]=issue["type"]
                output.append(o)  
            
    crearArchivos_proyecto(output,proyectos[indice_proyecto]["project"])  
          


def crearArchivos(data):
    #Obtengo la fecha y hora
    dt = datetime.now()
    #Formateo el Date String
    fecha_hora = (dt.strftime('%d%m%Y_%H%M%S'))
    #Creo el archivo para guardar la info
    with open('ListaDeVulnsSonar_full.json', 'w') as json_file:
        json.dump(data, json_file)

    with open('ListaDeVulnsSonar_full.json') as json_file:

        data_result = json.load(json_file)

        employee_data = data_result

        # now we will open a file for writing
        data_file = open('ListaDeVulnsSonar_full.csv', 'w',newline='')

        # create the csv writer object
        csv_writer = csv.writer(data_file)

        # Counter variable used for writing
        # headers to the CSV file
        count = 0

        for emp in employee_data:
            if count == 0:

                # Writing headers of CSV file
                header = emp.keys()
                csv_writer.writerow(header)
                count += 1

            # Writing data of CSV file
            csv_writer.writerow(emp.values())

        data_file.close()

        #if os.path.exists('ListaDeVulnsSonar_full.json'):
        #    os.remove('ListaDeVulnsSonar_full.json')
 


def crearArchivos_proyecto(data,proyecto):
    #Obtengo la fecha y hora
    dt = datetime.now()
    #Formateo el Date String
    fecha_hora = (dt.strftime('%d%m%Y_%H%M%S'))
    #Creo el archivo para guardar la info
    with open('ListaDeVulnsSonar_'+proyecto+'.json', 'w') as json_file:
        json.dump(data, json_file)

    with open('ListaDeVulnsSonar_'+proyecto+'.json') as json_file:

        data_result = json.load(json_file)

        employee_data = data_result

        # now we will open a file for writing
        data_file = open('ListaDeVulnsSonar_'+proyecto+'.csv', 'w',newline='')

        # create the csv writer object
        csv_writer = csv.writer(data_file)

        # Counter variable used for writing
        # headers to the CSV file
        count = 0

        for emp in employee_data:
            if count == 0:

                # Writing headers of CSV file
                header = emp.keys()
                csv_writer.writerow(header)
                count += 1

            # Writing data of CSV file
            csv_writer.writerow(emp.values())

        data_file.close()



def crear_carpetas():

    #Quitar la ruta absoluta, ver de obtener la ruta relativa
    #ubicacion_absoluta = "/usr/src/sonar_report"

    dt = datetime.now()
    ano = (dt.strftime('%Y'))
    mes = (dt.strftime('%m'))
    dia = (dt.strftime('%d'))

    os.makedirs(ano+'\\'+mes+'\\'+dia) 

    #reporte_ubicacion = '/'+ano+'/'+mes+'/'+dia+'/'
    reporte_ubicacion = '\\'+ano+'\\'+mes+'\\'+dia+'\\'

    os.chdir(ubicacion_absoluta+reporte_ubicacion)


def eliminar_json():
    
    dt = datetime.now()
    ano = (dt.strftime('%Y'))
    mes = (dt.strftime('%m'))
    dia = (dt.strftime('%d'))

    directory = ubicacion_absoluta+'\\'+ano+'\\'+mes+'\\'+dia+'\\'
    test = os.listdir( directory )

    for item in test:
        if item.endswith(".json"):
            os.remove( os.path.join( directory, item ) )


def comprimir_zip():

    dt = datetime.now()
    ano = (dt.strftime('%Y'))
    mes = (dt.strftime('%m'))
    dia = (dt.strftime('%d'))

    d = ubicacion_absoluta+'\\'+ano+'\\'+mes+'\\'+dia
    filename = "ReporteSonar"+dia+mes+ano

    os.chdir(os.path.dirname(d))
    with zipfile.ZipFile(filename + '.zip',"w",zipfile.ZIP_DEFLATED,allowZip64=True) as zf:
        for root, _, filenames in os.walk(os.path.basename(d)):
            for name in filenames:
                name = os.path.join(root, name)
                name = os.path.normpath(name)
                zf.write(name, name)


    
if __name__ == '__main__':
    crear_carpetas()
    #Se ejecuta la consulta y se traen todos los registros
    data = Consulta()
    crearArchivos(data)
    
    proyecto_ = listado_proyectos()

    cantidad = len(proyecto_) 

    for indice in range(0,cantidad):
        consulta_por_proyecto(proyecto_,indice)

    eliminar_json()
    comprimir_zip()
    email.enviar_email_reporte()