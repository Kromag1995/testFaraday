Hacer un script en python para convertir un archivo XML en un archivo JSON.

El script deberia tener dos parameter --input --output
El archivo de salida tiene que tener el siguiente formato:

{
“hosts_count”: cantidad_de_hosts,
“services_count”: cantidad_de_servicios,
“website_count”: cantidad_de_websites,
“web_vulns_count”: cantidad_de_vulns_web,
“vulns_count”: cantidad_de_vulns_not_web,
“vulns”: lista_con_vulns
}


Donde:
Cantidad_de_hosts: total de hosts contenidas en el archivo XML
Contidad_de_servicios: total de servicios contenidas en el XML
Cantidad_de_websites: cantidad de websites contenidas en el XML
Cantidad_de_vulns_web: cantidad de vulns web contenidas en el XML
Cantidad_de_vulns_not_web: cantidad de vulns no web contenidas en el XML (La diferencia es que no tienen servicio asignado)
Lista_con_vulns: es una lista de las vulnerabilidades que hay en el archivo xml

Para la lista de vuln, usar un formato adecuado (diccionario) sin perder información.


Nota: Las cantidades deberían evitar contar elementos duplicados