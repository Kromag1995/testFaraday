from xml.etree import ElementTree as etree
import json
import click

@click.command()
@click.option("--input", required=True, prompt=True,type=click.Path(exists=True))
@click.option("--output", required=True, prompt=True,)
def json_format(input: str, output: str):
    file = open(output,"w")
    json_string = json.dump(xml_to_json(input),file, indent=4)
    file.close()

def vuln_to_dic(vuln: etree.Element) ->dict:
    vuln_dict = {}
    for atrr in vuln:
        vuln_dict[atrr.tag] = atrr.text
    return vuln_dict

def vuln_count(vulns: list) -> tuple:
    vulns_ids = []
    web_vulns = 0
    no_web_vulns = 0
    for vuln in vulns:
        if not vuln["id"] in vulns_ids:
            if "web-site-id" in vuln:
                web_vulns += 1
            else:
                no_web_vulns += 1
    return web_vulns, no_web_vulns


def xml_to_json(input: str) -> dict:
    tree = etree.parse(input)
    root = tree.getroot()
    hosts = []
    services = [root.find('services')[0].find("id").text]
    vulns = []
    web_sites = []
    for i in root.findall('hosts'):
        hosts += i.findall('host')
    for host in hosts:
        for service in host.find('services').findall("service"):
            if not (service.find("id").text in services):
                services.append(service.find("id").text)
    
        for vuln in host.find('vulns').findall("vuln"):
            vulns.append(vuln_to_dic(vuln))
            if not (vuln.find('web-site-id') is None) and not (vuln.find('web-site-id').text in web_sites):
                web_sites.append(vuln.find('web-site-id').text)
    w_vulns_count,vulns_count = vuln_count(vulns)
    
    js = {
        "hosts_count": len(hosts),
        "services_count": len(services),
        "website_count": len(web_sites),
        "web_vulns_count": w_vulns_count,
        "vulns_count":vulns_count,
        "vulns":vulns
    }

    return js

if __name__ == "__main__":
    json_format()