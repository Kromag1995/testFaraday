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


def xml_to_json(input: str) -> dict:
    tree = etree.parse(input)
    root = tree.getroot()
    hosts = []
    services = 1
    vulns = []
    web_sites = []
    web_vulns_count = 0
    for i in root.findall('hosts'):
        hosts += i.findall('host')
    for host in hosts:
        for service in host.find('services').findall("service"):
            services += 1

        for vuln in host.find('vulns').findall("vuln"):
            vulns.append(vuln_to_dic(vuln))
            if not (vuln.find('web-site-id') is None):
                web_vulns_count += 1
                if not (vuln.find('web-site-id').text in web_sites):
                    web_sites.append(vuln)
    js = {
        "hosts_count": len(hosts),
        "services_count": services,
        "website_count": len(web_sites),
        "web_vulns_count": web_vulns_count,
        "vulns_count":len(vulns)-web_vulns_count,
        "vulns": vulns
    }
    print("hosts_count", len(hosts),
        "services_count", services,
        "website_count", len(web_sites),
        "web_vulns_count", web_vulns_count,
        "vulns_count",len(vulns)-web_vulns_count)

    return js

if __name__ == "__main__":
    json_format()