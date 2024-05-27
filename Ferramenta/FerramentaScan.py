from ipaddress import IPv4Network as enderecoValido
from os import system
import xml.etree.ElementTree as ET
import requests
import json

def varreduraRede():

# Transformar a variavel endereco_ip para poder usar na funcao tratamentoXML

    while True:
        endereco_ip = str(input("Digite um endereco IP valido: "))
        try:
            endereco_valido = enderecoValido(endereco_ip)
            print(endereco_valido)
            break
        except ValueError:
            print("Endereco IP não existe!")

    sistema = system(f'nmap -sV {endereco_ip} -oX {endereco_ip}.xml')


def tratamentoXML():

    global dictCPE
    dictCPE = {}

    # Carregar o arquivo XML gerado pelo Nmap
    tree = ET.parse('saida_teste_1.xml')
    root = tree.getroot()

    # Sobre os hosts no XML
    for host in root.findall('host'):
        endereco_host = host.find('address').attrib['addr'] # Obter o endereço IP do host

        dispositivo = 'N/A'
        # Sobre os endereços para encontrar o vendor
        for address in host.findall('address'):
            if 'vendor' in address.attrib:
                dispositivo = address.attrib['vendor']
                break  # Parar de procurar após encontrar o primeiro vendor

        print(f"|> Endereço IP: {endereco_host} <|")
        print(f"Dispositivo: {dispositivo}")
        print('▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽')

        # Iterar sobre os serviços oferecidos pelo host
        for port in host.findall('ports/port'):
            portid = port.attrib['portid'] # Vai retornar aos atributos como protocolo e port ID
            protocol = port.attrib['protocol']
            service = port.find('service') # Encontra o elemento service
            statePort = port.find('state') # Encontra o elemento state

            # Caso o elemento service seja encontrado dentro do elemento port
            if service is not None:
                name = service.attrib.get('name', 'N/A')
                version = service.attrib.get('version', 'N/A')
                extrainfo = service.attrib.get('extrainfo', 'N/A')
                product = service.attrib.get('product', 'N/A')
                ostype = service.attrib.get('ostype', 'N/A')
                cpe = service.find('cpe')

                # Caso o elemento cpe seja encontrado dentro do elemento service
                if cpe is not None:
                    cpe = cpe.text # Retorna ao conteudo da variavel em formato texto
                    if endereco_host not in dictCPE: # Caso o endereco não estiver no dicionario
                        dictCPE[endereco_host] = []
                    dictCPE[endereco_host].append(cpe)


            # Caso o elemento state seja encontrado dentro do elemento port
            if statePort is not None:
                state = statePort.attrib.get('state', 'N/A')


            print(f"Porta: {portid} | Status: {state} |  Protocolo: {protocol} | Serviço: {name} | Produto: {product} | Versão: {version} | Sistema Operacional: {ostype} | CPE: {cpe} | Informação Extra: {extrainfo} |")
        print('△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△')

def apiNVD(dictCPE):

    print(dictCPE)

    # Para pesquisar o CVE no NVD precisa formatar o CPE
    # Exemplo:
    #       cpe:/a:apache:http_server:2.2.8 --> cpe:2.3:a:apache:http_server:2.2.8
    # cpe:2.3: Significa a versão do NVD
    # a: aplicação e o: sistema operacional


    for ip, cpe in dictCPE.items():
        for cpe_old in cpe:
            cpe_new = cpe_old.replace("/", "2.3:")
            nvd = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_new}")
            nvd_json = nvd.json()
            with open(f'{cpe_new}.json', 'w') as arquivo:
                arquivo.write(json.dumps(nvd_json))

            print(f"IP: {ip}, CPE: {cpe_new}")


    # print(f"{cpe_old} --> {cpe_new}")


tratamentoXML()
apiNVD(dictCPE)

