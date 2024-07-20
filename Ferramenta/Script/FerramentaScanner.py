import os
import ipaddress 
from os import system
import xml.etree.ElementTree as ET
import requests
import json
from time import sleep
from datetime import datetime
import subprocess

def varreduraRede():

    global IP_Rede

    try:

        # Executando a biblioteca subprocess para obter o IP do dispositivo
        IP_dispositivo = subprocess.run("ip -o addr show eth0 | awk '/scope global/ {print $4}'", shell=True, capture_output=True, text=True)

        # Tratamento do output pois sai o comando inteiro
        IP_dispositivo = IP_dispositivo.stdout

        # IP_dispositivo[0:14] serve para nao pegar o /n, pois o resultado é EX: 192.168.0.0/24/n --> 192.168.0.0/24
        IP_CIDR = ipaddress.IPv4Network(IP_dispositivo[0:14], strict=False)

        # Usando a biblioteca para obter o endereço da rede
        IP_Rede = IP_CIDR.network_address

        print(f'Redes: {str(IP_Rede) + IP_dispositivo[11:14]}')

        system(f'nmap -sV {str(IP_Rede) + IP_dispositivo[11:14]} -oX {IP_Rede}.xml')

    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")

    # Teste usuario
    # while True:
    #     endereco_ip = str(input("Digite um endereco IP valido: "))
    #     try:
    #         endereco_valido = enderecoValido(endereco_ip)
    #         print(endereco_valido)
    #         break
    #     except ValueError:
    #         print("Endereco IP não existe!")

def tratamentoXML(IP_Rede):

    global dictCPE
    dictCPE = {}

    # Carregar o arquivo XML gerado pelo Nmap
    tree = ET.parse(f'{IP_Rede}.xml')
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

    # Para pesquisar o CVE no NVD precisa formatar o CPE
    # Exemplo:
    #       cpe:/a:apache:http_server:2.2.8 --> cpe:2.3:a:apache:http_server:2.2.8
    # cpe:2.3: Significa a versão do NVD
    # a: aplicação e o: sistema operacional

    global lista_nome_CPE
    lista_nome_CPE = []
    lista_nao_encontrado = []

    caminho_diretorio = f'./JSON_{datetime.now()}'.replace(":", "_")

    os.makedirs(caminho_diretorio)

    os.chdir(caminho_diretorio)

    for ip, cpe in dictCPE.items():
        for cpe_old in cpe:
            cpe_new = cpe_old.replace("/", "2.3:")
            cpe_new_texto = cpe_new.replace(":", "_")

            try:
                nvd = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_new}")
                nvd_json = nvd.json()

                with open(f'{cpe_new_texto}.json', 'w') as arquivo:
                    arquivo.write(json.dumps(nvd_json))

                lista_nome_CPE.append(cpe_new_texto)

            except requests.RequestException as e:
                print(f"Falha na solicitação para {cpe_new}: {e}")
                lista_nao_encontrado.append(cpe_new)
                print(f"- - - - - {lista_nao_encontrado} - - - - -")

            except Exception as e:
                print(f"Erro inesperado ao processar {cpe_new}: {e}")

            sleep(5)

    print(lista_nao_encontrado)
    print("Lista criada e finalizado!")


def manipulacaoJson(lista_nome_CPE):

    data = {}
    for numero_CPE in range(len(lista_nome_CPE)):

        with open(f'{lista_nome_CPE[numero_CPE]}.json','r') as arquivo:
            texto = arquivo.read()
            dados = json.loads(texto)

        vulnerabilidade = dados['vulnerabilities']

        for vuln in vulnerabilidade:
            cve_id = vuln['cve']['id']
            descricao_en = vuln['cve']['descriptions'][0]['value']

            print(f'-------------{lista_nome_CPE[numero_CPE]}----------------')
            print(f'CVE ID: {cve_id} - Descrição: {descricao_en}')
            print('-----------------------------')
            data.update({cve_id:descricao_en})

    print('+++++++++++++++++++++++++++++')
    print(data)

    with open(f'data.json', 'w') as arquivo:
        arquivo.write(json.dumps(data))



varreduraRede()
tratamentoXML(str(IP_Rede))
apiNVD(dictCPE)
manipulacaoJson(lista_nome_CPE)

