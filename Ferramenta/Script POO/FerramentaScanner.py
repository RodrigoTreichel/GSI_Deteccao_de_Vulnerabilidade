import os
import xml.etree.ElementTree as ET
import requests
import json
from time import sleep
from datetime import datetime
from ipaddress import IPv4Network as enderecoValido

#
# class VarreduraRede:
#     def __init__(self):
#         self.endereco_ip = ""
#
#     def endereco_valido(self, endereco_ip):
#         try:
#             enderecoValido(endereco_ip)
#             return True
#         except ValueError:
#             return False
#
#     def solicitar_endereco_ip(self):
#         while True:
#             self.endereco_ip = input("Digite um endereço IP válido: ")
#             if self.endereco_valido(self.endereco_ip):
#                 print(f"Endereço IP válido: {self.endereco_ip}")
#                 break
#             else:
#                 print("Endereço IP inválido!")
#
#     def varrer_rede(self):
#         comando = f'nmap -sV {self.endereco_ip} -oX {self.endereco_ip}.xml'
#         print(f"Executando: {comando}")
#         sistema = os.system(comando)
#         if sistema != 0:
#             print("Erro ao executar o Nmap")
#
class ProcessoXML:
    def __init__(self, file_name: str) -> None:
        self.file_name = file_name
        self.dictCPE = {}

    def tratamentoXML(self) -> list:
        tree = ET.parse(self.file_name)
        root = tree.getroot()

        for host in root.findall('host'):
            endereco_host = host.find('address').attrib['addr']
            dispositivo = 'N/A'
            for address in host.findall('address'):
                if 'vendor' in address.attrib:
                    dispositivo = address.attrib['vendor']
                    break

            print(f"|> Endereço IP: {endereco_host} <|")
            print(f"Dispositivo: {dispositivo}")
            print('▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽')

            for port in host.findall('ports/port'):
                portid = port.attrib['portid']
                protocol = port.attrib['protocol']
                service = port.find('service')
                statePort = port.find('state')

                name = service.attrib.get('name', 'N/A')
                version = service.attrib.get('version', 'N/A')
                extrainfo = service.attrib.get('extrainfo', 'N/A')
                product = service.attrib.get('product', 'N/A')
                ostype = service.attrib.get('ostype', 'N/A')
                cpe = service.find('cpe').text if service is not None and service.find('cpe') is not None else 'N/A'
                state = statePort.attrib.get('state', 'N/A') if statePort is not None else 'N/A'

                if cpe != 'N/A':
                    if endereco_host not in self.dictCPE:
                        self.dictCPE[endereco_host] = []
                    self.dictCPE[endereco_host].append(cpe)

                print(f"Porta: {portid} | Status: {state} |  Protocolo: {protocol} | Serviço: {name} | Produto: {product} | Versão: {version} | Sistema Operacional: {ostype} | CPE: {cpe} | Informação Extra: {extrainfo} |")
            print('△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△')

        return self.dictCPE


class APINVD:
    def __init__(self) -> None:
        self.lista_nome_CPE = []
        self.lista_nao_encontrado = []

    def consultarAPI(self, dictCPE:list) -> list:
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

                    self.lista_nome_CPE.append(cpe_new_texto)

                except requests.RequestException as e:
                    print(f"Falha na solicitação para {cpe_new}: {e}")
                    self.lista_nao_encontrado.append(cpe_new)
                    print(f"- - - - - {self.lista_nao_encontrado} - - - - -")

                except Exception as e:
                    print(f"Erro inesperado ao processar {cpe_new}: {e}")

                sleep(7)

        print(self.lista_nao_encontrado)
        print("Lista criada e finalizado!")
        return self.lista_nome_CPE


class ProcessoJSON:
    def __init__(self, lista_nome_CPE: list) -> None:
        self.lista_nome_CPE = lista_nome_CPE
        self.data_com_CPE = {}

    def manipulacaoJson(self) -> dict:

        cont = 0
        for numero_CPE in range(len(self.lista_nome_CPE)):
            with open(f'{self.lista_nome_CPE[numero_CPE]}.json', 'r') as arquivo:
                texto = arquivo.read()
                dados = json.loads(texto)

            vulnerabilidades = dados.get('vulnerabilities', [])
            for vuln in vulnerabilidades:
                cve_id = vuln['cve']['id']
                descricao_en = vuln['cve']['descriptions'][0]['value']

                print(f'-------------{self.lista_nome_CPE[numero_CPE]}----------------')
                print(f'CVE ID: {cve_id} - Descrição: {descricao_en}')
                print('-----------------------------')

                # Nesta parte o faço a concatenação do contador com o CPE, pois existe um problema que se fosse colocar
                # no dicionario somente o CVEs, ele não pegaria todos, e sim só o ultimo do arquivo.
                # Tambem fiz um cast, pois só pode concatenar tipos de variaveis iguais.
                cont += 1
                #CPE_com_numero = f'CPE: {str(self.lista_nome_CPE[numero_CPE])} ' + f'Numero: {str(cont)}'

                self.data_com_CPE.update({ f'ID: {str(cont)}': [{self.lista_nome_CPE[numero_CPE]:{cve_id: descricao_en}}]})

        print('+++++++++++++++++++++++++++++')
        print(self.data_com_CPE)

        with open('data_com_CPE.json', 'w') as arquivo:
            arquivo.write(json.dumps(self.data_com_CPE))

        #return self.data_com_CPE


