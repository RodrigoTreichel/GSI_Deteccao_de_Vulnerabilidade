from FerramentaScanner import ProcessoXML, APINVD, ProcessoJSON
from DB import MongoDataBase

if __name__ == "__main__":
    # Etapa 1: Varredura de Rede
    # scanner = VarreduraRede()
    # scanner.solicitar_endereco_ip()
    # scanner.varrer_rede()

    # Etapa 2: Processamento do XML gerado pelo Nmap
    xml = ProcessoXML(f'saida_teste_1.xml')
    dicionario_CPE = xml.tratamentoXM()

    # Etapa 3: Consulta à API NVD
    api_nvd = APINVD()
    lista_nome_CPE = api_nvd.consultarAPI(dicionario_CPE)

    # Etapa 4: Processamento dos arquivos JSON
    json = ProcessoJSON(lista_nome_CPE)
    data = json.manipulacaoJson()

    # Etapa 5: Inserir no Banco de Dados
    banco = MongoDataBase(data)
    banco.inserirMongo()
