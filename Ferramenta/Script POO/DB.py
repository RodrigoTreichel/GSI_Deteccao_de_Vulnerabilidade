from pymongo import MongoClient

class MongoDataBase:

    def __init__(self, data:dict) -> None:
        self.data = data

    def inserirMongo(self):
        # Conexão com o Banco
        db_client = MongoClient('mongodb://root:example@localhost', 27017)

        # Criação do Banco
        dataBase = db_client.MEU_BANCO

        # Criação da collection
        storage = dataBase.storage

        # Inserir os dados
        status = storage.insert_one(self.data)

        print(status)

    def consultarMongo(self):
        pass

    def deletarMongo(self):
        pass

