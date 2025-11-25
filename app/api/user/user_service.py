from pymongo import MongoClient
from typing import List, Dict

class UserService:
    def __init__(self, mongo_client: MongoClient, db_name: str):
        self.db = mongo_client[db_name]
        self.users = self.db["user"]

    def get_usernames(self) -> List[Dict]:
        """
        Devolve todos os usernames da coleção user.
        Apenas: { "username": "..." }
        """
        return list(self.users.find({}, {"_id": 0, "username": 1}))
