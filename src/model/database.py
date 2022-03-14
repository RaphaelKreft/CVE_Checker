"""
database.py: contains Database class that is  a class that implements the ModelInterface. Thus, the Program can operate
on top of it.
"""

import sqlite3
import logging
from .model import ModelError, ModelInterface


class Database(ModelInterface):

    def __init__(self, path):
        super().__init__()
        self.connection = None
        self.cursor = None
        self.connect_to_db(path)

    def connect_to_db(self, path):
        """
        Create a database or open it, if it does not exist
        """
        try:
            self.connection = sqlite3.connect(path)
            self.cursor = self.connection.cursor()
        except Exception as ex:
            raise ModelError(str(ex))

    def init_database(self):
        """
        Creates Tables and Database with the application schema
        """
        sql = """CREATE TABLE IF NOT EXISTS Software (
                    ID INT PRIMARY KEY,
                    Name TEXT,
                    EULA_URL TEXT,
                    EULA_HASH TEXT,
                    Last_Check DATE
        );"""
        self._execute_sql(sql)

    def has_alive_connection(self):
        """
        Returns true if instance has connection Instance at serlf.connection and this connection works.
        """
        try:
            self.connection.cursor()
            return True
        except Exception:
            return False
        
    def get_software_data_by_id(self, ID):
        sql = f"SELECT * FROM Software WHERE ID = {ID}"
        self._execute_sql(sql)
        row = self.cursor.fetchone()
        if row:
            return row
        else:
            raise ModelError(f"Software for ID {ID} not found!")

    def update_software_data_by_id(self, ID, values: dict):
        for key, value in values.items():
            sql = f"UPDATE Software Set {key} = {value} WHERE ID = {ID}"
            self._execute_sql(sql)

    def get_software_IDs(self) -> list:
        sql = "SELECT ID from Software"
        self._execute_sql(sql)
        rows = self.cursor.fetchall()
        if rows:
            return rows
        else:
            raise ModelError(f"No Software ID's found!")

    def _execute_sql(self, sql: str):
        try:
            self.cursor.execute(sql)
        except Exception as err:
            logging.error(err)