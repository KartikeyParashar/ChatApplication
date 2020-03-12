import redis
import logging
logging.basicConfig(level=logging.DEBUG)


class Redis:
    def __init__(self, host='localhost', port=6379, db=0):
        self.host = host
        self.port = port
        self.db = db
        self.connection = self.connect()

    def connect(self):
        connection = redis.StrictRedis(host=self.host, port=self.port, db=self.db)
        if connection:
            logging.info('Redis Cache Connection Established')
        return connection

    def set(self, key, value):
        self.connection.set(key, value)
        logging.info(f'{key} : {value}')

    def get(self, key):
        return self.connection.get(key)

    def exist(self, key):
        return self.connection.exists(key)

    def delete(self, key):
        logging.info(f'Key to Delete : {key}')
        self.connection.delete(key)


