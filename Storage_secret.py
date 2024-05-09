import sqlite3

class Storage_secret(object):
    """
    This is a singleton class that handles the storage of nonces in a SQLite database.
    """

    def __new__(cls):
        """
        Ensures that only one instance of the class can be created.
        """
        if not hasattr(cls, 'instance'):
            cls.instance = super(Storage_secret, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        """
        Initializes the SQLite database connection and creates the NonceTable if it doesn't exist.
        """
        self.__connection = sqlite3.connect('user_nonces.db')
        self.__cursor = self.__connection.cursor()
        self.__cursor.execute('''
            CREATE TABLE IF NOT EXISTS NonceTable (
                id BLOB PRIMARY KEY,
                nonce BLOB
            )
        ''')

    def add_nonce(self, id, nonce):
        """
        Adds a nonce to the NonceTable.

        Parameters:
            id (bytes): The ID of the user.
            nonce (bytes): The nonce to be stored.

        Raises:
            ValueError: If a nonce for the given ID already exists in the NonceTable.
        """
        if (self.get_nonce(id) != None):
            raise ValueError("Nonce already exists")
        self.__cursor.execute('''
            INSERT INTO NonceTable (id, nonce) VALUES (?, ?)
        ''', (id, nonce))
        self.__connection.commit()

    def get_nonce(self, id):
        """
        Retrieves a nonce from the NonceTable.

        Parameters:
            id (bytes): The ID of the user.

        Returns:
            bytes: The nonce associated with the given ID. If no nonce is found, None is returned.
        """
        self.__cursor.execute('''
            SELECT nonce FROM NonceTable WHERE id = ?
        ''', (id,))
        return self.__cursor.fetchone()[0]
    def close_connection(self):
        """Closes the connection to the SQLite database."""
        self.__cursor.close()
        self.__connection.close()
