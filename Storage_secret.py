import sqlite3

class Storage_secret:
    """
    This is a singleton class that handles the storage of nonces in a SQLite database.
    """

    __instance = None  # Private class variable for storing the singleton instance.

    def __new__(cls):
        """
        Ensures that only one instance of the class can be created.
        """
        if not hasattr(cls, 'instance'):  # If an instance does not already exist...
            cls.__instance = super(Storage_secret, cls).__new__(cls)  # ...create a new instance.
        return cls.__instance  # Return the singleton instance.

    def __init__(self):
        """
        Initializes the SQLite database connection and creates the NonceTable if it doesn't exist.
        """
        self.__connection = sqlite3.connect('user_nonces.db')  # Establish a connection to the SQLite database.
        self.__cursor = self.__connection.cursor()  # Create a cursor object for executing SQL commands.
        # Execute a SQL command to create the NonceTable if it does not already exist.
        self.__cursor.execute('''
            CREATE TABLE IF NOT EXISTS NonceTable (
                id TEXT PRIMARY KEY,
                nonce TEXT
            )
        ''')

    def __del__(self):
        """
        Destructor method to close the database connection when the instance is deleted.
        """
        self.close_connection()

    def add_nonce(self, id, nonce):
        """
        Adds a nonce to the NonceTable.

        Parameters:
            id (bytes): The ID of the user.
            nonce (bytes): The nonce to be stored.

        Raises:
            ValueError: If a nonce for the given ID already exists in the NonceTable.
        """
        if (self.get_nonce(id) != None):  # If a nonce for the given ID already exists...
            raise ValueError("Nonce already exists")  # ...raise a ValueError.
        # Execute a SQL command to insert the given ID and nonce into the NonceTable.
        self.__cursor.execute('''
            INSERT INTO NonceTable (id, nonce) VALUES (?, ?)
        ''', (str(id), str(nonce)))
        self.__connection.commit()  # Commit the changes to the database.

    def get_nonce(self, id):
        """
        Retrieves a nonce from the NonceTable.

        Parameters:
            id (bytes): The ID of the user.

        Returns:
            bytes: The nonce associated with the given ID. If no nonce is found, None is returned.

        Raises:
            ValueError: If the given ID does not exist in the NonceTable.
        """
        # Execute a SQL command to select the nonce associated with the given ID.
        self.__cursor.execute('''
            SELECT nonce FROM NonceTable WHERE id = ?
        ''', (str(id),))
        result = self.__cursor.fetchone()  # Fetch the result of the SQL command.
        if result:  # If a result was found...
            result = result[0]  # ...extract the nonce from the result.
            return result  # Return the nonce.
        raise ValueError("Invalid ID")  # If no result was found, raise a ValueError.

    def close_connection(self):
        """
        Closes the connection to the SQLite database.
        """
        self.__cursor.close()  # Close the cursor.
        self.__connection.close()  # Close the connection.