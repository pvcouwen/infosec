import sqlite3
from uuid import uuid4
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from secrets import token_urlsafe


class Storage:
    """
    A class used to represent a secure storage system.

    ...

    Attributes
    ----------
    __key : bytes
        a private attribute that stores the encryption key
    __cipher : AES object
        a private attribute that stores the AES cipher object
    __connection : sqlite3.Connection object
        a private attribute that stores the connection to the SQLite database
    __cursor : sqlite3.Cursor object
        a private attribute that stores the cursor for the SQLite database
    __nonce : bytes
        a private attribute that stores the nonce for the AES cipher

    Methods
    -------
    create_tables():
        Creates the necessary tables in the SQLite database.
    create_voter(hashed_val):
        Adds a new voter to the UserData table.
    __check_voter(hashed_val):
        Checks if a voter already exists in the UserData table.
    read_voters():
        Fetches and prints all voters from the UserData table (for testing purposes only).
    read_votes():
        Fetches and prints all votes from the VoteTable (for testing purposes only).
    vote(id, vote, token):
        Adds a vote to the VoteTable if the vote token is valid.
    __add_vote_token(id, token):
        Adds a vote token to the VoteTokenTable.
    remove_vote_token(id, token):
        Removes a vote token from the VoteTokenTable if it exists.
    close_connection():
        Closes the connection to the SQLite database.
    """

    def __init__(self):
        """The constructor for the Storage class."""
        self.__key = PBKDF2('ThisShouldbeAVerySecurePASSWORD123321', b'WfyiXVeh}0)w6X=A(fPV,Esxba>!-@', dkLen=32) # Only for demonstration purposes
        self.__cipher = AES.new(self.__key, AES.MODE_EAX)
        self.__connection = sqlite3.connect('secure_data.db')
        self.__cursor = self.__connection.cursor()
        self.__nonce = self.__cipher.nonce
        self.create_tables()

    def create_tables(self):
        """Creates the necessary tables in the SQLite database."""
        self.__cursor.execute('''
            CREATE TABLE IF NOT EXISTS UserData (
                id BLOB PRIMARY KEY,
                hashed_val TEXT
            )
        ''')
        self.__cursor.execute('''
            CREATE TABLE IF NOT EXISTS VoteTable (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vote TEXT
            )
        ''')
        self.__cursor.execute('''
            CREATE TABLE IF NOT EXISTS VoteTokenTable (
                id BLOB PRIMARY KEY,
                token TEXT
            )
        ''')
        self.__connection.commit()

    def create_voter(self, hashed_val):
        """
        Adds a new voter to the UserData table.

        Parameters:
            hashed_val (str): The hashed value of the voter's information.
        """
        if self.__check_voter(hashed_val):
            raise ValueError('Voter already exists')
        else:
            # encrypted_data = self.__cipher.encrypt(str(hashed_val).encode()) # Not sure if this is necessary
            id = uuid4().bytes
            self.__cursor.execute('INSERT INTO UserData VALUES (?, ?)', (id, hashed_val))
            self.__connection.commit()
            token = str(token_urlsafe(32))
            self.__add_vote_token(id, token)
            return id, token

    def __check_voter(self, hashed_val):
        """
        Checks if a voter already exists in the UserData table.

        Parameters:
            hashed_val (str): The hashed value of the voter's information.

        Returns:
            bool: True if the voter exists, False otherwise.
        """
        self.__cursor.execute('SELECT * FROM UserData WHERE hashed_val = ?', (hashed_val,))
        result = self.__cursor.fetchone()
        if result:
            return True
        return False

    '''# Dont use this function
    def read_voters(self):
        """Fetches and prints all voters from the UserData table (for testing purposes only)."""
        self.__cursor.execute('SELECT * FROM UserData')
        result = self.__cursor.fetchone()
        cipher = AES.new(self.__key, AES.MODE_EAX, nonce=self.__nonce)
        if result:
            hashed_val = cipher.decrypt(result[1])
            print(result)
            print(hashed_val)
    
    # Dont use this function
    def read_votes(self):
        """Fetches and prints all votes from the VoteTable (for testing purposes only)."""
        self.__cursor.execute('SELECT * FROM VoteTable')
        result = self.__cursor.fetchone()
        cipher = AES.new(self.__key, AES.MODE_EAX, nonce=self.__nonce)
        if result:
            vote = cipher.decrypt(result[1])
            print(result)
            print(vote)
    '''
    def vote(self, id, vote, token):
        """
        Adds a vote to the VoteTable if the vote token is valid.

        Parameters:
            id (bytes): The ID of the voter.
            vote (str): The vote.
            token (str): The vote token.

        Returns:
            int: The ID of the last inserted row in the VoteTable.
            bytes: The nonce used for encryption.
        """
        valid_vote = self.remove_vote_token(id, token)
        if valid_vote:
            encrypted_data = self.__cipher.encrypt(str(vote).encode())
            self.__cursor.execute('INSERT INTO VoteTable (vote) VALUES (?)', (encrypted_data,))
            return self.__cursor.lastrowid, self.__nonce
        else:
            raise ValueError('Invalid vote token')

    def __add_vote_token(self, id, token):
        """
        Adds a vote token to the VoteTokenTable.

        Parameters:
            id (bytes): The ID of the voter.
            token (str): The vote token.
        """
        self.__cursor.execute('INSERT INTO VoteTokenTable VALUES (?, ?)', (id, token))
        self.__connection.commit()

    def remove_vote_token(self, id, token):
        """
        Removes a vote token from the VoteTokenTable if it exists.

        Parameters:
            id (bytes): The ID of the voter.
            token (str): The vote token.

        Returns:
            bool: True if the vote token was removed, False otherwise.
        """
        self.__cursor.execute('SELECT * FROM VoteTokenTable WHERE id = ? AND token = ?', (id, token))
        result = self.__cursor.fetchone()
        if result:
            self.__cursor.execute('DELETE FROM VoteTokenTable WHERE id = ? AND token = ?', (id, token))
            self.__connection.commit()
            return True
        return False

    def close_connection(self):
        """Closes the connection to the SQLite database."""
        self.__connection.commit()
        self.__cursor.close()
        self.__connection.close()


# Example usage
# storage = Storage()
# id, token = storage.create_voter('hashed_value') # We can also just get the token inside the vote function, id must be returned
# storage.vote(id, 'Partij 1 codewoord', token)
# storage.close_connection()