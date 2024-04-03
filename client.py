from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Client:
    def __init__(self, ip):
        self._ip = ip

        self._keypair = RSA.generate(2048)

        self._verification_secret = None
        self._server_public_key = None
        self._sym_key = None
        self._id_number = None
        self._identification = get_random_bytes(16)
        self._vote = None

    def RSA_decrypt(self, message):
        """
        :param message: message to decrypt
        :return: decrypted message
        """
        decryptor = PKCS1_OAEP.new(self._keypair)
        decrypted = decryptor.decrypt(message)
        return decrypted

    def RSA_encrypt(self, message, key):
        """

        :param message: message to encrypt
        :param key: public key to use
        :return: encrypted message
        """
        encryptor = PKCS1_OAEP.new(key)
        encrypted = encryptor.encrypt(message)
        return encrypted

    def sym_decrypt(self, message, nonce):
        """
        :param nonce: The nonce used in AES
        :param message: message to decrypt
        :return: decrypted message
        """
        cipher = AES.new(self._sym_key, AES.MODE_EAX, nonce=nonce)
        decrypted = cipher.decrypt(message)
        return decrypted

    def sym_encrypt(self, message):
        """
        :param message: message to encrypt
        :return: encrypted message
        """
        cipher = AES.new(self._sym_key, AES.MODE_EAX)
        nonce = cipher.nonce
        encrypted = cipher.encrypt(message)
        return encrypted, nonce

    def generate_public_key_request(self):
        return "Request public key"

    def generate_sym_key_request(self, server_public_key):
        self._server_public_key = server_public_key

        verification_secret = get_random_bytes(16)
        self._verification_secret = verification_secret
        encrypted_secret = self.RSA_encrypt(verification_secret, self._server_public_key)

        return self._keypair.public_key(), encrypted_secret, self._ip

    def recieve_sym_key(self, encrypted_message):
        decrypted_message = self.RSA_decrypt(encrypted_message)
        decrypted_secret = decrypted_message[:16]
        sym_key = decrypted_message[16:]
        if decrypted_secret == self._verification_secret:
            self._sym_key = sym_key
        else:
            raise Exception("Verification secret incorrect!")

    def generate_vote(self, candidate):
        if len(candidate) != 16:
            raise Exception("Wrong candidate length!")
        self._vote = candidate

        vote_message = candidate + self._identification
        encrypted_message, nonce = self.sym_encrypt(vote_message)
        return encrypted_message, nonce

    def store_vote_id(self, encrypted_id, nonce):
        decrypted_id = self.sym_decrypt(encrypted_id, nonce)
        if decrypted_id[:2] != b'ID' or not all(chr(char).isdigit() for char in decrypted_id[2:]):
            print(decrypted_id)
            raise Exception("Recieved invalid voter ID!")
        self._id_number = decrypted_id
        

    def send_voter_id(self):
        encrypted_id, nonce = self.sym_encrypt(self._id_number)
        return encrypted_id, nonce

    def recieve_vote(self,encrypted_vote, nonce):
        decrypted_vote = self.sym_decrypt(encrypted_vote, nonce)
        print(decrypted_vote)
        if decrypted_vote != self._vote:
            raise Exception("Original candidate doesn't match!")
