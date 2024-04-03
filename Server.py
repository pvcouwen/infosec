from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Server:
    def __init__(self):
        self._keypair = RSA.generate(2048)
        self._bad_ips = [2]
        self._sym_key = None

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
        :param nonce: the nonce used in AES
        :param message: message to decrypt
        :return: decrypted message
        """
        cipher = AES.new(self._sym_key, AES.MODE_EAX, nonce=nonce)
        decrypted = cipher.decrypt(message)
        return decrypted

    def sym_encrypt(self, message):
        """
        :param message: message to encrypt
        :return: encrypted message and the nonce used
        """
        cipher = AES.new(self._sym_key, AES.MODE_EAX)
        nonce = cipher.nonce
        encrypted = cipher.encrypt(message)
        return encrypted, nonce

    def share_public_key(self):
        return self._keypair.publickey()

    def firewall(self, ip):
        """
        :param ip: ip to check
        :return: True if ip is OK, else false
        """
        # Just a simple representation of where DDOS protection would fit
        # Ideally this would be much more complex using metadata of the sender and IP
        # But for this demonstration its just a simple IP checker
        if ip in self._bad_ips:
            return False
        return True

    def handle_sym_key_request(self, client_key, verification_secret, ip):
        """
        :param client_key: public key of the client
        :param verification_secret: verification secret sent by client
        :param ip: ip of client for firewall
        :return: the RSA encrypted message with the secret & sym key
        """
        if self.firewall(ip):
            decrypted_secret = self.RSA_decrypt(verification_secret)
            sym_key = get_random_bytes(16)
            self._sym_key = sym_key
            full_message = self.RSA_encrypt(decrypted_secret + sym_key,
                                            client_key)
            return full_message
        else:
            print("I don't trust this IP!")
            return None

    def handle_vote(self, message, nonce):
        """
        :param message: the message containing the vote of the client
        :return: the vote & verification that the storage will use
        """
        message = self.sym_decrypt(message, nonce)
        if len(message) != 32:
            print("message length is wrong!")
            return None
        vote = message[16:]
        verification = message[:16]
        # Dit moet naar storage voor checken
        return vote, verification

    def handle_storage_vote_response(self, response):
        """
        :param response: the storage servers response, either the vote ID or False
        :return: sym encrypted message with the random verification ID of the vote
        """
        if response is False:
            print("This voter is not eligible!")
            return None
        else:
            # Encrypt
            encrypted_message, nonce = self.sym_encrypt(response)
            return encrypted_message, nonce

    def handle_vote_request(self, message, nonce):
        """
        :param nonce: The nonce used in AES
        :param message: The ID of the vote encrypted with sym_encr
        :return:
        """
        decrypted_id = self.sym_decrypt(message, nonce)
        # This should be passed to storage
        # If ID is wrong the storage server should return false
        return decrypted_id

    def handle_storage_ID_respone(self, response):
        """
        :param response: the storage servers response, either the vote data or False
        :return: sym encrypted message with the random verification ID of the vote
        """
        if response is False:
            print("This vote ID is not recognized!")
            return None
        else:
            # Encrypt
            encrypted_message, nonce = self.sym_encrypt(response)
            return encrypted_message, nonce
