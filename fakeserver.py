from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class FakeServer:
    def __init__(self):
        self._keypair = RSA.generate(2048)
        self._bad_ips = [2]
        fake_sym_key = get_random_bytes(16)
        self._sym_key = fake_sym_key

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

    def send_fake_sym_key(self, client_key, verification_secret, ip):
        """
        :param client_key: public key of the client
        :param verification_secret: verification secret sent by client
        :param ip: ip of client for firewall
        :return: the RSA encrypted message with the secret & sym key
        """
        fake_secret = get_random_bytes(16)
        full_message = self.RSA_encrypt(fake_secret + self._sym_key,
                                            client_key)
        return full_message

    def send_fake_vote_response(self):
        """
        :return: sym encrypted message with the random verification ID of the vote
        """
        fake_id = b'FAKE ID'
        encrypted_message, nonce = self.sym_encrypt(response)
        return encrypted_message, nonce

    def send_fake_ID_response(self):
        """
        :return: fake sym encrypted message with the random verification ID of the vote
        """
        fake_vote = "16karakters_fake"
        encrypted_message = self.sym_encrypt(fake_vote)
        return encrypted_message
