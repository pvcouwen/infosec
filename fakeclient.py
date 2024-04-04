from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class fakeClient:
    def __init__(self, ip):
        self._ip = ip

        self._keypair = RSA.generate(2048)
        self._fake_sym_key = get_random_bytes(16)
        self._verification_secret = None
        self._server_public_key = None
        self._id_number = "ID21347"
        self._identification = get_random_bytes(16)

    def sym_encrypt(self, message):
        """
        :param message: message to encrypt
        :return: encrypted message
        """
        cipher = AES.new(self._fake_sym_key, AES.MODE_EAX)
        nonce = cipher.nonce
        encrypted = cipher.encrypt(message)
        return encrypted, nonce

    def intercept_sym_key_req_replace_pub_key(self, verification_secret,ip):
        """
        intercept the verification secret and ip from true client and resend but with on public key
        :param verification_secret:
        :param ip:
        :return: fake public key, secret & ip of true client
        """
        return self._keypair.public_key(), verification_secret, ip


    def intercept_send_vote_replace_vote_and_verify(self):
        """
        intercept a client vote and replace with own vote
        :return: encrypted_message with vote and AES nonce
        """
        vote_message = b'myvoteisveryfake' + self._identification
        encrypted_message, nonce = self.sym_encrypt(vote_message)
        return encrypted_message, nonce

    def intercept_vote_ID_replace_ID(self):
        """
        intercept a vote ID request, replace with own ID
        :return: encrypted_message with ID and AES nonce
        """
        encrypted_id, nonce = self.sym_encrypt(self._id_number)
        return encrypted_id, nonce

