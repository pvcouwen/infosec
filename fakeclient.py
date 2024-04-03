from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class fakeClient:
    def __init__(self, ip):
        self._ip = ip

        self._keypair = RSA.generate(2048)

        self._verification_secret = None
        self._server_public_key = None
        self._sym_key = None
        self._id_number = None
        self._identification = get_random_bytes(16)

    def intercept_sym_key_req_replace_pub_key(self, verification_secret,ip):
        return self._keypair.public_key(), verification_secret, ip
