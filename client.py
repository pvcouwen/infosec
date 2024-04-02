from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Client:
    def __init___(self,ip):
        self._ip = ip

        self._keypair = RSA.generate(2048)
  
        self._verification_secret = None
        self._server_public_key = None
        self._sym_key = None
        self._id_number = None
        self._identification = get_random_bytes(16)

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

    def sym_decrypt(self, message):
        """
        :param message: message to decrypt
        :return: decrypted message
        """
        cipher = AES.new(self._sym_key, AES.MODE_CTR)
        decrypted = cipher.decrypt(message)
        return decrypted

    def sym_encrypt(self, message):
        """
        :param message: message to encrypt
        :return: encrypted message
        """
        cipher = AES.new(self._sym_key, AES.MODE_CTR)
        encrypted = cipher.encrypt(message)
        return encrypted

    def generate_public_key_request():
        return "Request public key"

    def generate_sym_key_request(server_public_key):
        self._server_public_key = server_public_key
        
        verification_secret = get_random_bytes(16)
        self._verification_secret = verification_secret
        encrypted_secret = self.RSA_encrypt(verification_secret, self._server_public_key)
        
        return self._public_key, encrypted_secret, self._ip

    def recieve_sym_key(encrypted_message):
        decrypted_message = self.RSA_decrypt(encrypted_message)

        decrypted_secret = decrypted_message[:16]
        sym_key = decrypted_message[16:]
        
        if decrypted_secret == verification_secret:
            self._sym_key = sym_key
        else:
            raise Exception("Verification secret incorrect!")

    def generate_vote(candidate):
        if len(candidate)!=16:
            raise Exception("Wrong candidate length!")
        
        vote_message = candidate + self.identification
        encrypted_message = self.sym_encrypt(vote_message)
        
        return encrypted_message

    def store_vote_id(encrypted_id):
        decrypted_id = self.sym_decrypt(encrypted_id)
        self._id_number = decrypted_id

    def send_voter_id():
        encrypted_id = self.sym_encrypt(self._id_number)
        
        return encrypted_id

    def recieve_vote(encrypted_vote):
        decrypted_vote = self.sym_decrypt(encrypted_vote)
        print(decrypted_vote)

    
        

    
    

    
