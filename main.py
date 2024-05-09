from Server import Server
from Storage import Storage
from fakeserver import FakeServer
from client import Client
from fakeclient import fakeClient
from Storage_secret import Storage_secret


# This main script simulates all communication lines between Client Server and Storage
# The server and client objects represent one connection between a client and a server
# We assume that everything that passes between Client and Server is over the internet can be eavesdropped
# Communication between Server and Storage is over a secure bus

def test_voting():
    # Legitimate voting test
    # Vote sending
    server = Server()
    client = Client(1)
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    client.recieve_sym_key(sym_key_message)
    vote_message, nonce = client.generate_vote(b'16karakters_lang')
    print("main vote msg:")
    print(vote_message)
    vote, verification = server.handle_vote(vote_message, nonce)
    print("main vote:")
    print(vote)
    # Server sends vote & verification to storage to check if it can be added
    storage = Storage()
    id, token = storage.create_voter(verification)
    storage_response, storage_response_nonce = storage.vote(id, vote, token)
    storage_response = ("ID"+storage_response).encode()
    storage_secret = Storage_secret()
    storage_secret.add_nonce(id, storage_response_nonce)
    # Storage sends back vote ID if OK
    encrypted_ID, nonce = server.handle_storage_vote_response(storage_response)
    client.store_vote_id(encrypted_ID, nonce)

    # Vote checking
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    client.recieve_sym_key(sym_key_message)
    # Server -> Client : Server sends symmetric key + secret
    encrypted_vote_ID, nonce = client.send_voter_id()
    # Client -> Server : Client sends vote ID
    decrypted_id = int(server.handle_vote_request(encrypted_vote_ID, nonce)[2:])
    print(decrypted_id)
    # Server -> Storage : decrypted ID sent to storage to check
    storage_nonce = storage_secret.get_nonce(decrypted_id)
    storage_response = storage.read_vote(decrypted_id, storage_nonce)
    print("storage response:")
    print(storage_response)
    # Storage -> Server : vote message sent to server
    encrypted_vote, nonce = server.handle_storage_ID_respone(storage_response)
    print("encrypted vote")
    print(encrypted_vote)
    # Server -> Client : Server sends encrypted vote message to client
    client.recieve_vote(encrypted_vote, nonce)

def test_server_fake_sym_key():
    # Fake server tries sending its own symmetric key and incorrect verification secret
    # Vote sending
    server = Server()
    client = Client(1)
    fake_server = FakeServer()
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = fake_server.send_fake_sym_key(client_key, verification_secret, ip)
    # FakeServer -> Client : FakeServer sends fake symmetric key + fake secret
    client.recieve_sym_key(sym_key_message)

def test_fake_ID_response():
    # Fake server tries sending its own generated voter ID
    # Vote sending
    server = Server()
    client = Client(1)
    fake_server = FakeServer()
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    client.recieve_sym_key(sym_key_message)
    vote_message, nonce = client.generate_vote(b'16karakters_lang')
    vote, verification = server.handle_vote(vote_message, nonce)
    encrypted_ID, nonce = fake_server.send_fake_ID_response()
    # 
    client.store_vote_id(encrypted_ID, nonce)

def test_fake_vote_response():
    # Fake server tries sending fake vote confirmation with its own generated vote candidate
    # Vote sending
    server = Server()
    client = Client(1)
    fake_server = FakeServer()
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    client.recieve_sym_key(sym_key_message)
    vote_message, nonce = client.generate_vote(b'16karakters_lang')
    vote, verification = server.handle_vote(vote_message, nonce)
    # Server sends vote & verification to storage to check if it can be added
    # Storage sends back vote ID if OK
    storage_response = b'ID123'  # Storage.handle_vote()
    encrypted_ID, nonce = server.handle_storage_vote_response(storage_response)
    client.store_vote_id(encrypted_ID, nonce)

    # Vote checking
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    client.recieve_sym_key(sym_key_message)
    # Server -> Client : Server sends symmetric key + secret
    encrypted_vote_ID, nonce = client.send_voter_id()
    # Client -> Server : Client sends vote ID
    decrypted_id = server.handle_vote_request(encrypted_vote_ID, nonce)
    # Server -> Storage : decrypted ID sent to storage to check
    storage_response = b"16karakters_lang"  # = Storage.handle_id()
    # Storage -> Server : vote message sent to server
    encrypted_vote, nonce = fake_server.send_fake_vote_response()
    # Server -> Client : Server sends encrypted vote message to client
    client.recieve_vote(encrypted_vote, nonce)
    
def blocked_ip_connect():
    # Blocked IP vote send
    server2 = Server()
    client2 = Client(2)
    client2.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server2.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client2.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server2.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret

def test_fake_client_sends_own_pubkey():
    # Vote sending
    server = Server()
    client = Client(1)
    fakeclient = fakeClient(1)
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    malclient_key, verification_secret, ip = fakeclient.intercept_sym_key_req_replace_pub_key(verification_secret, ip)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server.handle_sym_key_request(malclient_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    client.recieve_sym_key(sym_key_message)

def test_fake_client_sends_tampered_vote():
    # Vote sending
    server = Server()
    client = Client(1)
    fakeclient = fakeClient(1)
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    client.recieve_sym_key(sym_key_message)
    vote_message, nonce = client.generate_vote(b'16karakters_lang')
    # fakeclient intercepts client message and replaces it
    vote_message, nonce = fakeclient.intercept_send_vote_replace_vote_and_verify()
    vote, verification = server.handle_vote(vote_message, nonce)
    # Server cannot correctly decipher the vote because the sym key is wrong
    # TODO verification should be wrongly decoded at server side so storage cannot be able to handle that
    # Server sends vote & verification to storage to check if it can be added
    storage = Storage()
    id, token = storage.create_voter(verification)
    storage_response, storage_response_nonce = storage.vote(id, vote, token)
    storage_secret = Storage_secret()
    storage_secret.add_nonce(id, storage_response_nonce)
    # Storage sends back vote ID if OK
    storage_response = b'ID21345'  # Storage.handle_vote()
    encrypted_ID, nonce = server.handle_storage_vote_response(storage_response)
    client.store_vote_id(encrypted_ID, nonce)

def test_fake_client_sends_own_ID():
    # Fake client tries sending fake vote confirmation with its own generated vote candidate
    # Vote sending
    server = Server()
    client = Client(1)
    fakeclient = fakeClient(2)
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    client.recieve_sym_key(sym_key_message)
    vote_message, nonce = client.generate_vote(b'16karakters_lang')
    vote, verification = server.handle_vote(vote_message, nonce)
    # Server sends vote & verification to storage to check if it can be added

    # Storage sends back vote ID if OK
    storage_response = b'ID123'  # Storage.handle_vote()
    encrypted_ID, nonce = server.handle_storage_vote_response(storage_response)
    client.store_vote_id(encrypted_ID, nonce)

    # Vote checking
    client.generate_public_key_request()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = client.generate_sym_key_request(public_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    client.recieve_sym_key(sym_key_message)
    # Server -> Client : Server sends symmetric key + secret
    encrypted_vote_ID, nonce = client.send_voter_id()
    encrypted_vote_ID, nonce = fakeclient.intercept_vote_ID_replace_ID()
    # Client -> Server : Client sends vote ID
    decrypted_id = server.handle_vote_request(encrypted_vote_ID, nonce)
    # Server -> Storage : decrypted ID sent to storage to check
    # TODO ID should be wrongle decoded at server side so storage cannot be able to handle that
    storage = Storage()
    id, token = storage.create_voter(verification)
    storage_response, storage_response_nonce = storage.vote(id, vote, token)
    storage_secret = Storage_secret()
    storage_secret.add_nonce(id, storage_response_nonce)
    storage_response = b"16karakters_lang"  # = Storage.handle_id()
    # Storage -> Server : vote message sent to server
    encrypted_vote, nonce = server.handle_storage_vote_response(storage_response)
    # Server -> Client : Server sends encrypted vote message to client
    client.recieve_vote(encrypted_vote, nonce)

if __name__ == "__main__":
    test_voting()
    
