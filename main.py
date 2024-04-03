from Server import Server

from client import Client

# This main script simulates all communcation lines between Client Server and Storage
# We assume that everything that passes between Client and Server is over the internet can be eavesdropped
# Communication between Server and Storage is over a secure bus

if __name__ == "__main__":
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
    vote, verification = server.handle_vote(vote_message, nonce)
    # Server sends vote & verification to storage to check if it can be added
    # Storage sends back vote ID if OK
    storage_response = b'aze'  # Storage.handle_vote()
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
    encrypted_vote, nonce = server.handle_storage_ID_respone(storage_response)
    # Server -> Client : Server sends encrypted vote message to client
    client.recieve_vote(encrypted_vote, nonce)
