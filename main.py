from Server import Server

# from Client import Client

if __name__ == "__main__":
    # Vote sending
    server = Server()
    # client = Client()
    # client.public_key_req_generate()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = 0, 0, 0  # = client.sym_key_req_generate(publick_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = Server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    vote_message = "hallo"  # =  client.vote_generate(sym_key_message)
    vote, verification = Server.handle_vote(vote_message)
    # Server sends vote & verification to storage to check if it can be added
    # Storage sends back vote ID if OK
    storage_response = 123  # Storage.handle_vote()
    encrypted_ID = Server.handle_storage_vote_response(storage_response)
    # Client.store_vote_ID(encrypted_ID)

    # Vote checking
    # client.public_key_req_generate()
    # Client -> Server : Client requests public key
    public_key = server.share_public_key()
    # Server -> Client : Server gives public key
    client_key, verification_secret, ip = 0, 0, 0  # = client.sym_key_req_generate(publick_key)
    # Client -> Server : Client requests symmetric key by sending secret, his public key and ip
    sym_key_message = Server.handle_sym_key_request(client_key, verification_secret, ip)
    # Server -> Client : Server sends symmetric key + secret
    encrypted_vote_ID = 123  # =  client.vote_generate(sym_key_message)
    # Client -> Server : Client sends vote ID
    decrypted_id = Server.handle_vote_request(encrypted_vote_ID)
    # Server -> Storage : decrypted ID sent to storage to check
    storage_response = "hallo"  # = Storage.handle_id()
    # Storage -> Server : vote message sent to server
    encrypted_vote = Server.handle_storage_ID_respone(storage_response)
    # Server -> Client : Server sends encrypted vote message to client
    # Client.see_vote(encrypted_vote)

