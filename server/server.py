import socket
import requests
import json
import boto3
import tenseal as ts
import uuid

class HE:
    def __init__(self):
        try:
            self.keyId = str(uuid.uuid4())
            self.context = ts.context(
                    ts.SCHEME_TYPE.CKKS,
                    poly_modulus_degree=8192,
                    coeff_mod_bit_sizes=[60,40,40,60])
            self.context.generate_galois_keys()
            self.context.global_scale = 2**40
        except Exception as e:
            print("HE define error:{}".format(e))

def aws_api_call(credential):
    """
    Make AWS API call using credential obtained from parent EC2 instance
    """

    client = boto3.client(
        'kms',
        region_name = 'us-east-1',
        aws_access_key_id = credential['access_key_id'],
        aws_secret_access_key = credential['secret_access_key'],
        aws_session_token = credential['token']
    )

    
    print("---- the first vec from client---\n")
    first_vec = credential['vector']
    print(first_vec)




    # This is just a demo API call to demonstrate that we can talk to AWS via API
    response = client.describe_key(
        KeyId = '3c237224-043c-444a-8627-156798760271'
    )

    # Return some data from API response
    return {
        'KeyId': response['KeyMetadata']['KeyId'],
        'KeyState': response['KeyMetadata']['KeyState'],
        'vector':[1,2,3,4,5,6,7,8,9]
    }

def main():
    print("Starting server...")
    
    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Listen for connection from any CID
    cid = socket.VMADDR_CID_ANY

    # The port should match the client running in parent EC2 instance
    port = 5000

    # Bind the socket to CID and port

    s.bind((cid, port))

    # Listen for connection from client
    s.listen()

    while True:
        c, addr = s.accept()

        # Get AWS credential sent from parent instance
        payload = c.recv(4096)
        credential = json.loads(payload.decode())

        # Get data from AWS API call
        content = aws_api_call(credential)

        # Send the response back to parent instance
        c.send(str.encode(json.dumps(content)))

        ##############trail of tenseal
        print("-------main listen-trial tenseal-----")
        he_engine = HE()
        he_context = he_engine.context
        he_keyid   = he_engine.keyId
        print("key id is :",he_keyid)
        vec = credential['vector']
        print("vec in main :", vec)
        fvec = ts.ckks_vector(he_context, vec)
        print("dec vec in main", fvec.decrypt(he_context.secret_key()))



        # Close the connection
        c.close() 

if __name__ == '__main__':
    main()
