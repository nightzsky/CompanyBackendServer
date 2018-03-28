from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
import ast
import base64

#function which encrypts data using AES
def aes_encrypt(data,key):
    #process data to become suitable for encryption by converting to bytes if needed
    if type(data) != bytes:
        data = bytes(data, encoding = "utf8")
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB,iv)
    return str(list((iv+cipher.encrypt(data))))

#function which decrypts data using AES
def aes_decrypt(data,key):
    if type(key) != bytes:
        key = bytes(ast.literal_eval(key))
    if type(data) != bytes:
        try:
            data = bytes(ast.literal_eval(data))
        except Exception as e:
            print(e)
            print("Error: could not interpret data for decryption")
            return
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted = cipher.decrypt(data[16:]).decode()
    return decrypted

#function which encrypts data using RSA
def rsa_encrypt(data, public_key):
    if type(public_key) == str:
        public_key = RSA.importKey(public_key)

    if type(data) != bytes:
        data = bytes(data, encoding = "utf8")
    cipher = PKCS1_OAEP.new(public_key)
    #hybrid encryption is used here as PKCS1_OAEP can only encrypt a very small amount of data
    #to get around this, AES is used for the encryption of the data, and the AES key is encrypted using RSA
    session_key = Random.get_random_bytes(16)
    encrypted_data = aes_encrypt(data,session_key)
    encrypted_session_key = cipher.encrypt(session_key)
    return [encrypted_data, encrypted_session_key]

#function which decrypts data using RSA
def rsa_decrypt(data, private_key):
    if type(private_key) == str:
        private_key = RSA.importKey(private_key)

    if type(data) == str:
        data = ast.literal_eval(data)
    if type(data[0] == list):
        data[0] = java_to_python_bytes(data[0])

    if type(data[1] == list):
        data[1] = java_to_python_bytes(data[1]) 

    cipher = PKCS1_OAEP.new(private_key)
    #first decrypt the session key using RSA
    if type(data[1] != bytes):
        data[1] = bytes(data[1])
    print("encrypted session key: %s"%list(data[1]))
    session_key = cipher.decrypt(data[1])
    print("session key: %s"%list(session_key))
    data[1] = bytes(data[1])
    session_key = cipher.decrypt(data[1])
    #then decrypt the data using AES and the session key
    return aes_decrypt(str(data[0]), session_key)

#computes a SHA256 hash of the data
def hash256(data):
    data = bytes(data, encoding = "utf8")
    hash_object = SHA256.new(data=data)
    return hash_object.hexdigest()

#function that returns the root hash of the merkle tree from a list of data
#it assumes that everything in the data has already been hashed
def merkle(data):
    #base case, only one data point, return that one data point
    if len(data) == 1:
        return data[0]

    #another base case, compute hash of the concatenation of the 2 leaves
    if len(data) == 2:
        return hash256(data[0] + data[1])

    #if odd number, ignore last data point  
    if (len(data)%2 != 0):
        data = data[:-1]

    #recursively traverse the merkle tree from bottom to top to get the root hash
    temp = []
    for i in range(0,len(data),2):
        temp.append(merkle(data[i:i+2]))

    return merkle(temp)

#converts an int array of java bytes to an int array of python bytes
def java_to_python_bytes(arr):
    if type(arr) == str:
        arr = ast.literal_eval(arr)

    if type(arr) == list:
        for i in range(len(arr)):
            if type(arr[i]) == list:
                arr[i] = java_to_python_bytes(arr[i])
            else:
                arr[i] = arr[i]%256
            
        return arr
    else:
        raise ValueError("Input must be an array or string representation of an array")

#Encrypts a http request to be sent to the backend servers using an RSA public key
def encrypt_request(req, pub_key):
    encrypted = {}
    for i in req:
        if type(req[i]) == dict:
            encrypted[str(rsa_encrypt(i,pub_key))] = encrypt_request(req)
        encrypted[str(rsa_encrypt(i,pub_key))] = str(rsa_encrypt(req[i], pub_key))
    return encrypted


