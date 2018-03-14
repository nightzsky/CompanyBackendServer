# -*- coding: utf-8 -*-
"""
Created on Tue Mar 13 20:22:30 2018

@author: Nightzsky
"""

from flask import Flask,jsonify,request,Response
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
import requests
import os
#from flask.ext.sqlalchemy import SQLAlchemy
app = Flask(__name__)

database = {"hi":"bye"}
organization = {}


#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://local'

#db = SQLAlchemy()

@app.route("/")
def hello():
    return "Hello"

@app.route("/get_key",methods = ['GET'])
def return_pub_key():
    request_id= 111
    print(organization)
    RSA_pvt_key = RSA.generate(2048)
    RSA_pub_key = RSA_pvt_key.publickey()
    #write key to the file then read the same file to obtain the key in plaintext
    f = open("publicKey.pem", "a+b")
    f.write(RSA_pub_key.exportKey('PEM'))
    f.seek(0)
    RSA_pub_key_str = f.read()
    print("Generating RSA public key: %s"%RSA_pub_key_str)
    f.close()
    #delete file after this to prevent key from being stored as a file
    os.remove("publicKey.pem")
    print("Storing RSA public key in company info")
#    organization["public_key"] = RSA_pub_key_str.decode("utf-8")
    public_key = RSA_pub_key_str.decode("utf-8")
    #store private key, AES key, and user's block id in the token
    #first get private key as plaintext
    f = open("privateKey.pem", "a+b")
    f.write(RSA_pvt_key.exportKey('PEM'))
    f.seek(0)
    RSA_pvt_key_str = f.read()
    print("Generating RSA private key: %s"%RSA_pvt_key_str)
    f.close()
    #delete file after this to prevent key from being stored as a file
    os.remove("privateKey.pem")
    private_key = RSA_pvt_key_str.decode("utf-8")
    
    for_user = {}
    for_user["request_id"] = request_id
    for_user["public_key"] = public_key
    
    database[request_id] = private_key
    print(type(RSA_pvt_key_str))
    print(organization)
    
    return jsonify(for_user)

@app.route("/display")
def display():
    return jsonify(database)

@app.route("/register_user", methods = ['POST'])
def register_user():
    new_user = {}
    new_user["request_id"] = database["new"]
    new_user["username"] = rsa_decrypt(request.json["username"],organization["private_key"])
    new_user["password"] = rsa_decrypt(request.json["password"],organization["private_key"])
    new_user["token"] = rsa_decrypt(request.json["token"],organization["private_key"])
    
    user_AES_key = new_user["token"]["AES_key"]
    user_block_id = new_user["token"]["block_id"]
    
    r = requests.post("https://kyc-project.herokuapp.com/register_org", json = {"block_id":user_block_id})
    print(r.status_code)
    print(r.text)
    
    user_encrypted_data = r.json
    print("user_encrypted_data")
    print(user_encrypted_data)
    print("===========================================================")
    
    user_decrypted_data = {}
    for key in user_encrypted_data:
        user_decrypted_data[key] = aes_decrypt(user_encrypted_data[key], user_AES_key)
        
    print(user_decrypted_data)
    
    database[new_user["username"]] = user_decrypted_data
    
    return "Done"
    
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
	if type(data) != bytes:
		try:
			data = bytes(ast.literal_eval(data))
		except:
			print("Error: could not interpret data for decryption")
			return
	iv = data[:16]
	cipher = AES.new(key, AES.MODE_CFB, iv)
	decrypted = cipher.decrypt(data[16:]).decode()
	return decrypted  
    
    
    
    
#function which encrypts data using RSA
def rsa_encrypt(data, public_key):
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
	cipher = PKCS1_OAEP.new(private_key)
	#first decrypt the session key using RSA
	session_key = cipher.decrypt(data[1])
	#then decrypt the data using AES and the session key
	return aes_decrypt(data[0], session_key)

if __name__ == "__main__":
    app.run()
    
    
