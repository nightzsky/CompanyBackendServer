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
import ast
#from flask.ext.sqlalchemy import SQLAlchemy
app = Flask(__name__)

request_id_database = {"request_id":{"private_key":"private_key_to_decrpyt_info_sent_by_this_request_id","public_key":"public_key"}}
registered_user_database = {"username":"data_extracted_from_kyc"}


#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://local'

#db = SQLAlchemy()

@app.route("/")
def hello():
    return "Hello"

@app.route("/get_key",methods = ['GET'])
def return_pub_key():
    request_id= "111"
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
    
    request_id_database[request_id]={"private_key":private_key,"public_key":public_key}
#    request_id_database[request_id]["private_key"] = private_key
#    request_id_database[request_id]["public_key"] = public_key
    
    return jsonify(for_user)

@app.route("/display")
def display():
    return jsonify(registered_user_database)

@app.route("/getDatabase",methods = ['GET'])
def getDatabase():
    resp = jsonify(request_id_database)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

@app.route("/register_user", methods = ['POST'])
def register_user():
    new_user = {}
    request_id = "112"
#    key_pair = request_id_database[request_id]
#    print(key_pair)
#    private_key_for_decryption = RSA.import_key(key_pair["private_key"])
#    public_key = RSA.import_key(key_pair["public_key"])
    RSA_pvt_key = RSA.generate(2048)
    RSA_pub_key = RSA_pvt_key.publickey()
    
#    private_key_for_decryption = request_id_database[request_id]["private_key"]
#    public_key = request_id_database[request_id]["public_key"]
    
#    new_user["username"] = rsa_decrypt(request.json["username"],private_key_for_decryption)

#    new_user["token"] = rsa_decrypt(request.json["token"],private_key_for_decryption)
    new_user["username"] = request.json["username"]
    new_user["token"] = request.json["token"]
    
    print(new_user)
    
    new_user["username"] = rsa_encrypt(new_user["username"],RSA_pub_key)
    for key in new_user["token"]:
        new_user["token"][key] = rsa_encrypt(new_user["token"][key],RSA_pub_key)
    print("------------------------------Received Encrypted Info---------------------------------")
    print(new_user)
    print("-----------------------------------------End------------------------------------------")
    
    new_user["username"] = rsa_decrypt(new_user["username"],RSA_pvt_key)
    for key in new_user["token"]:
        new_user["token"][key] = rsa_decrypt(new_user["token"][key], RSA_pvt_key)
    print("------------------------------------Start Decrypting Info Received-------------------------------------")
    print(new_user)
    print("----------------------------------------------End Of Decryption----------------------------------------")
    
    user_AES_key = list(b(new_user["token"]["AES_key"])
    user_block_id = new_user["token"]["block_id"]
    
#    print("user_AES_key:" %user_AES_key)
#    print("user_block_id:" %user_block_id)
    
    print("-------------------------------------------Send Request to KYC Backend-----------------------------------------")
    r = requests.post("https://kyc-project.herokuapp.com/register_org", json = {"block_id":user_block_id})

    print("--------------------------------------------------Response Received---------------------------------------------")
    print(r.status_code)
    print(r.text) 
    user_encrypted_data = r.json
    print(user_encrypted_data)
    
#    print("user_encrypted_data")
#    print(user_encrypted_data)
#    print("===========================================================")
    
#    user_decrypted_data = {}
#    for key in user_encrypted_data:
#        user_decrypted_data[key] = aes_decrypt(user_encrypted_data[key], user_AES_key)
#        
#    print(user_decrypted_data)
#    
#    database[new_user["username"]] = user_decrypted_data
    
    registered_user_database["username"] = user_encrypted_data
    
    
    
    return "Done"

@app.route("/login_org",methods = ['POST'])
def login_org():
    request_id = request.json["request_id"]
    username = request.json["username"]
    if username in registered_user_database.keys():
        resp = Response(json.dumps({"status":"success"}))
        resp.status_code = 200
    else:
        resp = Response(json.dumps({"status":"fail"}))
        resp.status_code = 200
    print(resp)
    
    return resp
    
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
            print(data)
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
    
    
