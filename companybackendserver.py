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
import json
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
    
    AES_key = new_user["token"]["AES_key"]
    user_AES_key = bytes(ast.literal_eval(AES_key))
    print("AES_key")
    print(user_AES_key)
    user_block_id = new_user["token"]["block_id"]
    
#    print("user_AES_key:" %user_AES_key)
#    print("user_block_id:" %user_block_id)
    
    print("-------------------------------------------Send Request to KYC Backend-----------------------------------------")
    r = requests.post("https://kyc-project.herokuapp.com/register_org", json = {"block_id":user_block_id})

    print("--------------------------------------------------Response Received---------------------------------------------")
    print(r.status_code)
    print(r.text) 
    user_encrypted_data = json.loads(r.text)
#    user_encrypted_data = ast.literal_eval(user_encrypted_data)
    print(type(user_encrypted_data))
    print(user_encrypted_data)
    user_encrypted_data = user_encrypted_data["userData"]
    print(type(user_encrypted_data))
   # user_encrypted_data = ast.literal_eval(user_encrypted_data)
    user_encrypted_data ={"name":"[1, 203, 220, 109, 90, 88, 199, 217, 36, 177, 33, 222, 18, 142, 85, 131, 8, 238, 110, 108, 141, 32, 194, 9]","encrypted_id":"[71, 222, 61, 158, 6, 214, 60, 196, 222, 231, 219, 140, 91, 107, 217, 20, 50, 175, 114, 111, 159, 188, 61, 239, 215]","postcode":"[159, 54, 109, 142, 153, 181, 101, 166, 83, 27, 251, 50, 19, 52, 64, 106, 183, 175, 145, 217, 18, 196]","birthdate":"[66, 88, 132, 94, 179, 56, 130, 194, 140, 238, 51, 110, 15, 44, 155, 165, 137, 122, 181, 179, 253, 54, 34, 254, 126, 16]","merkle_root":"[97, 245, 2, 73, 27, 228, 32, 117, 142, 141, 7, 219, 152, 56, 131, 159, 216, 249, 248, 155, 215, 82, 91, 113, 218, 223, 33, 189, 53, 199, 202, 56, 214, 33, 132, 44, 191, 230, 85, 156, 243, 228, 60, 154, 254, 160, 193, 73, 160, 197, 84, 229, 123, 96, 66, 103, 27, 206, 194, 174, 79, 1, 44, 156, 48, 105, 65, 131, 193, 63, 219, 144, 117, 211, 158, 42, 17, 227, 9, 134]","rsa_public_key":"[225, 96, 151, 150, 145, 68, 8, 222, 90, 204, 189, 25, 102, 37, 71, 185, 21, 249, 170, 179, 29, 192, 34, 95, 231, 93, 232, 164, 172, 23, 32, 229, 189, 51, 35, 13, 158, 31, 239, 55, 223, 176, 246, 228, 47, 6, 195, 198, 159, 223, 233, 4, 248, 132, 3, 209, 174, 21, 220, 141, 67, 174, 6, 91, 195, 63, 190, 209, 112, 192, 82, 108, 55, 95, 149, 79, 101, 91, 137, 0, 213, 137, 105, 41, 83, 88, 19, 163, 135, 40, 210, 118, 65, 46, 204, 207, 143, 65, 114, 195, 148, 254, 66, 157, 22, 141, 55, 230, 248, 170, 205, 243, 218, 57, 140, 84, 75, 233, 78, 178, 24, 13, 91, 108, 22, 130, 70, 240, 193, 73, 2, 63, 89, 21, 71, 120, 156, 131, 170, 73, 215, 102, 145, 150, 82, 144, 158, 65, 154, 62, 73, 76, 238, 51, 57, 254, 27, 207, 215, 251, 53, 233, 89, 249, 44, 248, 234, 187, 142, 160, 51, 22, 100, 221, 173, 160, 97, 244, 96, 181, 152, 9, 13, 35, 115, 240, 117, 67, 172, 86, 198, 162, 83, 248, 20, 39, 198, 10, 14, 150, 148, 48, 164, 98, 79, 29, 67, 175, 91, 128, 36, 150, 21, 196, 217, 179, 12, 52, 196, 6, 75, 6, 17, 157, 181, 225, 13, 79, 238, 168, 134, 22, 218, 28, 6, 148, 173, 90, 110, 40, 107, 154, 85, 108, 152, 127, 245, 51, 228, 138, 110, 140, 117, 130, 13, 40, 65, 223, 157, 250, 91, 183, 123, 96, 201, 10, 216, 128, 45, 227, 58, 167, 121, 76, 160, 134, 101, 137, 85, 200, 8, 210, 242, 166, 50, 243, 234, 12, 127, 217, 239, 28, 50, 14, 144, 91, 117, 227, 98, 165, 92, 86, 248, 218, 190, 96, 182, 0, 12, 165, 43, 54, 87, 33, 117, 42, 110, 97, 105, 228, 2, 142, 209, 115, 203, 166, 142, 110, 94, 252, 228, 25, 131, 202, 150, 207, 216, 231, 65, 135, 118, 122, 150, 108, 108, 205, 20, 205, 27, 34, 140, 101, 62, 52, 222, 175, 91, 7, 169, 33, 67, 110, 150, 52, 181, 130, 253, 98, 227, 234, 231, 42, 197, 190, 103, 102, 120, 202, 142, 144, 224, 161, 215, 63, 49, 34, 71, 19, 124, 25, 4, 138, 199, 128, 134, 0, 71, 122, 69, 13, 198, 88, 69, 142, 158, 132, 57, 239, 246, 81, 30, 17, 152, 22, 101, 174, 193, 8, 225, 136, 96, 54, 143, 223, 101, 244, 73, 82, 146, 169, 56, 193, 219, 165, 122, 163, 159, 137, 196, 201, 64, 232, 2, 116, 125, 145, 120, 22, 210, 188, 154, 168, 153, 147, 239, 234, 28, 82, 61, 130, 2, 243, 71, 137, 200, 228]"}
    print(user_encrypted_data)
    user_decrypted_data = {}
    print("-----------------------------------------------------Start Decrypting-------------------------------------------")
    for key in user_encrypted_data:
        user_decrypted_data[key] = aes_decrypt(user_encrypted_data[key],user_AES_key)
#    user_decrypted_data = aes_decrypt(user_encrypted_data,user_AES_key)
    print(user_decrypted_data)
    print("-----------------------------------------------------------------Done--------------------------------------------")
    
    
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
    
    registered_user_database[new_user["username"]] = user_decrypted_data
    
    
    
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
      #  try:
      print(data)
      data = bytes(ast.literal_eval(data))
     #   except:
    #        print("Error: could not interpret data for decryption")
            
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
    
    
