# -*- coding: utf-8 -*-
"""
Created on Tue Mar 13 20:22:30 2018

@author: Nightzsky
"""

from flask import Flask,jsonify,request,Response
import threading
import requests
import os
import json
import ast
import psycopg2
from crypto_functions import *
#from flask.ext.sqlalchemy import SQLAlchemy
app = Flask(__name__)

request_id_database = {}
registered_user_database = {}
num_requests = 0
key_request_id = 1000000
mutex = threading.Lock()


#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://local'

#db = SQLAlchemy()

#Connect to the postgresql database. returns the connection object and its cursor
def connect_db():
    os.environ['DATABASE_URL'] = "postgres://kulppdlibhsggy:4655032868ea8a3c938e2bd5d015130b41c7810d012e8edc3518de8490bf205d@ec2-54-83-23-91.compute-1.amazonaws.com:5432/db5s1h8iuhepc"
    conn = psycopg2.connect(os.environ['DATABASE_URL'], sslmode = 'require')
    cur = conn.cursor()
    return conn, cur

#get the most updated request_id
def get_previous_request_id():
    conn,cur = connect_db()
    #retrieve count from the count table
    cur.execute("SELECT COUNT FROM COUNTTABLE")
    rows = cur.fetchall()
    count = rows[0][0]
    print("Current ID: %s"%count)
    
    return count
    
#get the request id from the table
def get_request_id():
    conn,cur = connect_db()
    count = get_previous_request_id()
    count += 1 #update the count and the table
    cur.execute("UPDATE COUNTTABLE SET COUNT = '%s'"%count)
    print("Updated CountTable")
    
    conn.commit()
    conn.close()
    
    request_id = count
    
    return request_id

#get the request database
def get_request_database():
    conn,cur = connect_db()
    cur.execute("SELECT * FROM REQUEST_DATABASE")
    rows = cur.fetchall()
    request_database ={}
    for row in rows:
        request_id = row[0]
        private_key = row[1]
        request_database[request_id] = private_key
        print("Request ID: %s"%request_id)
        print("Private Key: %s"%private_key)
    print("Done printing database")
    conn.close()
    
    return request_database

#get the company database
def get_company_database():
    conn,cur = connect_db()
    cur.execute("SELECT * FROM REQUEST_DATABASE")
    rows = cur.fetchall()
    company_database = {}
    for row in rows:
        username = row[0]
        password = row[1]
        user_info = row[2]
        
        company_database["Username"] = username
        company_database["Password"] = password
        company_database["User Info"] = user_info
    print(company_database)
    print("Done printing database")
    conn.close()
    
    return company_database

#update the request id and private key to the database
def update_request_database(request_id,private_key):
    conn,cur = connect_db()
    
    #update the request_database with request id and private key
    cur.execute("INSERT INTO REQUEST_DATABASE (ID,PRIVATE_KEY) \
                VALUES (%s,%s)",(request_id,private_key))
    
    print("Updated request id and private key")
    conn.commit()
    conn.close()

#get the private key from the table for decryption
def get_private_key(request_id):
    conn,cur = connect_db()
    cur.execute("SELECT * FROM REQUEST_DATABASE")
    rows = cur.fetchall()
    private_key = ""
    for row in rows:
        if (row[0] == request_id):
            private_key = row[1]
    print("hello")
    print(private_key)
    
    if (private_key == ""):
        print("Invalid Request ID!")
    
    conn.close()
    
    return private_key

#add the decrypted user info to the company database
def add_user_to_database(username,password,user_info):
    conn,cur = connect_db()
    cur.execute("INSERT INTO COMPANY_DATABASE (USERNAME,PASSWORD,USER_INFO) \
                VALUES (%s,%s,%s)",(username,password,json.dumps(user_info)))
    conn.commit()
    conn.close()

@app.route("/")
def hello():
    return "Hello"


@app.route("/get_key",methods = ['GET'])
def get_key():

    """
    generates a new public-private key pair with a unique request_id,
    then returns a json string containing the request_id and 
    only the public_key.
    """

    mutex.acquire()

    key_request_id = get_request_id()
    print("Request ID is %s"%key_request_id)
    
    #company generates their own RSA key pairs
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
    public_key = RSA_pub_key_str.decode("utf-8")

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
    
    #storing the request id and the correspond private key to databse
    update_request_database(key_request_id,private_key)
    print("private_key")
    print(private_key)
    
    #create json object to post response back to user
    for_user = {}
    for_user["request_id"] = key_request_id
    for_user["public_key"] = public_key
    
    mutex.release()
    
    return jsonify(for_user)

@app.route("/register_user", methods = ['POST'])
def register_user():
    request_id = request.json["request_id"] 
    print(request_id)
    #retrieve the private key from request_database
    str_private_key = get_private_key(request_id)
    private_key = RSA.import_key(str_private_key)
    
    print(str_private_key)
    print(type(str_private_key))
    #decrypt the user request using private key
    username = rsa_decrypt(request.json["username"],private_key)
    password = rsa_decrypt(request.json["password"],private_key)
    block_id = rsa_decrypt(request.json["block_id"],private_key)
    AES_key = rsa_decrypt(request.json["AES_key"],private_key)

#    token = request.json["token"]
#    for key in token:
#        token[key] = rsa_decrypt(token[key],private_key)
#    
    print(username)
    print(password)
#    print(token)
    
    #retrieve block id and AES key
#    block_id = token["block_id"]
#    AES_key = token["AES_key"]
    
    print("Block ID: %s"%block_id)
    print("AES_key: %s"%AES_key)
    
    #post request to kyc backend to retrieve user block of info
#    r = requests.post("https://kyc-project.herokuapp.com/register_org", json = {"block_id":block_id})
#    print(r.status_code)
#    print(r.text)
#    
#    # received ENCRYPTED user data from kyc backend
#    user_data = json.loads(r.text)
#    user_data = user_data["userData"]
#    
#    #decrpyt the user data with AES key
#    for key in user_data:
#        user_data[key] = aes_decrypt(user_data[key],AES_key)
    
    print(user_data)
    
    #post the user data to the company database along with password and username
    add_user_to_database(username,password,user_data)
    
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

@app.route("/display")
def display():
    return jsonify(registered_user_database)

@app.route("/get_database_size", methods = ['GET'])
def get_database_size():
    num_requests = get_previous_request_id()
    return num_requests

@app.route("/get_database",methods = ['GET'])
def get_database():

    """
    company calls this method. 
    """
    mutex.acquire()
    # pass the counter to the caller to check for a full response on the client side
    num_requests = get_previous_request_id()
    
    request_database = get_request_database()
    
    resp = jsonify(request_database)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    print(resp)
    mutex.release()
    return resp


if __name__ == "__main__":
    app.run()
    
    
