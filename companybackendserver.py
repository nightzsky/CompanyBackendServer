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

app = Flask(__name__)

mutex = threading.Lock()

#Connect to the postgresql database. returns the connection object and its cursor
def connect_db():
    conn = psycopg2.connect(os.environ['DATABASE_URL'], sslmode = 'require')
    cur = conn.cursor()
    return conn, cur

#select database
def select_db(column,database):
    conn,cur = connect_db()
    cur.execute("SELECT %s FROM %s"%(column,database))
    rows = cur.fetchall()
    return conn,cur,rows

#get the most updated database
def get_previous_request_id():
    conn,cur,rows = select_db("COUNT","COUNTTABLE")
    count = rows[0][0]
    print("Current ID: %s"%count)
    
    return conn,cur,count

#get request id
def get_request_id():
    conn,cur,count = get_previous_request_id()
    count += 1
    cur.execute("UPDATE COUNTTABLE SET COUNT = '%s'"%count)
    print("Updated Counttable")
    
    conn.commit()
    conn.close()
    
    request_id = count
    
    return request_id

#get private key for decryption
def get_private_key(request_id):
    conn,cur,rows = select_db("*","REQUEST_DATABASE")
    private_key = ""
    for row in rows:
        if (row[0] == (int)(request_id)):
            print(row[1])
            private_key = row[1]
    if(private_key == ""):
        print("Invalid Request ID!")
        return 'Invalid Request ID'
        
    conn.close()
    
    return private_key

#for register org and login org for username detection
def check_if_username_exists(username):
    conn,cur,rows = select_db("USERNAME","COMPANY_DATABASE")
    matching = False
    for row in rows:
        if (row[0] == username):
            matching = True
            
    if (matching == True):
        print("Username already exists!")
    return matching

def check_if_user_info_exists(user_info):
    conn,cur,rows = select_db("USER_INFO","COMPANY_DATABASE")
    exist = False
    for row in rows:
        if (row[0] == user_info):
            exist = True
    if (exist == True):
        print("You have registered this company before.")
    return exist

#check if the user exists on the database
def check_for_login(username,password):
    conn,cur,rows = select_db("*","COMPANY_DATABASE")
    can_login = False
    for row in rows:
        if (row[0] == username):
            if (row[1]==password):
                can_login = True
            else:
                can_login = False
        else:
            can_login = False
    if (can_login == False):
        print("Invalid username/password!")
    return can_login
    
#update the request id and private key to the database
def update_request_database(request_id,private_key):
    conn,cur = connect_db()
    
    #update the request_database with request id and private key
    cur.execute("INSERT INTO REQUEST_DATABASE (ID,PRIVATE_KEY) \
                VALUES (%s,%s)",(request_id,private_key))
    
    print("Updated request id and private key")
    conn.commit()
    conn.close()
    
#add the decrypted user info to the company database
def add_user_to_database(username,password,user_info):
    conn,cur = connect_db()
    cur.execute("INSERT INTO COMPANY_DATABASE (USERNAME,PASSWORD,USER_INFO) \
                VALUES (%s,%s,%s)",(username,password,json.dumps(user_info)))
    conn.commit()
    conn.close()

#extract the user_info for respective user from database
def extract_user_info(username):
    conn,cur,rows = select_db("*","COMPANT_DATABASE")
    user_info = ""
    for row in rows:
        if (row[0] == username):
            user_info = row[2]
            print(user_info)
    if (user_info == ""):
        print("User does not exist.")
    conn.close()
    return user_info

#delete user from company_database
def del_user(username):
    conn,cur = connect_db()
    if (check_if_user_exists(username) == True):
        cur.execute("DELETE from COMPANY_DATABASE where USERNAME = %s"%username)
        cur.commit()
        conn.close()
        return "Deleted user %s"%username
    else:
        return "User does not exist."
    
#refresh the request_database
def refresh_request_database():
    conn,cur = connect_db()
    #del the whole table
    cur.execute("DROP TABLE REQUEST_DATABASE")
    conn.commit()
    #create the table again
    cur.execute('''CREATE TABLE REQUEST_DATABASE 
                (ID INT NOT NULL,
                 PRIVATE_KEY TEXT NOT NULL);''')
    conn.commit()
    #refresh the counttable
    cur.execute("UPDATE COUNTTABLE set COUNT = 0");
    conn.commit()
    conn.close()
    

#to view the request database with request id and corresponding public key stored
@app.route("/get_request_database",methods = ['GET'])
def get_request_database():
    conn,cur,rows = select_db("*","REQUEST_DATABASE")
    print(rows)
    print(type(rows))
    response = jsonify(rows)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

#to view the company database, all the users info
@app.route("/get_company_database",methods = ['GET'])
def get_company_database():
    conn,cur,rows = select_db("*","COMPANY_DATABASE")
    print(rows)
    print("hi")
    response = jsonify(rows)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

#decrypt the json request    
def decrypt_request(request_id,json):
    #retrieve the private key from request_database
    str_private_key = get_private_key(request_id)

    #Handle case of invalid request id
    if str_private_key == 'Invalid Request ID':
        return 'Invalid Request ID'

    private_key = RSA.import_key(str_private_key)
    
    decrypted = {}
    for key in json:
        if type(json[key]) == dict:
            decrypted[rsa_decrypt(ast.literal_eval(key),private_key)] = decrypt_request(json[key])
        else:
            decrypted[rsa_decrypt(ast.literal_eval(key),private_key)] = rsa_decrypt(ast.literal_eval(json[key]), private_key)

    return decrypted

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
    received_request = request.json
    print(received_request)
    
    request_id = received_request["request_id"] 
    print("received request_id")
    print(request_id)
    
    #delete request_id from the request received for decrpytion
    if ("request_id" in received_request):
        del received_request["request_id"]
    
    print(received_request)
    
    #decrypt the request received
    decrypted = decrypt_request(request_id,received_request)

    #Handle invalid request id
    if decrypted == 'Invalid Request ID':
        resp = Response(json.dumps({"Message":"Invalid request ID"}))
        resp.status_code = 400
        return resp

    print(decrypted)
    
    #decrypt the user request using private key
    username = decrypted["username"]
    password = decrypted["password"]
    block_id = decrypted["block_id"]
    AES_key = decrypted["AES_key"]
    
    #if username already exist, don't allow the user to register
    if (check_if_username_exists(username) == True):
        resp = Response(json.dumps({"Error":"Username already exists!"}))
        resp.status_code = 409 #conflict with the current state of resources
        return resp
    
    print(username)
    print(password)  
    print("Block ID: %s"%block_id)
    print("AES_key: %s"%AES_key)
    print(type(AES_key))
        
    #post request to kyc backend to retrieve user block of info
    r = requests.post("https://kyc-project.herokuapp.com/register_org", json = {"block_id":block_id})
    print(r.status_code)
    print(r.text)
        
    if (r.status_code == 200): #if success in retrieving user info from kyc
        # received ENCRYPTED user data from kyc backend
        user_data = json.loads(r.text)
        print(type(user_data))
        user_data = user_data["userData"]
        del user_data["$class"]
        print(user_data)
           
        #decrpyt the user data with AES key
        for key in user_data:
            print("decrypting %s now"%key)
            user_data[key] = aes_decrypt(user_data[key],AES_key)
            
        print(user_data)
            
        if(check_if_user_info_exists(user_data) == True):
            resp = Response(json.dumps({"Error":"You have already registered the company!"}))
            resp.status_code = 409
            return resp
        else:    
            #post the user data to the company database along with password and username
            add_user_to_database(username,password,user_data)
            return "Done"
        
    else: #if fail to retrieve the user info
        resp = Response(json.dumps(json.loads(r.text)))
        resp.status_code = r.status_code
        return resp

@app.route("/login_org",methods = ['POST'])
def login_org():
    received_request = request.json
    print(received_request)
    
    request_id = received_request["request_id"] 
    print("received request_id")
    print(request_id)
    
    if ("request_id" in received_request):
        del received_request["request_id"]
    
    print(received_request)
    
    #decrypt the request received
    decrypted = decrypt_request(request_id,received_request)
    print(decrypted)
        
    
    username = decrypted["username"]
    password = decrypted["password"]
    
    print("username %s"%username)
    print("password %s"%password)
    
    can_login = check_for_login(username,password)
    
    if (can_login):
        resp = Response(json.dumps({"Message":"Welcome %s"%username}))
        resp.status_code = 200
    else:
        resp = Response(json.dumps({"Message":"Invalid username/password."}))
        resp.status_code = 401
    print(resp)
    
    return resp
    
@app.route("/get_database_size", methods = ['GET'])
def get_database_size():
    conn,cur,num_requests = get_previous_request_id()
    response = jsonify({"Total requests" : num_request})
    
    return response

if __name__ == "__main__":
    app.run()