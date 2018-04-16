# -*- coding: utf-8 -*-
"""
Created on Tue Mar 13 20:22:30 2018

@author: Nightzsky
"""

from flask import Flask,jsonify,request,Response,make_response,current_app
from datetime import timedelta
import requests
import os
import json
import ast
import psycopg2
from crypto_functions import *
from functools import wraps,update_wrapper

app = Flask(__name__)

def crossdomain(origin=None, methods=None, headers=None,
                max_age=21600, attach_to_all=True,
                automatic_options=True):

    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, str):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, str):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = '*'
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator

##
  #These methods are for Authentication  
##
def check_auth(username, password):
    conn,cur,rows = select_db("*","COMPANY_LOGIN")
    for row in rows:
        if (username == row[0] and password == row[1] and row[2] == 'true'):
            return True
    return False

def authenticate():
    print("in authenticate()")
    message = {'message':"Authenticate."}
    resp = jsonify(message)
    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = 'Basic realm = "Example"'
    return resp

def requires_auth(f):
    print("in requires_auth()")
    @wraps(f)
    def decorated(*args,**kwargs):
        print("in decorated()")
        auth = request.authorization
        if not auth:
            print("not auth")
            return authenticate()
        
        elif not check_auth(auth.username, auth.password):
            print("wrong auth")
            return authenticate()
        return f(*args, **kwargs)
    return decorated

##
#   For database connection
#   connect_db(): Connect to the postgresql database. returns the connection object and its cursor
#   select_db(): choose the database to connect to
##
def connect_db():
    conn = psycopg2.connect(os.environ['DATABASE_URL'], sslmode = 'require')
    cur = conn.cursor()
    return conn, cur

def select_db(column,database):
    conn,cur = connect_db()
    cur.execute("SELECT %s FROM %s"%(column,database))
    rows = cur.fetchall()
    return conn,cur,rows


##
#   These methods are for generating all the request id for all the user who made request to the company backend server.
#   Each request id and its corresponding private key are stored in database in order to decrypt the corresponding request from the user.
#   get_previous_request_id(): get the lastest request id from the database
#   get_request_id(): generate the new request id for the user
#   get_private_key(request_id): return the corresponding private key for that request id for decryption
#   update_request_database(): update the request database after generating request id for the user
##
    
def get_previous_request_id():
    conn,cur,rows = select_db("COUNT","COUNTTABLE")
    count = rows[0][0]
    print("Current ID: %s"%count)
    
    return conn,cur,count

def get_request_id():
    conn,cur,count = get_previous_request_id()
    count += 1
    cur.execute("UPDATE COUNTTABLE SET COUNT = '%s'"%count)
    print("Updated Counttable")
    
    conn.commit()
    conn.close()
    
    request_id = count
    
    return request_id

def update_request_database(request_id,private_key):
    conn,cur = connect_db()
    
    cur.execute("INSERT INTO REQUEST_DATABASE (ID,PRIVATE_KEY) \
                VALUES (%s,%s)",(request_id,private_key))
    
    print("Updated request id and private key")
    conn.commit()
    conn.close()

def get_private_key(request_id):
    conn,cur,rows = select_db("*","REQUEST_DATABASE")
    private_key = ""
    for row in rows:
        if (row[0] == (int)(request_id)):
            private_key = row[1]
    if(private_key == ""):
        return 'Invalid Request ID'
        
    conn.close()
    
    return private_key

##
#   These methods are for checking validity or existence of the user in company database.
#   check_if_username_exists(): for register org and login org for username detection
#   check_if_user_info_eixsits(): check if the user already register the company
#   check_for_login(): check if the user can login by cross-checking the username,password and the status of his blockchain on database
##

def check_if_username_exists(username):
    conn,cur,rows = select_db("USERNAME","COMPANY_DATABASE")
    matching = False
    for row in rows:
        if (row[0].lower() == username.lower()):
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
        print("You have registered for this company before.")
    return exist

def check_for_login(username,password,encrypted_merkle_raw):
    conn,cur,rows = select_db("*","COMPANY_DATABASE")
    can_login = False
    for row in rows:
        if (row[0].lower() == username.lower()):
            if (row[1]==password):
                user_public_key = row[2]["rsa_public_key"]            
                if (verify_signature(row[2]["merkle_root"],encrypted_merkle_raw,user_public_key)==True):
                    can_login = True
                    return can_login
                
    if (can_login == False):
        print("Invalid username/password/token!")
    return can_login
    
##
#   These methods updates and retrieves data from the company database
#   add_user_to_database: Add a new register user info to the company database
#   extract_user_info: Retrieve the user's information    
#   del_user: delete user from the database
##

def add_user_to_database(username,password,user_info):
    conn,cur = connect_db()
    cur.execute("INSERT INTO COMPANY_DATABASE (USERNAME,PASSWORD,USER_INFO) \
                VALUES (%s,%s,%s)",(username,password,json.dumps(user_info)))
    conn.commit()
    conn.close()

def extract_user_info(username):
    conn,cur,rows = select_db("*","COMPANY_DATABASE")
    user_info = ""
    for row in rows:
        if (row[0] == username):
            user_info = row[2]
    if (user_info == ""):
        print("User does not exist.")
    conn.close()
    return user_info

def del_user(username):
    conn,cur = connect_db()
    print("checking for user " + str(username))
    if (check_if_username_exists(username) == True):
        cur.execute("DELETE from COMPANY_DATABASE where USERNAME = '%s'"%username)
        conn.commit()
        conn.close()
        return "Deleted user %s"%username
    else:
        conn.close()
        return "User does not exist, delete failed"

##
#   This method checks if the username exists in database before registration
##        
        
def isValidUsername(username):
    contains_weird_letter = False
    for letter in username:
        if letter in """!"#$%&()*+/:;<=>?@[\]^`{|}~ """:
            contains_weird_letter = True
    
    return not contains_weird_letter
        
#delete user from company_database: called by company frontend
@app.route("/company_del_user", methods = ['POST'])
def company_del_user():
    username = request.args.get('username')
    message = del_user(username)
    response = jsonify(message)
    if message == 'User does not exist, delete failed':
        response.status_code = 400
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

# checks if username and password exist and map in the sql
@app.route("/staff_login", methods = ['POST'])
def staff_login():
    input_username = request.args.get('u')
    input_password = request.args.get('p')
    print("RECEIVED ARGUMENTS: " + input_username, input_password)
    conn,cur,rows = select_db("*","COMPANY_LOGIN")
    response = jsonify("Wrong credentials or no such staff in the database.")
    for entry in rows:
        if (input_username == entry[0] and input_password == entry[1] and entry[2] != "true"):
            cur.execute("UPDATE COMPANY_LOGIN SET LOGGED_IN = 'true' WHERE USERNAME = '%s'"%input_username)
            conn.commit()
            conn.close()
            response = jsonify("User " + input_username + " successfully logged in.")
            response.status_code = 200
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response
    response.status_code = 400
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

# logs out
@app.route("/staff_logout", methods = ['POST'])
def staff_logout():
    input_username = request.args.get('u')
    print("RECEIVED ARGUMENT: " + input_username)
    conn,cur,rows = select_db("*","COMPANY_LOGIN")
    response = jsonify("Wrong credentials or no such staff in the database.")
    for entry in rows:
        if (input_username == entry[0] and entry[2] == "true"):
            cur.execute("UPDATE COMPANY_LOGIN SET LOGGED_IN = 'false' WHERE USERNAME = '%s'"%input_username)
            conn.commit()
            conn.close()
            response = jsonify("User " + input_username + " successfully logged out.")
            response.status_code = 200
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response
    response.status_code = 400
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

# logs out
@app.route("/is_staff_logged_in", methods = ['POST'])
def is_staff_logged_in():
    input_username = request.args.get('u')
    print("RECEIVED ARGUMENT: " + input_username)
    conn,cur,rows = select_db("*","COMPANY_LOGIN")
    response = jsonify("Wrong credentials or no such staff in the database.")
    for entry in rows:
        if (input_username == entry[0]):
            response = jsonify(entry[2]);
            response.status_code = 200
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response
    response.status_code = 400
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

##
#   This method refresh the request id database  
##
    
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

##
#   These methods is for viewing the company database
#   get_request_database: view the request id database with the corresponding public key stored
#   get_company_database: view all the users who registered the company (company database)
##

@app.route("/get_request_database",methods = ['GET'])
@requires_auth
def get_request_database():
    conn,cur,rows = select_db("*","REQUEST_DATABASE")
    print(rows)
    print(type(rows))
    response = jsonify(rows)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route("/get_company_database",methods = ['GET','OPTIONS'])
@crossdomain(origin='*',methods=['GET','OPTIONS'], headers='Authorization') 
@requires_auth
def get_company_database():
    print("in get_company_database()")
    conn,cur,rows = select_db("*","COMPANY_DATABASE")
    print(rows)
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

@app.route("/get_key",methods = ['GET'])
def get_key():

    """
    generates a new public-private key pair with a unique request_id,
    then returns a json string containing the request_id and 
    only the public_key.
    """
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
    f.write(RSA_pvt_key.exportKey('PEM', pkcs = 8))
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

    return jsonify(for_user)

##
#   This method add the new register user to the company database
##
@app.route("/register_user", methods = ['POST'])
def register_user():
    received_request = request.json
    
    request_id = received_request["request_id"] 
    print("received request_id")
    print(request_id)
    
    #delete request_id from the request received for decrpytion
    if ("request_id" in received_request):
        del received_request["request_id"]
    
    #decrypt the request received
    decrypted = decrypt_request(request_id,received_request)

    #Handle invalid request id
    if decrypted == 'Invalid Request ID':
        resp = Response(json.dumps({"Message":"Invalid request ID"}))
        resp.status_code = 400
        return resp
    
    #decrypt the user request using private key
    username = decrypted["username"]
    password = decrypted["password"]
    block_id = decrypted["block_id"]
    AES_key = decrypted["AES_key"]
    
#    private_key,AES_key,merkle_raw = get_token(block_id)
    
    if (isValidUsername(username) == False):
        resp = Response(json.dumps({"Error":"Username contains invalid characters"}))
        resp.status_code = 400
        return resp
    
    #if username already exist, don't allow the user to register
    if (check_if_username_exists(username) == True):
        resp = Response(json.dumps({"Error":"Username already exists!"}))
        resp.status_code = 409 #conflict with the current state of resources
        return resp
        
    #post request to kyc backend to retrieve user block of info
    r = requests.post("https://kyc-project.herokuapp.com/register_org", json = {"block_id":block_id})
    print(r.status_code)
    print(r.text)
        
    if (r.status_code == 200): #if success in retrieving user info from kyc
        # received ENCRYPTED user data from kyc backend
        user_data = json.loads(r.text)
        can_access = user_data["access"]
        # check if the user got report lost of token
        if (can_access):      
            user_data = user_data["userData"]
            del user_data["$class"]
            print(user_data)
           
            #decrpyt the user data with AES key
            for key in user_data:
                user_data[key] = aes_decrypt(user_data[key],AES_key)
                
                
            if(check_if_user_info_exists(user_data) == True):
                resp = Response(json.dumps({"Error":"You have already registered with this company!"}))
                resp.status_code = 409
                return resp
            else:    
                #post the user data to the company database along with password and username
                add_user_to_database(username,password,user_data)
                return "Done"
        else: 
            resp = Response(json.dumps({"Error":"The user is disabled."}))
            resp.status_code = 400
            return resp
        
    else: #if fail to retrieve the user info
        resp = Response(json.dumps(json.loads(r.text)))
        resp.status_code = r.status_code
        return resp

##
#   This method for user who wants to login to the company website by checking their username and password
##
@app.route("/login_org",methods = ['POST'])
def login_org():
    received_request = request.json
    
    request_id = received_request["request_id"] 
    print("received request_id")
    print(request_id)
    
    if ("request_id" in received_request):
        del received_request["request_id"]
    
    #decrypt the request received
    decrypted = decrypt_request(request_id,received_request)
    print(decrypted)
    
    username = decrypted["username"]
    password = decrypted["password"]
    block_id = decrypted["block_id"]
    encrypted_merkle_raw = decrypted["merkle_raw"]
        
    #post request to kyc backend to retrieve user block of info
    r = requests.post("https://kyc-project.herokuapp.com/register_org", json = {"block_id":block_id})
    data_received = json.loads(r.text)
    can_access = data_received["access"]
    
    if not can_access:
        resp = Response(json.dumps({"Error":"This user is disabled"}))
        resp.status_code = 400
        return resp
    
    
    can_login = check_for_login(username,password,bytes(java_to_python_bytes(encrypted_merkle_raw)))
    
    if (can_login):
        resp = Response(json.dumps({"Message":"Welcome %s"%username}))
        resp.status_code = 200
    else:
        resp = Response(json.dumps({"Message":"Invalid username/password."}))
        resp.status_code = 401
    print(resp)
    
    return resp
    
if __name__ == "__main__":
    app.run()
