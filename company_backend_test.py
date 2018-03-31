import unittest
import random
import string
import psycopg2
import json
import ast

DATABASE_URL = "postgres://kulppdlibhsggy:4655032868ea8a3c938e2bd5d015130b41c7810d012e8edc3518de8490bf205d@ec2-54-83-23-91.compute-1.amazonaws.com:5432/db5s1h8iuhepc"

#Connect to the postgresql database. returns the connection object and its cursor
def connect_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode = 'require')
    cur = conn.cursor()
    return conn, cur

#select database
def select_db(column,database):
    conn,cur = connect_db()
    cur.execute("SELECT %s FROM %s"%(column,database))
    rows = cur.fetchall()
    return conn,cur,rows
    
#add the decrypted user info to the company database
def add_user_to_database(username,password,user_info):
    conn,cur = connect_db()
    cur.execute("INSERT INTO COMPANY_DATABASE (USERNAME,PASSWORD,USER_INFO) \
                VALUES (%s,%s,%s)",(username,password,json.dumps(user_info)))
    conn.commit()
    conn.close()
    
#extract the user_info for respective user from database
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

def delete_user(username):
	conn,cur = connect_db()
	username = username.replace("'","''")
	cur.execute("DELETE FROM COMPANY_DATABASE WHERE USERNAME = '%s'"%username)
	conn.commit()
	conn.close()

def generate_random_userdetails():
	username_length = random.randint(5,15)
	password_length = random.randint(8,20)
	username = ""
	password = ""
	for i in range(username_length):
		username += random.choice(string.printable)

	for i in range(password_length):
		password += random.choice(string.printable)

	user_data = {}
	for i in range(6):
		length = random.randint(5,20)
		key = ""
		value = ""
		for i in range(length):
			key += random.choice(string.printable)
			value += random.choice(string.printable)
		user_data[key] = value

	return username,password,user_data


class TestDatabase(unittest.TestCase):
	##
	# Test functionality of adding and extracting information from the SQL database
	# Adds and extracts 100 sets of random data from the database 
	# Test passes if the data that was extracted is the same as the data that was entered
	##
	def testDB(self):
		for i in range(100):
			print("test %d"%i)
			username,password,user_info = generate_random_userdetails()
			add_user_to_database(username,password,user_info)
			extracted = extract_user_info(username)
			delete_user(username)
			self.assertEqual(user_info,extracted)

# if __name__ == '__main__':
# 	unittest.main()

delete_user()
