import org.json.JSONObject;
import org.junit.Test;
import org.seleniumhq.jetty9.server.Authentication;

import static org.junit.Assert.*;
/**
 * Class which tests the user login to a company service
 */
public class UserLoginCompanyTest {
    /**
     * Tests successful login with correct username and password
     * Creates a user, tries to login with it, then deletes the user afterwords
     */
    @Test
    public void testCorrectLogin(){
        //create the new user and ensure that user creation is successful
        String request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");
        JSONObject requestJson = new JSONObject(request_and_key);
        String str_pub_key = requestJson.get("public_key").toString();
        String request_id = requestJson.get("request_id").toString();
        int responseCode = UserRegisterCompany.registerCompany("username", "password", "04d2a86fdff20c15dd4e16435ee643b194ea6e928ef4fe4695f1464977142646","[89, 247, 59, 84, 13, 113, 250, 217, 152, 163, 247, 100, 154, 9, 42, 124, 138, 38, 86, 33, 17, 219, 40, 105, 135, 8, 140, 14, 54, 210, 100, 130]",request_id,str_pub_key);
        assertEquals(200,responseCode);

        //attempt login and ensure it is successful
        responseCode = UserLoginCompany.login("username", "password");
        try {
            assertEquals(200,responseCode);
        }
        //delete user after completion
        finally {
            responseCode = UserRegisterCompany.deleteUser("username");
            assertEquals(200,responseCode);
        }
    }

    /**
     * Tests unsuccessful logins
     * Unsuccessful logins could be due to incorrect username, or incorrect password
     */
    @Test
    public void testIncorrectLogin(){
        //create the new user and ensure that user creation is successful
        String request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");
        JSONObject requestJson = new JSONObject(request_and_key);
        String str_pub_key = requestJson.get("public_key").toString();
        String request_id = requestJson.get("request_id").toString();
        int responseCode = UserRegisterCompany.registerCompany("username", "password", "04d2a86fdff20c15dd4e16435ee643b194ea6e928ef4fe4695f1464977142646","[89, 247, 59, 84, 13, 113, 250, 217, 152, 163, 247, 100, 154, 9, 42, 124, 138, 38, 86, 33, 17, 219, 40, 105, 135, 8, 140, 14, 54, 210, 100, 130]",request_id,str_pub_key);
        assertEquals(200,responseCode);

        try {
            //attempt login with wrong username
            responseCode = UserLoginCompany.login("username!", "password");
            assertEquals(401, responseCode);

            //attempt login with wrong password
            responseCode = UserLoginCompany.login("username", "passw0rd");
            assertEquals(401, responseCode);
        }
        finally{
            responseCode = UserRegisterCompany.deleteUser("username");
            assertEquals(200,responseCode);
        }

    }
}
