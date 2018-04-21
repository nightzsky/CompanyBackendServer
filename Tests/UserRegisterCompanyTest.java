import org.json.JSONObject;
import org.junit.Test;

import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;

import static org.junit.Assert.*;

/**
 * Tests the registration of users with companies
 * Users must already be registered with blocktrace
 * Users are deleted immediately after they are added
 * Users used here to test have been previously registered with blocktrace beforehand
 */
public class UserRegisterCompanyTest {
    //function which revokes or reactivates the token of a specified user, used for tests later
    static int revokeToken(String blockId){
        HttpURLConnection urlConnection = null;

        try {
            URL url = new URL("https://kyc-project.herokuapp.com/token_lost");
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("block_id", blockId);

            JSONObject encryptedJSON = EncryptRequest.encryptRequest(jsonObject);

            urlConnection = (HttpURLConnection) url.openConnection();
            //set the request method to Post
            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("Content-Type","application/json");
            urlConnection.setDoInput(true);
            urlConnection.setDoOutput(true);


            //output the stream to the server
            OutputStreamWriter wr = new OutputStreamWriter(urlConnection.
                    getOutputStream());
            wr.write(encryptedJSON.toString());
            wr.flush();

            int responseCode = urlConnection.getResponseCode();
            return responseCode;
        }catch (Exception ex){
            ex.printStackTrace();
            return 0;
        }
    }
    static int reactivateToken(String blockId){
        HttpURLConnection urlConnection = null;

        try {
            URL url = new URL("https://kyc-project.herokuapp.com/token_found");
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("block_id", blockId);

            JSONObject encryptedJSON = EncryptRequest.encryptRequest(jsonObject);

            urlConnection = (HttpURLConnection) url.openConnection();
            //set the request method to Post
            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("Content-Type","application/json");
            String encoded = Base64.getEncoder().encodeToString(("admin"+":"+"secret").getBytes(StandardCharsets.UTF_8));  //Java 8
            urlConnection.setRequestProperty("Authorization", "Basic "+encoded);
            urlConnection.setDoInput(true);
            urlConnection.setDoOutput(true);
            urlConnection.setDoInput(true);
            urlConnection.setDoOutput(true);


            //output the stream to the server
            OutputStreamWriter wr = new OutputStreamWriter(urlConnection.
                    getOutputStream());
            wr.write(encryptedJSON.toString());
            wr.flush();

            int responseCode = urlConnection.getResponseCode();
            return responseCode;
        }catch (Exception ex){
            ex.printStackTrace();
            return 0;
        }
    }
    @Test
    public void testCorrectRegistration(){
        String request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");

        //convert into jsonObject
        JSONObject requestJson = new JSONObject(request_and_key);
        String str_pub_key = requestJson.get("public_key").toString();
        String request_id = requestJson.get("request_id").toString();

        int responseCode = UserRegisterCompany.registerCompany("username", "password", "04d2a86fdff20c15dd4e16435ee643b194ea6e928ef4fe4695f1464977142646","[89, 247, 59, 84, 13, 113, 250, 217, 152, 163, 247, 100, 154, 9, 42, 124, 138, 38, 86, 33, 17, 219, 40, 105, 135, 8, 140, 14, 54, 210, 100, 130]",request_id,str_pub_key);
        assertEquals(200, responseCode);

        //delete user
        responseCode = UserRegisterCompany.deleteUser("username");
        assertEquals(200,responseCode);
    }

    //Tests request IDs which are not valid
    @Test
    public void testIncorrectRequestId(){
        String request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");
        //convert into jsonObject
        JSONObject requestJson = new JSONObject(request_and_key);
        String str_pub_key = requestJson.get("public_key").toString();
        String request_id = requestJson.get("request_id").toString();

        int responseCode = UserRegisterCompany.registerCompany("username1", "password", "7f4004c07d63cdc52e3a90a50b1a85a39d89c685dbae4e9dcc6705558487ddf2","[100, 165, 19, 52, 211, 98, 58, 177, 87, 99, 109, 247, 128, 190, 231, 242, 61, 102, 136, 3, 94, 177, 13, 91, 30, 49, 214, 249, 23, 155, 6, 215]","9999",str_pub_key);
        assertEquals(400, responseCode);
    }

    /**
     * Test that ensures repeated registrations get rejected by the server
     * There are two possible ways of repetition: registering with a username that is used,
     * or registering using a block id that has already been used before
     */
    @Test
    public void testRepeatedRegistration(){
        String request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");
        //convert into jsonObject
        JSONObject requestJson = new JSONObject(request_and_key);
        String str_pub_key = requestJson.get("public_key").toString();
        String request_id = requestJson.get("request_id").toString();

        //test repeated registration with same block id
        int responseCode = UserRegisterCompany.registerCompany("username1", "password", "5c5bc59bc2723b932c863414360914d5000078ef6674d7c6282667749850b204","[209, 198, 250, 133, 134, 26, 65, 213, 74, 179, 138, 149, 91, 61, 73, 3, 190, 241, 19, 132, 59, 5, 42, 61, 117, 251, 1, 217, 147, 27, 5, 49]",request_id,str_pub_key);
        assertEquals(200,responseCode);
        request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");
        //convert into jsonObject
        requestJson = new JSONObject(request_and_key);
        str_pub_key = requestJson.get("public_key").toString();
        request_id = requestJson.get("request_id").toString();
        responseCode = UserRegisterCompany.registerCompany("username2", "password", "5c5bc59bc2723b932c863414360914d5000078ef6674d7c6282667749850b204","[209, 198, 250, 133, 134, 26, 65, 213, 74, 179, 138, 149, 91, 61, 73, 3, 190, 241, 19, 132, 59, 5, 42, 61, 117, 251, 1, 217, 147, 27, 5, 49]",request_id,str_pub_key);
        assertEquals(409, responseCode);

        //test repeated registration with same username
        request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");
        //convert into jsonObject
        requestJson = new JSONObject(request_and_key);
        str_pub_key = requestJson.get("public_key").toString();
        request_id = requestJson.get("request_id").toString();
        responseCode = UserRegisterCompany.registerCompany("username1", "password", "7f4004c07d63cdc52e3a90a50b1a85a39d89c685dbae4e9dcc6705558487ddf2","[143, 143, 27, 59, 13, 30, 96, 133, 215, 218, 132, 228, 102, 72, 44, 142, 119, 251, 136, 78, 95, 248, 136, 198, 30, 187, 181, 159, 69, 143, 107, 37]",request_id,str_pub_key);
        assertEquals(409, responseCode);

        //delete user
        responseCode = UserRegisterCompany.deleteUser("username1");
        assertEquals(200,responseCode);
    }

    /**
     * Test invalid usernames
     * Usernames are invalid if they contain whitespace or symbols
     */
    @Test
    public void testInvalidUsernames(){
        int responseCode;
        String request_and_key;
        JSONObject requestJson;
        String str_pub_key;
        String request_id;
        String[] invalidCharacters = new String[] {"!","#","$","%","&","(",")","*","+","/",":",";","<","=",">","?","@","[","\\","]","^","`","{","|","}","~"," ", "\""};
        //Try registering with usernames using all possible invalid characters
        for (String invalid : invalidCharacters){
            request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");
            requestJson = new JSONObject(request_and_key);
            str_pub_key = requestJson.get("public_key").toString();
            request_id = requestJson.get("request_id").toString();
            responseCode = UserRegisterCompany.registerCompany("user" + invalid + "name", "password", "7f4004c07d63cdc52e3a90a50b1a85a39d89c685dbae4e9dcc6705558487ddf2","[143, 143, 27, 59, 13, 30, 96, 133, 215, 218, 132, 228, 102, 72, 44, 142, 119, 251, 136, 78, 95, 248, 136, 198, 30, 187, 181, 159, 69, 143, 107, 37]",request_id,str_pub_key);
            assertEquals(400, responseCode);
        }
    }

    //Test which ensures that a revoked token cannot be used to register for a company
    @Test
    public void testRevokeTokenRegistrationDenied(){
        int responseCode = revokeToken("04d2a86fdff20c15dd4e16435ee643b194ea6e928ef4fe4695f1464977142646");
        //ensure token revocation is successful
        assertEquals(200,responseCode);
        String request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");

        //convert into jsonObject
        JSONObject requestJson = new JSONObject(request_and_key);
        String str_pub_key = requestJson.get("public_key").toString();
        String request_id = requestJson.get("request_id").toString();

        responseCode = UserRegisterCompany.registerCompany("username", "password", "04d2a86fdff20c15dd4e16435ee643b194ea6e928ef4fe4695f1464977142646","[89, 247, 59, 84, 13, 113, 250, 217, 152, 163, 247, 100, 154, 9, 42, 124, 138, 38, 86, 33, 17, 219, 40, 105, 135, 8, 140, 14, 54, 210, 100, 130]",request_id,str_pub_key);
        try {
            assertEquals(400, responseCode);
        }
        finally{
            reactivateToken("04d2a86fdff20c15dd4e16435ee643b194ea6e928ef4fe4695f1464977142646");
        }
    }

    //Robustness test which attempts user registration with lots of random inputs
    @Test
    public void testRobustnessRegistration(){
        for (int i = 0; i < 100; i++) {
            int responseCode = 0;
            String username = "";
            try {
                username = RandomInput.randomString();
                responseCode = UserRegisterCompany.registerCompany(username, RandomInput.randomString(), RandomInput.randomString(), RandomInput.randomString(), RandomInput.randomString(), RandomInput.randomString());
            } catch (Exception e) {

            }
            try {
                if (responseCode != 0)
                    assertFalse(responseCode == 200);
            } catch (Exception e) {
                UserRegisterCompany.deleteUser(username);
            }
        }
    }
}
