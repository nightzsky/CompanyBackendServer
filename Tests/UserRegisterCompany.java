import jdk.nashorn.internal.ir.Block;
import org.json.JSONObject;

import javax.swing.text.html.HTML;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Iterator;

/**
 * Class used to register for a company
 * It contains methods to register for the company via HTTP POST to the backend server
 * It also contains a method to delete a user who has already registered previously
 */
public class UserRegisterCompany {
    //get method
    public static String httpGet(String urlString){
        HttpURLConnection urlConnection = null;
        try {
            //set up the connection to the URL
            URL url = new URL(urlString);
            urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestMethod("GET");

            //get the response message
            int responseCode = urlConnection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
                StringBuilder data_received = new StringBuilder("");
                String line = "";

                while ((line = in.readLine()) != null) {
                    data_received.append(line);
                }
                in.close();
                //disconnect with the url after done
                urlConnection.disconnect();

                return data_received.toString();
            } else {
                return "False: " + responseCode;
            }
        }catch (Exception ex){
            return "Exception: " + ex.getMessage();
        }
    }

    //post method
    public static int httpPost(String urlString, JSONObject jsonObject){
        HttpURLConnection urlConnection = null;
        try {
            //set up the connection to the URL
            URL url = new URL(urlString);
            urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("Content-Type", "application/json");
            urlConnection.setDoOutput(true);
            urlConnection.setDoInput(true);

            //write the output to the url and send JSONObject to the url
            OutputStreamWriter wr = new OutputStreamWriter(urlConnection.getOutputStream());
            wr.write(jsonObject.toString());
            wr.flush();

            //get the response message
            int responseCode = urlConnection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {

                //disconnect with the url after done
                urlConnection.disconnect();

                return responseCode;
            }
            else {
                BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getErrorStream()));
                StringBuilder message = new StringBuilder("");
                String line = "";

                while ((line = in.readLine())!= null){
                    message.append(line);
                }
                in.close();
                urlConnection.disconnect();
                System.out.println(message);
                return responseCode;
            }

        } catch (Exception ex) {
            ex.printStackTrace();
            return 0;
        }
    }

    public static JSONObject encryptJson(JSONObject plainJson, byte[] public_key){
        JSONObject encrypted_info = new JSONObject();
        try {
            Iterator<String> keys = plainJson.keys();
            while (keys.hasNext()){
                String k = keys.next();
                if (k.equals("request_id")){
                    encrypted_info.put(k,plainJson.get(k));
                }
                else {
                    String encryptedKey = Arrays.deepToString(BlocktraceCrypto.rsaEncrypt(k, public_key));
                    String encryptedValue = Arrays.deepToString(BlocktraceCrypto.rsaEncrypt(plainJson.getString(k), public_key));
                    encrypted_info.put(encryptedKey, encryptedValue);
                }
            }
        } catch (Exception ex){
            ex.printStackTrace();
        }
        return encrypted_info;
    }

    public static int registerCompany(String username, String password, String blockId, String aesKey, String request_id, String public_key) {
        //get the public key from company backend and convert into byte[] for encryption the request
        try {
            byte[] publicKeyByte = BlocktraceCrypto.pemToBytes(public_key);

            //create jsonobject
            JSONObject register_org_info = new JSONObject();
            register_org_info.put("request_id", request_id);
            register_org_info.put("username", username);
            register_org_info.put("password", BlocktraceCrypto.hash256(password));
            register_org_info.put("block_id", blockId);
            register_org_info.put("AES_key", aesKey);

            //encrypt the data that is going to be sent to company backend
            JSONObject encrypted_info = encryptJson(register_org_info, publicKeyByte);

            int result = httpPost("https://shielded-bayou-99151.herokuapp.com/register_user", encrypted_info);

            return result;

        } catch (Exception ex) {
            ex.printStackTrace();
            return 0;
        }
    }

    public static int deleteUser(String username){
        HttpURLConnection urlConnection = null;
        try{
            username = URLEncoder.encode(username,"UTF-8");
            URL url = new URL("http://shielded-bayou-99151.herokuapp.com/company_del_user?username=" + username);
            urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("Content-Type", "application/json");
            urlConnection.setDoOutput(true);
            urlConnection.setDoInput(true);
            int responseCode = urlConnection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK){
                BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getErrorStream()));
                StringBuilder message = new StringBuilder("");
                String line = "";

                while ((line = in.readLine())!= null){
                    message.append(line);
                }
                in.close();
                System.out.println(message);
            }
            urlConnection.disconnect();
            return urlConnection.getResponseCode();
        }
        catch (Exception e){
            e.printStackTrace();
            return 0;
        }
        finally {
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }
    }


}
