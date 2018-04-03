import jdk.nashorn.internal.ir.Block;
import org.json.JSONObject;

import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Class which helps a user login into a company which they have registered for
 */
public class UserLoginCompany {
    public static int login(String username, String password, String merkle, String privateKey, String blockId){
        String request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");
        //convert into jsonObject
        JSONObject requestJson = new JSONObject(request_and_key);
        String str_pub_key = requestJson.get("public_key").toString();
        String request_id = requestJson.get("request_id").toString();

        byte[] publicKeyByte = BlocktraceCrypto.pemToBytes(str_pub_key);
        String signature = Arrays.toString(BlocktraceCrypto.sign(merkle,BlocktraceCrypto.pemToBytes(privateKey)));

        JSONObject loginObject = new JSONObject();
        loginObject.put("username", username);
        loginObject.put("password", BlocktraceCrypto.hash256(password));
        loginObject.put("request_id", request_id);
        loginObject.put("merkle_raw", signature);
        loginObject.put("block_id", blockId);
        JSONObject encrypted_info = UserRegisterCompany.encryptJson(loginObject,publicKeyByte);

        int result = UserRegisterCompany.httpPost("https://shielded-bayou-99151.herokuapp.com/login_org", encrypted_info);

        return result;

    }

    public static void main(String[] args) {


    }
}

