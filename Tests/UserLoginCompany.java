import jdk.nashorn.internal.ir.Block;
import org.json.JSONObject;

/**
 * Class which helps a user login into a company which they have registered for
 */
public class UserLoginCompany {
    public static int login(String username, String password){
        String request_and_key = UserRegisterCompany.httpGet("https://shielded-bayou-99151.herokuapp.com/get_key");

        //convert into jsonObject
        JSONObject requestJson = new JSONObject(request_and_key);
        String str_pub_key = requestJson.get("public_key").toString();
        String request_id = requestJson.get("request_id").toString();

        byte[] publicKeyByte = BlocktraceCrypto.pemToBytes(str_pub_key);

        JSONObject loginObject = new JSONObject();
        loginObject.put("username", username);
        loginObject.put("password", BlocktraceCrypto.hash256(password));
        loginObject.put("request_id", request_id);
        JSONObject encrypted_info = UserRegisterCompany.encryptJson(loginObject,publicKeyByte);

        int result = UserRegisterCompany.httpPost("https://shielded-bayou-99151.herokuapp.com/login_org", encrypted_info);

        return result;

    }
}

