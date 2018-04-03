import jdk.nashorn.internal.ir.Block;
import org.json.JSONObject;
import org.yaml.snakeyaml.tokens.BlockEndToken;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;

/**
 * Class which encrypts requests for the KYC backend server
 */
public class EncryptRequest {
    //Gets the public key used to encrypt requests to the kyc backend server
    public static String getKycPublicKey(){
        StringBuilder result = new StringBuilder();
        try {
            URL url = new URL("https://kyc-project.herokuapp.com/getkey");
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestMethod("GET");
            BufferedReader rd = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String line;
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }
            rd.close();
        }

        catch (Exception e){
            e.printStackTrace();
        }
        return result.toString();
    }

    public static JSONObject encryptRequest(JSONObject json){
        JSONObject encrypted = new JSONObject();
        String pubKeyString = getKycPublicKey();
        byte[] pubKeyBytes = BlocktraceCrypto.pemToBytes(pubKeyString);
        for (String k:json.keySet()) {
            String encryptedKey = Arrays.deepToString(BlocktraceCrypto.rsaEncrypt(k, pubKeyBytes));
            String encryptedValue = Arrays.deepToString(BlocktraceCrypto.rsaEncrypt(json.getString(k),pubKeyBytes));
            encrypted.put(encryptedKey,encryptedValue);
        }
        return encrypted;
    }
}
