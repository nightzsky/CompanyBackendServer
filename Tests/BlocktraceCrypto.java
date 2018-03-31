

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * AES/RSA cryptographic implementations
 * Contains methods for both encryption and decryption
 */
public class BlocktraceCrypto {
    /*
     * Takes a string and a AES key, and encrypts the data with AES
     * Returns the encrypted data
     */
    public static byte[] aesEncrypt(String data, byte[] key){
        byte[] output = null;
        try {
            Cipher AesCipher = Cipher.getInstance("AES/CFB8/NoPadding");
            SecureRandom randomIvGen = new SecureRandom();
            byte[] iv = new byte[AesCipher.getBlockSize()];
            randomIvGen.nextBytes(iv);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key,"AES");
            AesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParams);
            output = concatArray(iv,AesCipher.doFinal(data.getBytes("UTF-8")));
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return output;
    }

    /*
     * Takes a data encrypted by AES and decrypts it with the given key
     * Returns the decrypted data
     */
    public static String aesDecrypt(byte[] data, byte[] key){
        String output = "";
        try {
            Cipher aesCipher = Cipher.getInstance("AES/CFB8/NoPadding");
            byte[] iv = new byte[aesCipher.getBlockSize()];
            byte[] actualData = new byte[data.length - aesCipher.getBlockSize()];
            System.arraycopy(data,aesCipher.getBlockSize(),actualData,0,data.length-aesCipher.getBlockSize());
            System.arraycopy(data,0,iv,0,aesCipher.getBlockSize());
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            aesCipher.init(Cipher.DECRYPT_MODE,secretKeySpec,ivParams);
            byte[] decrypted = aesCipher.doFinal(actualData);
            output = new String(decrypted,"UTF-8");
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return output;
    }

    /*
     * Takes a string and RSA public key and encrypts the data
     * More precisely, it encrypts an AES key using RSA, and encrypts the actual data using AES
     */
    public static byte[][] rsaEncrypt(String data, byte[] publicKey){
        byte[][] output = new byte[2][];
        try{
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
            rsaCipher.init(Cipher.ENCRYPT_MODE, key);
            SecureRandom sr = new SecureRandom();
            byte[] aesKey = new byte[16];
            sr.nextBytes(aesKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey);
            byte[] encryptedData = aesEncrypt(data,aesKey);
            output[0] = encryptedData;
            output[1] = encryptedAesKey;

        }
        catch (Exception e){
            e.printStackTrace();
        }
        return output;
    }

    /*
     * Decrypts a byte array encrypted with the RSA-AES hybrid encryption using the RSA private key
     * Returns the decrypted data
     */
    public static String rsaDecrypt(byte[][] data, byte[] privateKey){
        String output = "";
        try {
            byte[] encryptedAesKey = data[1];
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE,key);
            byte[] decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);
            byte[] encryptedData = data[0];
            output = aesDecrypt(encryptedData,decryptedAesKey);

        }
        catch (Exception e){
            e.printStackTrace();
        }
        return output;
    }

    /*
     * Takes two byte arrays and concatenates them
     * Returns the concatenated array
     */
    public static byte[] concatArray(byte[] array1, byte[] array2){
        byte[] output = new byte[array1.length+array2.length];
        System.arraycopy(array1,0,output,0,array1.length);
        System.arraycopy(array2,0,output,array1.length,array2.length);
        return output;
    }

    /*
     * converts a RSA public/private key in pem format to a byte array
     */
    public static byte[] pemToBytes(String key){
        String[] parts = key.split("-----");
        return DatatypeConverter.parseBase64Binary(parts[parts.length / 2]);
    }

    /**
     * Hashes a string using the SHA256 hashing algorithm
     * Returns a hex version of the hashed bytes
     */
    public static String hash256(String inp){
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = digest.digest(inp.getBytes(StandardCharsets.UTF_8));
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < encoded.length; i++) {
                String hex = Integer.toHexString(0xff & encoded[i]);
                if(hex.length() == 1) output.append('0');
                output.append(hex);
            }
            return output.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

    }

    public static void main(String[] args) {
        SecureRandom sr = new SecureRandom();
        byte[] keyBytes = new byte[16];
        sr.nextBytes(keyBytes);
//        System.out.println("Printing key");
//        System.out.print("[");
//        for (int i = 0; i < keyBytes.length; i++){
//            System.out.print(keyBytes[i] + ", ");
//        }
//        System.out.println("]");
//        String pubKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsuvd81pnoS599N4uOCLK1wQ+5ela2WLJ1ZFCYkv6fzZUoyVwGgBM/7N37/gfqOBV3OjHCKMgShhVL+pfh87hRKttPqrqbJAcd4Gbpyd0SnPfOiWyEpYxEgtZ6vdJLGU2NTAGT+1u64ZXe6NGsaL+bJj7rMalI4/3H9AFn2Yzq4di5PTV5gFYisjXGQ9SzR+dqptELVAkcUYPulY6P4GnjkQnahoVwYoE6CSSZmAm5vUaxbJYBiyWT3JMnSP6dTeHTdEkDE/kGuyp2XzHLb/jT2m+pT2V13YKGfzz2kZrTO3Z2WTGWEfBbPCM5zaRnOQdc63CCHit/qC7YzHjk0wD3wIDAQAB-----END PUBLIC KEY-----";
//
//        String pvtKey = "-----BEGIN PRIVATE KEY-----MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCy693zWmehLn303i44IsrXBD7l6VrZYsnVkUJiS/p/NlSjJXAaAEz/s3fv+B+o4FXc6McIoyBKGFUv6l+HzuFEq20+qupskBx3gZunJ3RKc986JbISljESC1nq90ksZTY1MAZP7W7rhld7o0axov5smPusxqUjj/cf0AWfZjOrh2Lk9NXmAViKyNcZD1LNH52qm0QtUCRxRg+6Vjo/gaeORCdqGhXBigToJJJmYCbm9RrFslgGLJZPckydI/p1N4dN0SQMT+Qa7KnZfMctv+NPab6lPZXXdgoZ/PPaRmtM7dnZZMZYR8Fs8IznNpGc5B1zrcIIeK3+oLtjMeOTTAPfAgMBAAECggEABRnlc5U9xCIrtCoLfk07pEK6OlrbXLxMzdp83omVBEB7zET6e7tLdrTatAxKdsmimRBH8G6aMpKcBygy/g+/a3JJxJIh6eN39E5NLkhZL/A6ypEdkRsYHhAVybWwL+RY1c5fN7MoyO1FHEDM+K6Re24nKsdlGOz3WkBXkLJcwcSnroqsuNZE9JC3Wrgvh/FBAsKhLmwCWwfzZ5oWZEVDAfkDEMne0Kqk8vEXr5iRWV+o+XpS2VuNquSORZjYz4JyGaBggNrXTrL0xRJ4iqIX0/Vxz+29e24zTq4jsWeGNGOxHuYE06Wyg3VRFJP2VUrYByeCZ89j3juTxEEgBDLktQKBgQDOlw/CpWv0kX7tBusd10poHcZJ10DTuFMsb5vJ+IxAY4jJeYZbVegly5FyLyJ5bH7GxWOlZDeg3s88KFGmCTQcPPgHxwlPRD97V4Ryj7y57SFmcBhnGqq/tgI60nDLBb3LmCGqcplOac35GPa9P0mEC5Y85Ev6y98kEhVkF+kylQKBgQDdtrnQHdpnFEF/1Gno5zPR3+iCcmT52orWv5jw4QDfojNP/gM9Hwzb8tmZX7Eu5AaeYLhsZBxp54eSUbswImef8O2k1gvZ4qDsd0AbeHQhXKC/DLh6jFYvNfOvKPXx8mTNcAgHDJaoA10ko0qYzPenCgfTDiTvQnN/FuXLaKDTowKBgCv8mgx1sFC4ke/h4znNVzhn7opWXKU3v+3cLa2JUEN9beiICYV0+yLg/yzywEJeSXgFGzxh5D5KcpF6fDgACaphiOYPCPppq6KVdcv2stZbmRr4jxmU4fpDxKHFoOJ5bHnnAHQMRnwdpw98szyENyD4XprEeTEDK5XAi/Ft7ecpAoGASQhr5NYwn0vY15bM3F9sfnHXUUEFahhHK74pTw+PDhuL84mk33le7wTsEM2ou915IKqTlYDUqz4NNnGdy5lJsTHX1jh75uX0RHBzuZjQCD1O5h/2lMetjBelkclYWr6R3epNeqT265lQEUWIyRSbb3aqZSd/myC0kuSkBYENmSkCgYB2pjxzxPAEfTU3Fi0q58vbrd4IFfcw0d55WBzwdAwYLHVmHDO+4eUtqz+FnQO+TmzQQcJl434KVaGoA5bedUiMC2dS0LAFv0XvMxZ/frGI5RK6yNRa3RyeqQlQnqr48/3nNyjQkQ9iOiPKP8KX88RHu4SPPL0QAz8MSJvGk0U6kA==-----END PRIVATE KEY-----";
//        byte[][] cipherText = rsaEncrypt("Hello World", pemToBytes(pubKey));
//        System.out.println("Printing ciphertext");
//        System.out.println(Arrays.deepToString(cipherText));
        System.out.println(hash256("Hello World"));



    }
}
