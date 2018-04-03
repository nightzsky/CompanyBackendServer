

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

    /**
     * Generates a digital signature from the given data and private key
     */
    public static byte[] sign(String inp, byte[] privateKey){
        byte[] inpBytes = inp.getBytes(StandardCharsets.UTF_8);
        try {
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(key);
            signer.update(inpBytes);
            return signer.sign();
        }
        catch (Exception e){
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
        String pubKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsuvd81pnoS599N4uOCLK1wQ+5ela2WLJ1ZFCYkv6fzZUoyVwGgBM/7N37/gfqOBV3OjHCKMgShhVL+pfh87hRKttPqrqbJAcd4Gbpyd0SnPfOiWyEpYxEgtZ6vdJLGU2NTAGT+1u64ZXe6NGsaL+bJj7rMalI4/3H9AFn2Yzq4di5PTV5gFYisjXGQ9SzR+dqptELVAkcUYPulY6P4GnjkQnahoVwYoE6CSSZmAm5vUaxbJYBiyWT3JMnSP6dTeHTdEkDE/kGuyp2XzHLb/jT2m+pT2V13YKGfzz2kZrTO3Z2WTGWEfBbPCM5zaRnOQdc63CCHit/qC7YzHjk0wD3wIDAQAB-----END PUBLIC KEY-----";
//
        String pvtKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/EQVuXbRRIrCQ\n7uDu82SuLiHRdVTG1AtDQakC2h2C7Pk5Jw6tnSwTC9CDFw6fne2lEHE5BiqYdE+c\nxYYIvQgSm8zt9ejMAbL8oFyPX9dJvKIbnUok7JkwIGemNwFw7zlnSWu+UR824uqk\nM063jP82sJqmckqLeJZ9N1frfvEd9/yxWTOm3LbmV04oQfNpgDrluLduxarRe+a5\neAhskvWEpN3Ceh0gQx1kiS277I7GxKIYsAum4G2AU4l8JgK0wH1TqVJUKOJjFtNe\nJ5XGVdLXOQSv7RBF5Z3uxpgTc3NfCjD6Woclnpvs+hhoPY0/Pa8o6UsholpbUFel\nxY94YXIVAgMBAAECggEAHKRwFH3umJUjM+7jgF6zUpsuzagRp+bEs3Xl4LwS3Xwp\n1kQBIsyjfU1xmh08P3hc1jhTSNGgVA9nmeBQegHgcm2xuGB7YA3HJ7Dgf0vGSdMB\n2DLpmQRw6HKLJzMqv6PVDqNGiBbAH6m/tBLO85wq7CdoX5hVjXfr02SXBQIYIj42\naa9zJLlOp5o+1EGD447+M9viB1FxoCmnAB/ZWBcECz9J4Z21mJa/Hqi7UnPHuc3z\ndoR4zY8Tqm0sKjtzOMVj399t/PvrBbmmMrfX6luONQUQr/P5tW++HB9EjigU44mE\n8Cj5hr+jXqYJtk7X/CylLqjvMketUzVLo5k18i7QVwKBgQDDDxdwJN3nkEWwQX6F\nrkMrxlmELsQeVaw34qJfAhtL1QkR62a0CvltK6XndyOSIM+DEoO1+jhmy0P1eMd6\nBILHolZa8FrTz+JDq5pUH0VMcuwv53UHi0NQ8DkNe5QCDdQRj7wLMQduJqZyxI8d\nEv2QF6cYyRpZ9qy2KgyDzj78XwKBgQD6wpxROpzWbRfR+hbE53lPTjh+uELgOqJ7\neRjt9hK2ndeEKLKuI+j7+SfOQcktfZBnGXUQtoWtQ/ac5rQHdul9HYuRA1Ewrig5\npYxQngX/AlShRG6pi0NYw0M/VCV1GwBn/pMhoo7Ps0tWn+bRjGyyNH+ADmAeO1J6\nsyM6WVmmCwKBgB8Wb6ja51b5onG17oFFxcTbRvcPMQiYpOr/PtufjVQnrtthRiwZ\nt6kTlMxwK4Ylno0ITV+acpTHfpxH1Jr4zxMcJ2E0/3TUo/4fAmi31yaZBlWYMQmz\nw1XKA33HnU46f/sQimrKNKH0nQCbnSeIGEt3yZTksEN4UgxyZS44l8dHAoGBAMF2\nV6eLsujz7cbATcTIWR1IWenaOy5Hzoe4W/VrPfDKQjXiOEiFyABur7k/o/iGwVvp\nlhm419Vfc+qFSyvfIDC5FK5igsct9jbTdDfWUwX1RFnPNBl2KhVXQJChWOzKUjvp\nepYellPEHkHMyAWvc0Thn+SqMpngZrfncSxZNwMVAoGAXhzFfH2DaOaRbKOPOyUT\nwWhHCTWVE3SWvhpzo2VUf0CayoMLqxWbzCR0VmR4tmjMgzYtIUG3jivmQS5ZbEiC\n7iOnzKvDt2MViBG/Lwks9kocmxBjXowJlrvdcCbxnGxiScCP/2P54fDhr87lbIUb\n1bSwhBdSZMBmMDTDUiAMeQY=\n-----END PRIVATE KEY-----";
//        byte[][] cipherText = rsaEncrypt("Hello World", pemToBytes(pubKey));
//        System.out.println("Printing ciphertext");
//        System.out.println(Arrays.deepToString(cipherText));
        String signature = Arrays.toString(sign("846796410f5f108a7c1fb71abf0c5bdce6f45836f1dac54f7e7dab428121ffbb",pemToBytes(pvtKey)));
        System.out.println(signature);



    }
}
