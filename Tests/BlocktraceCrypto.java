

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

}
