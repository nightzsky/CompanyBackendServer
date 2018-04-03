import java.nio.charset.Charset;
import java.util.Random;

/**
 * Class meant for generating random inputs for testing purposes
 */
public class RandomInput {

    //randomly generates a string of length 0-1024
    public static String randomString(){
        int length = new Random().nextInt(1024);
        byte[] array = new byte[length];
        new Random().nextBytes(array);
        String generatedString = new String(array, Charset.forName("UTF-8"));
        return generatedString;
    }
}
