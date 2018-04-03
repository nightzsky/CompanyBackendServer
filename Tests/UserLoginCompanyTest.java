import org.json.JSONObject;
import org.junit.Test;
import org.seleniumhq.jetty9.server.Authentication;

import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.*;
/**
 * Class which tests the user login to a company service
 * User account used for login is created beforehand
 */
public class UserLoginCompanyTest {
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
    /**
     * Tests successful login with correct username and password
     * The account use is an account that was created beforehand
     */
    @Test
    public void testCorrectLogin(){
        int responseCode = UserLoginCompany.login("InfinityWar",
                "byebye",
                "4fb455fc94279ec6b70301bc9108920c3c221430475de5fad15b854673f9d786",
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwPxRNM32MW2j5\ng/HlGSnx2oJ6cgNkNlMZ7Ad3mdtkux8SoaLrV9c54ru7JcNx+M81mBvtDP4wlWzD\n0gfT62ATsAcs0HwM/Qn7xQw6ra/tkK7Kuj1R37VWT+zyFDwFV5Z6KwFRn7xBFJBT\niL1ikBi/LAnq55AmslhToFBwfh68UCJQ6fl3oaQxkIV30nC/au91NhBphw1WQXiS\nynuYRlz4XNCV1nbzOwRpdMna+sDctjQDw721YxrQ/exsugyRfMF2aOsVHQsCRk+0\ndZc7Cobz8LGxrs1ubdUO4cOFl4L4vo53BmxzE5k1UiE9jtSEjQb2LbhE7Wb/hsN5\n33h3NnUBAgMBAAECggEAAOm8Hi5sNPppWARgafLMtoXapePBRKIoMXlVPmntD7q9\nNm49EpVOP06zVQjTAioqMJMBETgFXS4NXNsttdfkddxmPH3AWGPZSN4u6xL+uSw0\nDrso1p24MwMuqCw7jYYALL4EPpGDZ+RfYzCFTbRjKY6O1vBC/Td0mhL9rvAhMp3E\n5sFZ4SnvmgRmGhKOkGgFF93w6M5y2e3vC+4xhJZ0jITNQO8bUpP5Sz7fTJiAtLlO\nDrlVlPZDAJ+zLojswx3/jr5v1bK1T1VCwnUbhtGxxSrgimSKjpSsBzZKWlOxk3+I\nm+aBY6zyJdi7aehyp4r+h6W82O1ED4hqJc9nJGoUgQKBgQC3IvZkb2KA+hSnPelJ\n1wHMUJN4ze+vw8HBopXELbQnB5QcJVp8xyz5kUuVKwrQFkZUavHc3VOMYbDuY8lS\nv8ORwdXoWkgIAPWzzffvg6eBwEuzz2hc3dU8dfDHoRC9vAvLrdxJJZ/mVdvWqXKV\na0XmvQnZUiSPwzbMr6tHGXxggQKBgQD2XlTYUABOOd6LeZ5mVtGtW5hB5bkegI7r\nW4uXxsWYD5yVOntZC/q4+nM+dHWHwiVpoMKFGA80yooOdtq9r/LwOCg7bw+Dkmmy\n9qrQmfLF33PwxgOInpvTGs6dX5TSlSNEPxQcgmZS934/fgkZ5JnzI7ap7hwzRHXc\nAV6B8B/UgQKBgGcdu4hfoyImLZzhYkreUjfdoruhkPTxj1ZdGmDkrwxO2xlh+upJ\nJ8y5/8nU+3ihIiaENPz8bf+cPghsjT4XlaGrd6slsms3RyFfttvY0Gdhg/6RqRyp\nF1i8u79btFZw3F9p3KAfHEKQU4Ex1b/GMAy0oigIdWexLljgDNuywPKBAoGAc86H\np16DpkHBgGJcuNJaoViKy38Gc3YOuEdB6MhAnWfJPMROst7UrhrcDSGFFZmHKI2u\nog1bKH+EQaRQ0hVg5tYe40EjU7+A++TDCmczHRwaTbVmd9PGf4b8VDFXrVz5RN05\nwOTy4FECASpncMpqK0ZAWMRacSbfF9l06TNMYwECgYEAruQeVz0/zZO4m4ngvG/B\nb8Ua68uJHwuWqQgteKHt6+FY+ppDmAHDLXYkHL3SrJFDV0Y4zNiSBX2SpCErj8yy\ntOKhSPckqSZON6fQuf9tDyLUEMT2Q1THMymi6Mra833W5zpeK6BQPAOERMMrsqNl\n5j29LX39eqNdFkvPkX22U+Q=\n-----END PRIVATE KEY-----",
                "8752337d9dfa5bff1e82deba44e7156e10ec5144c85682aae70c30d41aaa0125");
        assertEquals(200,responseCode);
    }

    /**
     * Tests unsuccessful logins
     * Unsuccessful logins could be due to incorrect username, or incorrect password
     */
    @Test
    public void testIncorrectLogin(){
        //test invalid username
        int responseCode = UserLoginCompany.login("InfinitiWar",
                "byebye",
                "4fb455fc94279ec6b70301bc9108920c3c221430475de5fad15b854673f9d786",
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwPxRNM32MW2j5\ng/HlGSnx2oJ6cgNkNlMZ7Ad3mdtkux8SoaLrV9c54ru7JcNx+M81mBvtDP4wlWzD\n0gfT62ATsAcs0HwM/Qn7xQw6ra/tkK7Kuj1R37VWT+zyFDwFV5Z6KwFRn7xBFJBT\niL1ikBi/LAnq55AmslhToFBwfh68UCJQ6fl3oaQxkIV30nC/au91NhBphw1WQXiS\nynuYRlz4XNCV1nbzOwRpdMna+sDctjQDw721YxrQ/exsugyRfMF2aOsVHQsCRk+0\ndZc7Cobz8LGxrs1ubdUO4cOFl4L4vo53BmxzE5k1UiE9jtSEjQb2LbhE7Wb/hsN5\n33h3NnUBAgMBAAECggEAAOm8Hi5sNPppWARgafLMtoXapePBRKIoMXlVPmntD7q9\nNm49EpVOP06zVQjTAioqMJMBETgFXS4NXNsttdfkddxmPH3AWGPZSN4u6xL+uSw0\nDrso1p24MwMuqCw7jYYALL4EPpGDZ+RfYzCFTbRjKY6O1vBC/Td0mhL9rvAhMp3E\n5sFZ4SnvmgRmGhKOkGgFF93w6M5y2e3vC+4xhJZ0jITNQO8bUpP5Sz7fTJiAtLlO\nDrlVlPZDAJ+zLojswx3/jr5v1bK1T1VCwnUbhtGxxSrgimSKjpSsBzZKWlOxk3+I\nm+aBY6zyJdi7aehyp4r+h6W82O1ED4hqJc9nJGoUgQKBgQC3IvZkb2KA+hSnPelJ\n1wHMUJN4ze+vw8HBopXELbQnB5QcJVp8xyz5kUuVKwrQFkZUavHc3VOMYbDuY8lS\nv8ORwdXoWkgIAPWzzffvg6eBwEuzz2hc3dU8dfDHoRC9vAvLrdxJJZ/mVdvWqXKV\na0XmvQnZUiSPwzbMr6tHGXxggQKBgQD2XlTYUABOOd6LeZ5mVtGtW5hB5bkegI7r\nW4uXxsWYD5yVOntZC/q4+nM+dHWHwiVpoMKFGA80yooOdtq9r/LwOCg7bw+Dkmmy\n9qrQmfLF33PwxgOInpvTGs6dX5TSlSNEPxQcgmZS934/fgkZ5JnzI7ap7hwzRHXc\nAV6B8B/UgQKBgGcdu4hfoyImLZzhYkreUjfdoruhkPTxj1ZdGmDkrwxO2xlh+upJ\nJ8y5/8nU+3ihIiaENPz8bf+cPghsjT4XlaGrd6slsms3RyFfttvY0Gdhg/6RqRyp\nF1i8u79btFZw3F9p3KAfHEKQU4Ex1b/GMAy0oigIdWexLljgDNuywPKBAoGAc86H\np16DpkHBgGJcuNJaoViKy38Gc3YOuEdB6MhAnWfJPMROst7UrhrcDSGFFZmHKI2u\nog1bKH+EQaRQ0hVg5tYe40EjU7+A++TDCmczHRwaTbVmd9PGf4b8VDFXrVz5RN05\nwOTy4FECASpncMpqK0ZAWMRacSbfF9l06TNMYwECgYEAruQeVz0/zZO4m4ngvG/B\nb8Ua68uJHwuWqQgteKHt6+FY+ppDmAHDLXYkHL3SrJFDV0Y4zNiSBX2SpCErj8yy\ntOKhSPckqSZON6fQuf9tDyLUEMT2Q1THMymi6Mra833W5zpeK6BQPAOERMMrsqNl\n5j29LX39eqNdFkvPkX22U+Q=\n-----END PRIVATE KEY-----",
                "8752337d9dfa5bff1e82deba44e7156e10ec5144c85682aae70c30d41aaa0125");
        assertEquals(401, responseCode);

        //test invalid password
        responseCode = UserLoginCompany.login("InfinityWar",
                "bywbye",
                "4fb455fc94279ec6b70301bc9108920c3c221430475de5fad15b854673f9d786",
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwPxRNM32MW2j5\ng/HlGSnx2oJ6cgNkNlMZ7Ad3mdtkux8SoaLrV9c54ru7JcNx+M81mBvtDP4wlWzD\n0gfT62ATsAcs0HwM/Qn7xQw6ra/tkK7Kuj1R37VWT+zyFDwFV5Z6KwFRn7xBFJBT\niL1ikBi/LAnq55AmslhToFBwfh68UCJQ6fl3oaQxkIV30nC/au91NhBphw1WQXiS\nynuYRlz4XNCV1nbzOwRpdMna+sDctjQDw721YxrQ/exsugyRfMF2aOsVHQsCRk+0\ndZc7Cobz8LGxrs1ubdUO4cOFl4L4vo53BmxzE5k1UiE9jtSEjQb2LbhE7Wb/hsN5\n33h3NnUBAgMBAAECggEAAOm8Hi5sNPppWARgafLMtoXapePBRKIoMXlVPmntD7q9\nNm49EpVOP06zVQjTAioqMJMBETgFXS4NXNsttdfkddxmPH3AWGPZSN4u6xL+uSw0\nDrso1p24MwMuqCw7jYYALL4EPpGDZ+RfYzCFTbRjKY6O1vBC/Td0mhL9rvAhMp3E\n5sFZ4SnvmgRmGhKOkGgFF93w6M5y2e3vC+4xhJZ0jITNQO8bUpP5Sz7fTJiAtLlO\nDrlVlPZDAJ+zLojswx3/jr5v1bK1T1VCwnUbhtGxxSrgimSKjpSsBzZKWlOxk3+I\nm+aBY6zyJdi7aehyp4r+h6W82O1ED4hqJc9nJGoUgQKBgQC3IvZkb2KA+hSnPelJ\n1wHMUJN4ze+vw8HBopXELbQnB5QcJVp8xyz5kUuVKwrQFkZUavHc3VOMYbDuY8lS\nv8ORwdXoWkgIAPWzzffvg6eBwEuzz2hc3dU8dfDHoRC9vAvLrdxJJZ/mVdvWqXKV\na0XmvQnZUiSPwzbMr6tHGXxggQKBgQD2XlTYUABOOd6LeZ5mVtGtW5hB5bkegI7r\nW4uXxsWYD5yVOntZC/q4+nM+dHWHwiVpoMKFGA80yooOdtq9r/LwOCg7bw+Dkmmy\n9qrQmfLF33PwxgOInpvTGs6dX5TSlSNEPxQcgmZS934/fgkZ5JnzI7ap7hwzRHXc\nAV6B8B/UgQKBgGcdu4hfoyImLZzhYkreUjfdoruhkPTxj1ZdGmDkrwxO2xlh+upJ\nJ8y5/8nU+3ihIiaENPz8bf+cPghsjT4XlaGrd6slsms3RyFfttvY0Gdhg/6RqRyp\nF1i8u79btFZw3F9p3KAfHEKQU4Ex1b/GMAy0oigIdWexLljgDNuywPKBAoGAc86H\np16DpkHBgGJcuNJaoViKy38Gc3YOuEdB6MhAnWfJPMROst7UrhrcDSGFFZmHKI2u\nog1bKH+EQaRQ0hVg5tYe40EjU7+A++TDCmczHRwaTbVmd9PGf4b8VDFXrVz5RN05\nwOTy4FECASpncMpqK0ZAWMRacSbfF9l06TNMYwECgYEAruQeVz0/zZO4m4ngvG/B\nb8Ua68uJHwuWqQgteKHt6+FY+ppDmAHDLXYkHL3SrJFDV0Y4zNiSBX2SpCErj8yy\ntOKhSPckqSZON6fQuf9tDyLUEMT2Q1THMymi6Mra833W5zpeK6BQPAOERMMrsqNl\n5j29LX39eqNdFkvPkX22U+Q=\n-----END PRIVATE KEY-----",
                "8752337d9dfa5bff1e82deba44e7156e10ec5144c85682aae70c30d41aaa0125");
        assertEquals(401,responseCode);

        //test invalid token
        responseCode = UserLoginCompany.login("InfinityWar",
                "byebye",
                "4fb456fc94279ec6b70301bc9108920c3c221430475de5fad15b854673f9d786",
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwPxRNM32MW2j5\ng/HlGSnx2oJ6cgNkNlMZ7Ad3mdtkux8SoaLrV9c54ru7JcNx+M81mBvtDP4wlWzD\n0gfT62ATsAcs0HwM/Qn7xQw6ra/tkK7Kuj1R37VWT+zyFDwFV5Z6KwFRn7xBFJBT\niL1ikBi/LAnq55AmslhToFBwfh68UCJQ6fl3oaQxkIV30nC/au91NhBphw1WQXiS\nynuYRlz4XNCV1nbzOwRpdMna+sDctjQDw721YxrQ/exsugyRfMF2aOsVHQsCRk+0\ndZc7Cobz8LGxrs1ubdUO4cOFl4L4vo53BmxzE5k1UiE9jtSEjQb2LbhE7Wb/hsN5\n33h3NnUBAgMBAAECggEAAOm8Hi5sNPppWARgafLMtoXapePBRKIoMXlVPmntD7q9\nNm49EpVOP06zVQjTAioqMJMBETgFXS4NXNsttdfkddxmPH3AWGPZSN4u6xL+uSw0\nDrso1p24MwMuqCw7jYYALL4EPpGDZ+RfYzCFTbRjKY6O1vBC/Td0mhL9rvAhMp3E\n5sFZ4SnvmgRmGhKOkGgFF93w6M5y2e3vC+4xhJZ0jITNQO8bUpP5Sz7fTJiAtLlO\nDrlVlPZDAJ+zLojswx3/jr5v1bK1T1VCwnUbhtGxxSrgimSKjpSsBzZKWlOxk3+I\nm+aBY6zyJdi7aehyp4r+h6W82O1ED4hqJc9nJGoUgQKBgQC3IvZkb2KA+hSnPelJ\n1wHMUJN4ze+vw8HBopXELbQnB5QcJVp8xyz5kUuVKwrQFkZUavHc3VOMYbDuY8lS\nv8ORwdXoWkgIAPWzzffvg6eBwEuzz2hc3dU8dfDHoRC9vAvLrdxJJZ/mVdvWqXKV\na0XmvQnZUiSPwzbMr6tHGXxggQKBgQD2XlTYUABOOd6LeZ5mVtGtW5hB5bkegI7r\nW4uXxsWYD5yVOntZC/q4+nM+dHWHwiVpoMKFGA80yooOdtq9r/LwOCg7bw+Dkmmy\n9qrQmfLF33PwxgOInpvTGs6dX5TSlSNEPxQcgmZS934/fgkZ5JnzI7ap7hwzRHXc\nAV6B8B/UgQKBgGcdu4hfoyImLZzhYkreUjfdoruhkPTxj1ZdGmDkrwxO2xlh+upJ\nJ8y5/8nU+3ihIiaENPz8bf+cPghsjT4XlaGrd6slsms3RyFfttvY0Gdhg/6RqRyp\nF1i8u79btFZw3F9p3KAfHEKQU4Ex1b/GMAy0oigIdWexLljgDNuywPKBAoGAc86H\np16DpkHBgGJcuNJaoViKy38Gc3YOuEdB6MhAnWfJPMROst7UrhrcDSGFFZmHKI2u\nog1bKH+EQaRQ0hVg5tYe40EjU7+A++TDCmczHRwaTbVmd9PGf4b8VDFXrVz5RN05\nwOTy4FECASpncMpqK0ZAWMRacSbfF9l06TNMYwECgYEAruQeVz0/zZO4m4ngvG/B\nb8Ua68uJHwuWqQgteKHt6+FY+ppDmAHDLXYkHL3SrJFDV0Y4zNiSBX2SpCErj8yy\ntOKhSPckqSZON6fQuf9tDyLUEMT2Q1THMymi6Mra833W5zpeK6BQPAOERMMrsqNl\n5j29LX39eqNdFkvPkX22U+Q=\n-----END PRIVATE KEY-----",
                "8752337d9dfa5bff1e82deba44e7156e10ec5144c85682aae70c30d41aaa0125");
        assertEquals(401,responseCode);
    }

    /**
     * Test which makes sure that login is not possible when token is revoked
     */
    @Test
    public void testRevokeTokenAccessDenied(){
        int responseCode = revokeToken("8752337d9dfa5bff1e82deba44e7156e10ec5144c85682aae70c30d41aaa0125");
        //ensure token revocation is successful
        assertEquals(200,responseCode);
        responseCode = UserLoginCompany.login("InfinityWar",
                "byebye",
                "4fb455fc94279ec6b70301bc9108920c3c221430475de5fad15b854673f9d786",
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwPxRNM32MW2j5\ng/HlGSnx2oJ6cgNkNlMZ7Ad3mdtkux8SoaLrV9c54ru7JcNx+M81mBvtDP4wlWzD\n0gfT62ATsAcs0HwM/Qn7xQw6ra/tkK7Kuj1R37VWT+zyFDwFV5Z6KwFRn7xBFJBT\niL1ikBi/LAnq55AmslhToFBwfh68UCJQ6fl3oaQxkIV30nC/au91NhBphw1WQXiS\nynuYRlz4XNCV1nbzOwRpdMna+sDctjQDw721YxrQ/exsugyRfMF2aOsVHQsCRk+0\ndZc7Cobz8LGxrs1ubdUO4cOFl4L4vo53BmxzE5k1UiE9jtSEjQb2LbhE7Wb/hsN5\n33h3NnUBAgMBAAECggEAAOm8Hi5sNPppWARgafLMtoXapePBRKIoMXlVPmntD7q9\nNm49EpVOP06zVQjTAioqMJMBETgFXS4NXNsttdfkddxmPH3AWGPZSN4u6xL+uSw0\nDrso1p24MwMuqCw7jYYALL4EPpGDZ+RfYzCFTbRjKY6O1vBC/Td0mhL9rvAhMp3E\n5sFZ4SnvmgRmGhKOkGgFF93w6M5y2e3vC+4xhJZ0jITNQO8bUpP5Sz7fTJiAtLlO\nDrlVlPZDAJ+zLojswx3/jr5v1bK1T1VCwnUbhtGxxSrgimSKjpSsBzZKWlOxk3+I\nm+aBY6zyJdi7aehyp4r+h6W82O1ED4hqJc9nJGoUgQKBgQC3IvZkb2KA+hSnPelJ\n1wHMUJN4ze+vw8HBopXELbQnB5QcJVp8xyz5kUuVKwrQFkZUavHc3VOMYbDuY8lS\nv8ORwdXoWkgIAPWzzffvg6eBwEuzz2hc3dU8dfDHoRC9vAvLrdxJJZ/mVdvWqXKV\na0XmvQnZUiSPwzbMr6tHGXxggQKBgQD2XlTYUABOOd6LeZ5mVtGtW5hB5bkegI7r\nW4uXxsWYD5yVOntZC/q4+nM+dHWHwiVpoMKFGA80yooOdtq9r/LwOCg7bw+Dkmmy\n9qrQmfLF33PwxgOInpvTGs6dX5TSlSNEPxQcgmZS934/fgkZ5JnzI7ap7hwzRHXc\nAV6B8B/UgQKBgGcdu4hfoyImLZzhYkreUjfdoruhkPTxj1ZdGmDkrwxO2xlh+upJ\nJ8y5/8nU+3ihIiaENPz8bf+cPghsjT4XlaGrd6slsms3RyFfttvY0Gdhg/6RqRyp\nF1i8u79btFZw3F9p3KAfHEKQU4Ex1b/GMAy0oigIdWexLljgDNuywPKBAoGAc86H\np16DpkHBgGJcuNJaoViKy38Gc3YOuEdB6MhAnWfJPMROst7UrhrcDSGFFZmHKI2u\nog1bKH+EQaRQ0hVg5tYe40EjU7+A++TDCmczHRwaTbVmd9PGf4b8VDFXrVz5RN05\nwOTy4FECASpncMpqK0ZAWMRacSbfF9l06TNMYwECgYEAruQeVz0/zZO4m4ngvG/B\nb8Ua68uJHwuWqQgteKHt6+FY+ppDmAHDLXYkHL3SrJFDV0Y4zNiSBX2SpCErj8yy\ntOKhSPckqSZON6fQuf9tDyLUEMT2Q1THMymi6Mra833W5zpeK6BQPAOERMMrsqNl\n5j29LX39eqNdFkvPkX22U+Q=\n-----END PRIVATE KEY-----",
                "8752337d9dfa5bff1e82deba44e7156e10ec5144c85682aae70c30d41aaa0125");
        try {
            assertEquals(400, responseCode);
        }
        finally{
            reactivateToken("8752337d9dfa5bff1e82deba44e7156e10ec5144c85682aae70c30d41aaa0125");
        }
    }
}
