package coursework;



import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;
import java.nio.file.Path;


class AES_ENCRYPTION {
    private SecretKey key;
    private final int KEY_SIZE = 128;
    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;

    public void init() throws Exception { // Generate 128 bit key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        key = keyGenerator.generateKey();
    }
    
    public String encrypt(String data) throws Exception {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key); // initialize cipher with key and operation mode set to encrypt
        byte[] aesKey = key.getEncoded();
        String aesKeyBase64 = Base64.getEncoder().encodeToString(aesKey); // get secretkey, converted to base64
        System.out.println("==============================");
        System.out.println("NOTE: Save encryption key and IV! Those will be needed for decryption.");
        System.out.println("Encryption key: " + aesKeyBase64);
        System.out.println("IV: " + encode(encryptionCipher.getIV()));
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedData, String key, String IV) throws Exception {
        String aesKeyBase64 = key;
        SecretKey asd = new SecretKeySpec(decode(aesKeyBase64), "AES");
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte [] iv = decode(IV);
        GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, iv);

        decryptionCipher.init(Cipher.DECRYPT_MODE, asd, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) { // encode byte array to base64 string
        return Base64.getEncoder().encodeToString(data);
    }

    public byte[] decode(String data) { // decode base64 string to byte array
        return Base64.getDecoder().decode(data);
    }
    
}


public class work {
    public static void printLogo() {
        System.out.println("           ______  _____ _     _       ");
        System.out.println("     /\\   |  ____|/ ____| |   (_)      ");
        System.out.println("    /  \\  | |__  | (___ | |__  _ _ __  ");
        System.out.println("   / /\\ \\ |  __|  \\___ \\| '_ \\| | '_ \\ ");
        System.out.println("  / ____ \\| |____ ____) | |_) | | | | |");
        System.out.println(" /_/    \\_\\______|_____/|_.__/|_|_| |_|");
        System.out.println();                                                                  
    }

    static Scanner sc = new Scanner(System.in);

    public static String getMessageToEncrypt() throws IOException{
        String message = "";
        System.out.println("Enter '1' to input message, '2' to get message from file: ");
        switch (sc.nextInt()) {
            case 1:
            System.out.println("Enter message: ");
            sc.nextLine(); // remove newline (otherwise won't be able to get string after int)
            message = sc.nextLine();
            break;
            case 2:
            System.out.println("Enter file name: (NOTE: file must be stored on Desktop)");
            sc.nextLine();
            String fileName = sc.nextLine();
            Path filePath = Path.of(System.getProperty("user.home") + "/Desktop/" + fileName);
            message = Files.readString(filePath);
            break;
            default:
            System.out.println("Wrong input");
        }
        return message;
    }

    public static String encryptMessage(String message) {
        String encryptedMessage = "";
        try {
            AES_ENCRYPTION aes_encryption = new AES_ENCRYPTION();
            aes_encryption.init();
            encryptedMessage = aes_encryption.encrypt(message);
            System.out.println("==============================");
            System.out.println("Initial message: " + message);
            System.out.println("==============================");
            System.out.println("Encrypted message: " + encryptedMessage);
            System.out.println("==============================");
        }
        catch (Exception ignored) {}
        return encryptedMessage;
    }

    public static String decryptMessage() throws Exception {
        sc.nextLine();
        System.out.println("Enter url OR paste key to decrypt from: ");
        System.out.println("(WITHOUT HTTPS) pastebin.com/XXXXXXX OR XXXXXX" );
        String[] urlSplit = sc.nextLine().split("/");
        String key = "";
        if (urlSplit.length == 0) {
            System.err.println("Wrong url");
        }
        if (urlSplit.length == 2) {
            key = urlSplit[1];
        }
        else {
            key = urlSplit[0];
        }

        URL url = new URL("https://pastebin.com/raw/" + key);
		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		httpConn.setRequestMethod("GET");

		InputStream responseStream = httpConn.getResponseCode() / 100 == 2
				? httpConn.getInputStream()
				: httpConn.getErrorStream();
		Scanner s = new Scanner(responseStream).useDelimiter("\\A");
		String response = s.hasNext() ? s.next() : "";
        s.close();
		AES_ENCRYPTION aes_encryption = new AES_ENCRYPTION();
        aes_encryption.init();
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter decryption key: ");
        String decrKey = scan.nextLine();
        System.out.println("Enter IV: ");
        String IV = scan.nextLine();
        String decryptedData = aes_encryption.decrypt(response, decrKey, IV);
        System.out.println("Decrypted data: " + decryptedData);
        System.out.println("Do you want to store decrypted message to file? (Y/N)");
        switch (scan.nextLine().toLowerCase()) {
            case "y":
                System.out.println("Enter file name: ");
                String fileName = scan.nextLine();
                try {
                    File file = new File(System.getProperty("user.home") + "/Desktop/"+ fileName + ".txt");
                    FileOutputStream fos = new FileOutputStream(file);
                    if (!file.exists()) {
                        file.createNewFile();
                    }
                    byte[] contentInBytes = decryptedData.getBytes();
                    fos.write(contentInBytes);
                    fos.flush();
                    fos.close();
                    System.out.println("File " + fileName + ".txt has been saved to Desktop!");
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
                break;
                
            case "n":
                break;
            default:
                System.out.println("Wrong input");
                break;
        }
        scan.close();
        return "";
    } 

    public static String sendPaste(String message) throws IOException{
        final String API_KEY = "SJnlcK2-kkQb2CMxTASsUCoH4Zf-E4GV"; // api key used for pasting
        final String api_option = "paste";
		URL url = new URL("https://pastebin.com/api/api_post.php");
		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		httpConn.setRequestMethod("POST");

		httpConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

		httpConn.setDoOutput(true);
		OutputStreamWriter writer = new OutputStreamWriter(httpConn.getOutputStream());
		writer.write("api_dev_key=" + API_KEY + "&api_paste_code=" + message + "&api_option=" + api_option);
		writer.flush();
		writer.close();
		httpConn.getOutputStream().close();

		InputStream responseStream = httpConn.getResponseCode() / 100 == 2
				? httpConn.getInputStream()
				: httpConn.getErrorStream();
		Scanner s = new Scanner(responseStream).useDelimiter("\\A");
		String response = s.hasNext() ? s.next() : "";
        s.close();
		System.out.println(response);
        return response;
    }
	public static void main(String[] args) throws Exception {
        printLogo();
        System.out.println("Enter '1' to encrypt message, '2' to decrypt");
        switch (sc.nextInt()){
            case 1:
                String message = getMessageToEncrypt();
                message = encryptMessage(message);
                sendPaste(message);
                break;
            case 2:
                decryptMessage();
                break;
            default:
                System.out.println("Wrong input");
                break;
        }  
        
	}
}
        