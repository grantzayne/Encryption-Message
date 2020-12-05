import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;

    //Global variables
    private PublicKey bobPub;
    private KeyPair Alice;
    private Cipher cipher;

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    public String generateKey(){
        SecretKey secretKey;
        KeyGenerator keygen = null;
        try{
            keygen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e){
            System.out.println(e.getMessage());
        }
        keygen.init(128);
        secretKey = keygen.generateKey();
        String keyString = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        return keyString;
    }

    /**
     * Generates the KeyPair for Alice/Client
     */
    public void generateKeypair(String filename, String passcode){
        try {
            //KeyStore Load
            char[] password = passcode.toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(filename),password);

            //Alice KeyPair
            String AliceS = "alice";
            Key Alicekey = ks.getKey(AliceS,password);
            if(Alicekey instanceof PrivateKey){
                Certificate cert = ks.getCertificate(AliceS);
                PublicKey publicKey = cert.getPublicKey();

                Alice = new KeyPair(publicKey,(PrivateKey) Alicekey);
                //System.out.println(Alice);
            }

            //Bob Key
            String Bob = "bob";
            Key Bobkey = ks.getKey(Bob,password);
            if(Bobkey instanceof PrivateKey){
                Certificate cert = ks.getCertificate(Bob);
                bobPub = cert.getPublicKey();
                //System.out.println(bobPub);
            }

            //Cipher Setup
            String ciphername = ("RSA/ECB/PKCS1Padding");
            cipher = Cipher.getInstance(ciphername);

        } catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) {
        try {
            if (msg.length() > 32 || msg.length() < 1){
                System.out.println("Error: Message length invalid, between 1 and 32 characters only");
                return null;
            }

            //Alice encrypts using Bob's public key.
            cipher.init(Cipher.ENCRYPT_MODE, bobPub);
            System.out.println("Client sending cleartext "+msg);
            final byte[] originalBytes = msg.getBytes();
            byte[] cipherTextBytes = cipher.doFinal(originalBytes);
            System.out.println("Client sending ciphertext "+ Util.bytesToHex(cipherTextBytes));

            //Alice signs using her private key.
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(Alice.getPrivate());
            sig.update(originalBytes);
            byte[] signatureBytes = sig.sign();

            //Alice sends the message
            out.write(cipherTextBytes);
            //System.out.println(Util.bytesToHex(signatureBytes));
            //out.write(signatureBytes);
            out.flush();

            // Alice receives and decrypts the message using her private key
            cipher.init(Cipher.DECRYPT_MODE, Alice.getPrivate());
            in.read(cipherTextBytes);
            byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
            String reply = new String(decryptedBytes);
            System.out.println("Server returned cleartext "+reply);

            //Alice authenticates using Bob's public key.
            in.read(signatureBytes);
            sig.initVerify(bobPub);
            sig.update(decryptedBytes);
            final boolean signatureValid = sig.verify(signatureBytes);
            if (signatureValid){
                System.out.println("Yes, Bob sent this.");
            } else {
                throw new IllegalArgumentException("Signature does not match");
            }

            return reply;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    public static void main(String[] args) {
        EchoClient client = new EchoClient();
        client.generateKeypair(args[0],args[1]);
        client.startConnection("127.0.0.1", 4444);
        client.sendMessage(client.generateKey());
        client.sendMessage("");
        client.sendMessage("ABCDEFGH");
        client.sendMessage("87654321");
        client.sendMessage("HGFEDCBA");
        client.stopConnection();
    }
}
