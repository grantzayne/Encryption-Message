import javax.crypto.Cipher;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;

    //Global Variables
    private PublicKey AlicePub;
    private KeyPair Bob;
    private Cipher cipher;

    /**
     * Generates the KeyPair for Bob/Server
     */
    public void generateKeypair(String filename, String passcode){
        try {
            //KeyStore Load
            char[] password = passcode.toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(filename),password);

            //Bob KeyPair
            String BobS = "bob";
            Key Bobkey = ks.getKey(BobS,password);
            if(Bobkey instanceof PrivateKey){
                Certificate cert = ks.getCertificate(BobS);
                PublicKey publicKey = cert.getPublicKey();

                Bob = new KeyPair(publicKey,(PrivateKey) Bobkey);
                //System.out.println(Alice);
            }

            //Alice Key
            String Alice = "alice";
            Key key = ks.getKey(Alice,password);
            if(key instanceof PrivateKey){
                Certificate cert = ks.getCertificate(Alice);
                AlicePub = cert.getPublicKey();
                //System.out.println(AlicePub);
            }

            //Cipher setup
            String ciphername = ("RSA/ECB/PKCS1Padding");
            cipher = Cipher.getInstance(ciphername);

        } catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) {
        try {
            //Bob receives the message
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            byte[] data = new byte[256];
            while (in.read(data) != -1) {
                // Bob decrypts using his private key.
                //System.out.println(Util.bytesToHex(data));
                cipher.init(Cipher.DECRYPT_MODE, Bob.getPrivate());
                byte[] decryptedBytes = cipher.doFinal(data);
                String msg = new String(decryptedBytes);
                System.out.println("Server received cleartext "+ msg);

                /* I kinda failed to get the authentication for Alice's message I
                * couldn't figure out how to write and extract her signature into data
                * but I do have all the code here that should get it to work */
                //Bob authenticates using Alice's public key.
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(AlicePub);
                sig.update(decryptedBytes);
                //System.out.println(Util.bytesToHex(data));
                /*final boolean signatureValid = sig.verify(data);
                if (signatureValid){
                    System.out.println("Yes, Alice wrote this.");
                } else {
                    throw new IllegalArgumentException("Signature does not match");
                }*/

                // Bob encrypts using Alice's public key
                cipher.init(Cipher.ENCRYPT_MODE, AlicePub);
                final byte[] originalBytes = msg.getBytes();
                byte[] cipherTextBytes = cipher.doFinal(originalBytes);

                //Bob signs using his private key.
                sig.initSign(Bob.getPrivate());
                sig.update(originalBytes);
                byte[] signatureBytes = sig.sign();

                //Bob sends the message
                System.out.println("Server sending ciphertext "+ Util.bytesToHex(cipherTextBytes));
                out.write(cipherTextBytes);
                out.write(signatureBytes);
                out.flush();
            }
            stop();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void main(String[] args) {
        EchoServer server = new EchoServer();
        server.generateKeypair(args[0],args[1]);
        server.start(4444);
    }

}



