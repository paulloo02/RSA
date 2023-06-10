package RSA_Algorithm.src;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class RSADecrypt {
    private BigInteger n;
    private BigInteger d;

    public static byte[] ciphertext;

    public BigInteger getD() {
        return this.d;
    } // d getter

    public BigInteger getN() {
        return this.n;
    } // n getter

    public void setD(BigInteger d) {
        this.d = d;
    } // d setter

    public void setN(BigInteger n) {
        this.n = n;
    } // n setter


    // get ciphertext from file
    public void loadCiphertext() throws IOException {
        File file = new File("ciphertext.txt");
        try (RandomAccessFile randomAccessFile = new RandomAccessFile(file, "r")) {
            ciphertext = new byte[(int) file.length()];
            System.out.println("File size: " + file.length());
            randomAccessFile.readFully(ciphertext);
        }

        System.out.println("\nCiphertext loaded!");
    }

    // load private key from file
    public void loadKey(RSADecrypt rsaDecrypt) throws FileNotFoundException {
        File file = new File("privatekey.txt");
        System.out.println(file.length());
        try (Scanner privateScanner1 = new Scanner(file)) {
            BigInteger d = privateScanner1.nextBigInteger();
            BigInteger n = privateScanner1.nextBigInteger();
            rsaDecrypt.setD(d);
            rsaDecrypt.setN(n);
        }
        System.out.println("\nPrivate key loaded!");
    }

    public String decrypt(RSADecrypt rsaDecrypt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        BigInteger D = rsaDecrypt.getD();
        System.out.println("\n D: " + D);
        BigInteger N = rsaDecrypt.getN();
        System.out.println("\n N: " + N);

        // error handling
        if (D == null || N == null)
            return "d_n_null";


        // create decryption instance of Cipher library with RSA and private key initialized
        System.out.println("\nDecrypting...");
        KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(N, D);
        RSAPrivateKey pub = (RSAPrivateKey) rsaKeyFactory.generatePrivate(privateKeySpec);
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, pub);

        // error handling
        if (ciphertext == null)
            return "c_null";

        // count number of chunk
        int noOfChunk = ciphertext.length / 128;
        int pos = 0;
        StringBuilder message = new StringBuilder();

        for (int i = 0; i < noOfChunk; i++) {
            byte[] messageChunkByte = new byte[128];
            System.arraycopy(ciphertext, pos, messageChunkByte, 0, messageChunkByte.length); // get ciphertext chunk
            pos += 128;
            System.out.println("\nCiphertext: " + Arrays.toString(messageChunkByte));


            message.append(new String(rsaCipher.doFinal(messageChunkByte))); // decrypt the message and append to stringbuilder
        }

        System.out.println("\nMessage: " + message);

        return message.toString(); // return message to GUI
    }
}
