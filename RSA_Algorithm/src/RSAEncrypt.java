package RSA_Algorithm.src;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

public class RSAEncrypt {
    private BigInteger n;
    private BigInteger e;
    private final Random random = new Random();

    public void generate() throws IOException {
        int bitLength = 512;

//        Key generation

        System.out.println("\nGenerating keys with size 1024...");
        BigInteger p = BigInteger.probablePrime(bitLength, random); // generate p
        BigInteger q = BigInteger.probablePrime(bitLength, random); // generate q
        n = p.multiply(q); // calculate modulus n
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // calculate phi
        e = new BigInteger("65537"); // choose e (public key)

        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && phi.gcd(e).compareTo(BigInteger.ONE) < 0) {
            System.out.println("Regenerating prime due to gcd != 1");
            p = BigInteger.probablePrime(bitLength / 2, random);
            q = BigInteger.probablePrime(bitLength / 2, random);
            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        }

        BigInteger d = e.modInverse(phi); // calculate d (private key)

        Writer writer = new FileWriter("publickey.txt"); // save public key to file
        writer.write(e + "\n" + n);
        writer.close();
        writer = new FileWriter("privatekey.txt"); // save private key to file
        writer.write(d + "\n" + n);
        writer.close();

        System.out.println("\nKeys is saved to publickey.txt and privatekey.txt");
        System.out.println("\nUsing the public key");
    }

    public BigInteger getE() {
        return this.e;
    } // e getter

    public BigInteger getN() {
        return this.n;
    } // n getter

    public void encrypt(String message, RSAEncrypt rsaEncrypt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        BigInteger E = rsaEncrypt.getE();
        System.out.println("\n E: " + E);
        BigInteger N = rsaEncrypt.getN();
        System.out.println("\n N: " + N);

        byte[] messageBytes = message.getBytes(); // convert string message into bytes
        List<Byte> messageByteList = new ArrayList<>(); // create arraylist of byte
        for (byte messagebyte : messageBytes) {
            messageByteList.add(messagebyte);
        }

        System.out.println("\nMessage byte length: " + messageBytes.length);
        int noOfChunk = (int) Math.ceil((double) messageBytes.length / 64); // calculate number of chunk if split message (if have any)
        int lastChunkRemainderSize = messageBytes.length % 64; // calculate last chunk's byte (if have any)

//        Encrypt
        // create encryption instance of Cipher library with RSA and public key initialized
        System.out.println("\nEncrypting...");
        KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(N, E);
        RSAPublicKey pub = (RSAPublicKey) rsaKeyFactory.generatePublic(publicKeySpec);
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pub);

        byte[] messageChunkByte;
        int pos = 0;
        FileOutputStream fos = new FileOutputStream("ciphertext.txt");
        for (int i = 0; i < noOfChunk; i++) {
            if (noOfChunk - i == 1) messageChunkByte = new byte[lastChunkRemainderSize];
            else messageChunkByte = new byte[64];

            // create message chunk from array list
            for (int j = 0; j < messageChunkByte.length; j++) {
                messageChunkByte[j] = messageByteList.get(pos);
                pos++;
            }
            System.out.println("\nMessage chunk byte " + (i + 1) + ": " + Arrays.toString(messageChunkByte));
            System.out.println("Message chunk " + (i + 1) + ": " + new String(messageChunkByte));

            byte[] ciphertextBytes = rsaCipher.doFinal(messageChunkByte); // encrypt message
            System.out.println("Ciphertext length: " + ciphertextBytes.length); // should be 128 bytes
            System.out.println("Ciphertext: " + Arrays.toString(ciphertextBytes));

            fos.write(ciphertextBytes); // write each ciphertexts into file
        }
        fos.close();

        System.out.println("\nCiphertext is saved to: ciphertext.txt");
    }
}
