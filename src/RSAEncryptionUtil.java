import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;

public class RSAEncryptionUtil {

    /**
     * Strings to hold name of the encryption algorithm.
     */
    public static final String ALGORITHM = "RSA";
    public static final String ALGORITHM_AND_MODE = ALGORITHM + "/ECB/NOPADDING";

    /**
     * Loads a ciphertext stored in binary format from the specified file and
     * returns it in the form of a BigInteger.
     *
     * @param filename the name of the file
     * @return the ciphertext
     * @throws java.io.IOException
     */
    public static BigInteger loadCiphertext(String filename) throws IOException {
        return new BigInteger(Files.readAllBytes(Paths.get(filename)));
    }

    /**
     * Tries to load a public key object from the specified file.
     *
     * @param filename the name of the file
     * @return the public key
     * @throws FileNotFoundException
     * @throws ClassNotFoundException
     * @throws IOException
     */
    public static RSAPublicKey loadRSAPublicKey(String filename)
            throws FileNotFoundException, ClassNotFoundException, IOException {
        return (RSAPublicKey) loadKey(filename);
    }

    /**
     * Tries to load a private key object from the specified file.
     *
     * @param filename the name of the file
     * @return the private key
     * @throws FileNotFoundException
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static RSAPrivateKey loadRSAPrivateKey(String filename)
            throws ClassNotFoundException, IOException {
        return (RSAPrivateKey) loadKey(filename);
    }

    private static Object loadKey(String filename) throws FileNotFoundException, IOException, ClassNotFoundException {
        ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(filename));
        Object obj = inputStream.readObject();
        inputStream.close();
        return obj;
    }

    /**
     * Encrypt a plaintext using the public key.
     *
     * @param plaintext the plaintext
     * @param publicKey the public key
     * @return the ciphertext
     */
    public static byte[] encrypt(String plaintext, PublicKey publicKey) {
        byte[] ciphertext = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM_AND_MODE);
            
            // encrypt the plaintext using the public key
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] bytes = plaintext.getBytes(StandardCharsets.US_ASCII);
            ciphertext = cipher.doFinal(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ciphertext;
    }

    /**
     * Decrypt a ciphertext using the private key.
     *
     * @param ciphertext the ciphertext
     * @param privateKey the private key
     * @return the plaintext
     */
    public static String decrypt(byte[] ciphertext, PrivateKey privateKey) {
        byte[] plaintext = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM_AND_MODE);

            // decrypt the ciphertext using the private key
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            plaintext = cipher.doFinal(ciphertext);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new String(plaintext, StandardCharsets.US_ASCII);
    }

    /**
     * Encrypts the provided text using the public key and then decrypts the
     * encrypted ciphertext using the private key. Prints the original, encrypted
     * and decrypted texts to the standard output.
     *
     * @param text text to be used
     * @param privateKey the private key
     * @param publicKey the public key
     */
    public static void printEncryptedDecrypted(String text, PrivateKey privateKey, PublicKey publicKey) {
        final byte[] ciphertext = encrypt(text, publicKey);
        final String plaintext = decrypt(ciphertext, privateKey);
        
        // print the original, encrypted and decrypted text
        System.out.println("Original:  " + text);
        System.out.println("Encrypted: " + Arrays.toString(ciphertext));
        System.out.println("Decrypted: " + plaintext);
    }

    /**
     * Calculates the cube root of a BigInteger number
     *
     * @param n the number
     * @return the cube root of the number
     */
    public static BigInteger cubeRoot(BigInteger n) {
        // Using Newton's method, we approximate the cube root
        // of n by the sequence:
        // x_{i + 1} = \frac{1}{3} \left( \frac{n}{x_i^2} + 2 x_i \right).
        // See http://en.wikipedia.org/wiki/Cube_root#Numerical_methods.
        //
        // Implementation based on Section 1.7.1 of
        // "A Course in Computational Algebraic Number Theory"
        // by Henri Cohen.
        BigInteger THREE = BigInteger.valueOf(3);
        BigInteger x = BigInteger.ZERO.setBit(n.bitLength() / 3 + 1);
        while (true) {
            BigInteger y = x.shiftLeft(1).add(n.divide(x.multiply(x))).divide(THREE);
            if (y.compareTo(x) >= 0) {
                break;
            }
            x = y;
        }
        return x;
    }
}
