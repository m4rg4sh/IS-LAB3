import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;

public class RSAAttacks {

    private static final BigInteger ONE = new BigInteger("1");

    /**
     * Tries to find the message assuming that the public exponent is equal to 3
     * and that the ciphertexts contain the same message encrypted with different
     * public keys.
     *
     * @param c1 first ciphertext
     * @param m1 modulus of first public key
     * @param c2 second ciphertext
     * @param m2 modulus of second public key
     * @param c3 third ciphertext
     * @param m3 modulus of third public key
     * @return the candidate message or null if algorithm fails
     */
    public static String tryLowExponentAttack(
            BigInteger c1, BigInteger m1,
            BigInteger c2, BigInteger m2,
            BigInteger c3, BigInteger m3) {
        try {
            BigInteger productOfModuli = m1.multiply(m2).multiply(m3);
            BigInteger n1 = productOfModuli.divide(m1);
            BigInteger n2 = productOfModuli.divide(m2);
            BigInteger n3 = productOfModuli.divide(m3);

            BigInteger d1 = n1.modInverse(m1);
            BigInteger d2 = n2.modInverse(m2);
            BigInteger d3 = n3.modInverse(m3);

            BigInteger x1 = c1.multiply(n1).multiply(d1);
            BigInteger x2 = c2.multiply(n2).multiply(d2);
            BigInteger x3 = c3.multiply(n3).multiply(d3);

            BigInteger x0 = x1.add(x2).add(x3);

            BigInteger x = x0.mod(productOfModuli);

            BigInteger message = RSAEncryptionUtil.cubeRoot(x);

            return new String(message.toByteArray(), StandardCharsets. US_ASCII);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Tries to find the private key corresponding to the first modulus assuming
     * that the two provided moduli have a common factor.
     *
     * @param m1 first modulus
     * @param m2 second modulus
     * @param e1 public exponent corresponding to the first modulus
     * @return the candidate private key or null if algorithm fails
     */
    public static RSAPrivateKey tryCommonFactorAttack(
            BigInteger m1, BigInteger m2, BigInteger e1) {
        try {
            BigInteger g = m1.gcd(m2);
            if(!g.equals(ONE)) {
                BigInteger p = m1.divide(g);
                BigInteger phi = (p.subtract(ONE)).multiply(g.subtract(ONE));
                BigInteger d = e1.modInverse(phi);
                RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m1, d);
                return (RSAPrivateKey) KeyFactory.getInstance(RSAEncryptionUtil.ALGORITHM).generatePrivate(keySpec);

            }
            else {
                return null;
            }
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Cracking Application.
     */
    public static void main(String[] args) {
        try {
            RSAPublicKey key1 = RSAEncryptionUtil.loadRSAPublicKey("resources/bob.pub");
            BigInteger m1 = key1.getModulus();
            BigInteger c1 = RSAEncryptionUtil.loadCiphertext("resources/message-bob.enc");


            RSAPublicKey key2 = RSAEncryptionUtil.loadRSAPublicKey("resources/carol.pub");
            BigInteger m2 = key2.getModulus();
            BigInteger c2 = RSAEncryptionUtil.loadCiphertext("resources/message-carol.enc");


            RSAPublicKey key3 = RSAEncryptionUtil.loadRSAPublicKey("resources/dave.pub");
            BigInteger m3 = key3.getModulus();
            BigInteger c3 = RSAEncryptionUtil.loadCiphertext("resources/message-dave.enc");


            System.out.println("\nMessages to Bob, Carol and Dave; successfully decrypted with LowExponentAttack (e=3):");
            System.out.println(tryLowExponentAttack(c1, m1, c2, m2, c3, m3));

            RSAPublicKey key4 = RSAEncryptionUtil.loadRSAPublicKey("resources/fred.pub");
            BigInteger m4 = key4.getModulus();
            BigInteger c4 = RSAEncryptionUtil.loadCiphertext("resources/message-fred.enc");
            BigInteger e4 = key4.getPublicExponent();

            RSAPublicKey key5 = RSAEncryptionUtil.loadRSAPublicKey("resources/gustav.pub");
            BigInteger m5 = key5.getModulus();
            BigInteger c5 = RSAEncryptionUtil.loadCiphertext("resources/message-gustav.enc");
            BigInteger e5 = key5.getPublicExponent();


            RSAPrivateKey privkey4 = tryCommonFactorAttack(m4, m5, e4);
            RSAPrivateKey privkey5 = tryCommonFactorAttack(m5, m4, e5);

            System.out.println("\n\nMessages to Fred and Gustav; successfully decrypted with CommonFactorAttack:");
            System.out.println(RSAEncryptionUtil.decrypt(c4.toByteArray(),privkey4));
            System.out.println(RSAEncryptionUtil.decrypt(c5.toByteArray(),privkey5));

            System.out.println("\n\nMessage to Hans; successfully decrypted with SmallLengthAttack:");
            BigInteger c6 = RSAEncryptionUtil.loadCiphertext("resources/message-hans.enc");

            BigInteger message = RSAEncryptionUtil.cubeRoot(c6);
            System.out.println(new String(message.toByteArray(), StandardCharsets.US_ASCII));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
