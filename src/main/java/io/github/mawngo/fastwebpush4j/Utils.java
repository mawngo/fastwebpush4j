package io.github.mawngo.fastwebpush4j;

import lombok.experimental.UtilityClass;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

@UtilityClass
public class Utils {
    private static final String CURVE = "prime256v1";
    private static final String ALGORITHM = "ECDH";

    public static byte[] decodeBase64(String toDecode) {
        try {
            return Base64.getUrlDecoder().decode(toDecode);
        } catch (Exception e) {
            return Base64.getDecoder().decode(toDecode);
        }
    }

    /**
     * Create a byte array of the given length from the given integer.
     */
    public static byte[] toByteArray(int integer, int size) {
        final ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.putInt(integer);
        return buffer.array();
    }

    /**
     * Utility to concat byte arrays
     */
    public static byte[] concat(byte[]... arrays) {
        int lastPos = 0;

        byte[] combined = new byte[combinedLength(arrays)];

        for (byte[] array : arrays) {
            if (array == null) {
                continue;
            }

            System.arraycopy(array, 0, combined, lastPos, array.length);

            lastPos += array.length;
        }

        return combined;
    }

    /**
     * Compute combined array length
     */
    public static int combinedLength(byte[]... arrays) {
        int combinedLength = 0;

        for (byte[] array : arrays) {
            if (array == null) {
                continue;
            }

            combinedLength += array.length;
        }

        return combinedLength;
    }

    /**
     * Get the uncompressed encoding of the public key point. The resulting array should be 65 bytes length and start with 0x04 followed by the x and
     * y coordinates (32 bytes each).
     */
    static byte[] encode(ECPublicKey publicKey) {
        return publicKey.getQ().getEncoded(false);
    }

    static byte[] encode(ECPrivateKey privateKey) {
        return privateKey.getD().toByteArray();
    }

    /**
     * Load the public key from a URL-safe base64 encoded string. Takes into account the different encodings, including point compression.
     */
    static PublicKey loadPublicKey(String encodedPublicKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedPublicKey;
        try {
            decodedPublicKey = Base64.getUrlDecoder().decode(encodedPublicKey);
        } catch (Exception e) {
            decodedPublicKey = Base64.getDecoder().decode(encodedPublicKey);
        }
        return loadPublicKey(decodedPublicKey);
    }

    /**
     * Load the public key from a byte array.
     */
    static PublicKey loadPublicKey(byte[] decodedPublicKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER_NAME);
        final ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(CURVE);
        final ECCurve curve = parameterSpec.getCurve();
        final ECPoint point = curve.decodePoint(decodedPublicKey);
        final ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, parameterSpec);
        return keyFactory.generatePublic(pubSpec);
    }

    /**
     * Load the private key from a URL-safe base64 encoded string.
     */
    static PrivateKey loadPrivateKey(String encodedPrivateKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedPrivateKey;
        try {
            decodedPrivateKey = Base64.getUrlDecoder().decode(encodedPrivateKey);
        } catch (Exception e) {
            decodedPrivateKey = Base64.getDecoder().decode(encodedPrivateKey);
        }
        return loadPrivateKey(decodedPrivateKey);
    }

    /**
     * Load the private key from a byte array.
     */
    static PrivateKey loadPrivateKey(byte[] decodedPrivateKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        final BigInteger s = BigIntegers.fromUnsignedByteArray(decodedPrivateKey);
        final ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(CURVE);
        final ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(s, parameterSpec);
        final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER_NAME);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * Verify that the private key belongs to the public key.
     */
    static boolean verifyKeyPair(PrivateKey privateKey, PublicKey publicKey) {
        final ECNamedCurveParameterSpec curveParameters = ECNamedCurveTable.getParameterSpec(CURVE);
        final ECPoint g = curveParameters.getG();
        final ECPoint sG = g.multiply(((java.security.interfaces.ECPrivateKey) privateKey).getS());
        return sG.equals(((ECPublicKey) publicKey).getQ());
    }
}
