package io.github.mawngo.fastwebpush4j;

import lombok.experimental.UtilityClass;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

import static io.github.mawngo.fastwebpush4j.Utils.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.crypto.Cipher.ENCRYPT_MODE;

/**
 * An implementation of Encrypted Content-Encoding for HTTP.
 * <p>
 * The first implementation follows the specification in [1]. The specification later moved from "aesgcm" to "aes128gcm" as content encoding [2]. To
 * remain backwards compatible this library supports both.
 * <p>
 * [1] <a href="https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-01">...</a> [2]
 * <a href="https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-09">...</a>
 * <p>
 * TODO: Support multiple records (not needed for Web Push)
 */
@UtilityClass
public class HttpEceUtils {
    public static final int SHA_256_LENGTH = 32;
    public static final int TAG_SIZE = 16;
    public static final String WEB_PUSH_INFO = "WebPush: info\0";

    /**
     * Encrypt the given plaintext.
     *
     * @param plaintext Payload to encrypt.
     * @param salt      A random 16-byte buffer
     */
    public byte[] encrypt(KeyPair localKeypair, byte[] plaintext, byte[] salt, Subscription subscription, long expireNanos) throws GeneralSecurityException {
        log("encrypt", plaintext);

        // Reuse the local key if it's still valid.
        // expireNanos <= 0 mean we disabled this feature.
        if (subscription.getLocalKey() != null && expireNanos > 0) {
            final var localKey = subscription.getLocalKey();
            if (localKey.getExpire() > 0 && localKey.getExpire() > Instant.now().toEpochMilli()) {
                final var decode = Base64.getUrlDecoder();
                return encrypt(
                        decode.decode(localKey.getPublicKey()),
                        decode.decode(localKey.getSecret()),
                        plaintext,
                        salt
                );
            }
            subscription.setLocalKey(null);
        }

        final var dh = (ECPublicKey) Utils.loadPublicKey(subscription.getKeys().getP256dh());
        final var authSecret = Utils.decodeBase64(subscription.getKeys().getAuth());

        final byte[][] keyAndNonce = deriveKeyAndNonce(localKeypair, salt, dh, authSecret);
        final byte[] localPublicKey = encode((ECPublicKey) localKeypair.getPublic());
        final var encoder = Base64.getUrlEncoder().withoutPadding();

        // Write computed public and secret to subscription.
        subscription.setLocalKey(
                new Subscription.LocalKey(
                        encoder.encodeToString(keyAndNonce[2]),
                        encoder.encodeToString(localPublicKey),
                        Instant.now().plus(expireNanos, ChronoUnit.NANOS).toEpochMilli()
                )
        );
        return encrypt(keyAndNonce, localPublicKey, plaintext, salt);
    }

    private byte[] encrypt(byte[] localPublicKey, byte[] secret, byte[] plaintext, byte[] salt) throws GeneralSecurityException {
        log("encrypt", plaintext);
        byte[][] keyAndNonce = deriveKeyAndNonce(secret, salt);
        return encrypt(keyAndNonce, localPublicKey, plaintext, salt);
    }

    private byte[] encrypt(byte[][] keyAndNonce, byte[] localPublicKey, byte[] plaintext, byte[] salt) throws GeneralSecurityException {
        byte[] key = keyAndNonce[0];
        byte[] nonce = keyAndNonce[1];

        // Note: Cipher adds the tag to the end of the ciphertext
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec params = new GCMParameterSpec(TAG_SIZE * 8, nonce);
        cipher.init(ENCRYPT_MODE, new SecretKeySpec(key, "AES"), params);

        // For AES128GCM suffix {0x02}.
        final byte[] header = buildHeader(localPublicKey, salt, plaintext.length);
        final byte[] encrypted = concat(cipher.update(plaintext), cipher.update(new byte[]{2}), cipher.doFinal());
        return concat(header, encrypted);
    }

    private byte[] buildHeader(byte[] localPublicKeyByte, byte[] salt, int len) {
        byte[] rs = toByteArray(len * 8, 4);
        byte[] idlen = new byte[]{(byte) localPublicKeyByte.length};
        return concat(salt, rs, idlen, localPublicKeyByte);
    }

    /**
     * Convenience method for computing the HMAC Key Derivation Function. The real work is offloaded to BouncyCastle.
     */
    private static byte[] hkdfExpand(byte[] ikm, byte[] salt, byte[] info, int length) {
        log("salt", salt);
        log("ikm", ikm);
        log("info", info);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, salt, info));

        byte[] okm = new byte[length];
        hkdf.generateBytes(okm, 0, length);

        log("expand", okm);

        return okm;
    }


    private byte[][] deriveKeyAndNonce(KeyPair localKeypair, byte[] salt, ECPublicKey dh, byte[] authSecret) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] secret = extractSecret(localKeypair, dh, authSecret);
        return deriveKeyAndNonce(secret, salt);
    }

    private byte[][] deriveKeyAndNonce(byte[] secret, byte[] salt) {
        byte[] keyInfo = "Content-Encoding: aes128gcm\0".getBytes(UTF_8);
        byte[] nonceInfo = "Content-Encoding: nonce\0".getBytes(UTF_8);

        byte[] hkdf_key = hkdfExpand(secret, salt, keyInfo, 16);
        byte[] hkdf_nonce = hkdfExpand(secret, salt, nonceInfo, 12);

        log("key", hkdf_key);
        log("nonce", hkdf_nonce);

        return new byte[][]{
                hkdf_key,
                hkdf_nonce,
                secret
        };
    }

    private byte[] extractSecret(KeyPair localKeypair, ECPublicKey dh, byte[] authSecret) throws InvalidKeyException, NoSuchAlgorithmException {
        if (dh == null) {
            return encode((ECPublicKey) localKeypair.getPublic());
        }

        return webpushSecret(localKeypair, dh, authSecret);
    }

    /**
     * Combine Shared and Authentication Secrets
     * <p>
     * See <a href="https://tools.ietf.org/html/draft-ietf-webpush-encryption-09#section-3.3">...</a>.
     */
    public byte[] webpushSecret(KeyPair localKeypair, ECPublicKey dh, byte[] authSecret) throws NoSuchAlgorithmException, InvalidKeyException {
        ECPublicKey senderPubKey = (ECPublicKey) localKeypair.getPublic();

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(localKeypair.getPrivate());
        keyAgreement.doPhase(dh, true);
        byte[] ikm = keyAgreement.generateSecret();
        byte[] info = concat(WEB_PUSH_INFO.getBytes(UTF_8), encode(dh), encode(senderPubKey));
        return hkdfExpand(ikm, authSecret, info, SHA_256_LENGTH);
    }

    /**
     * Print the length and unpadded url-safe base64 encoding of the byte array.
     */
    private static byte[] log(String info, byte[] array) {
        if ("1".equals(System.getenv("ECE_KEYLOG"))) {
            System.out.println(info + " [" + array.length + "]: " + Base64.getUrlEncoder().withoutPadding().encodeToString(array));
        }

        return array;
    }
}
