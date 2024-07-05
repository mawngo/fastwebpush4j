package io.github.mawngo.fastwebpush4j;

import lombok.Value;
import lombok.experimental.Accessors;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import java.io.Closeable;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Vapid push service.
 */
public final class VapidPusher implements Closeable {
    // Initialize the BouncyCastle provider.
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Vapid token and local key cache
     */
    private final ConcurrentHashMap<String, ReusableWebPushKeys> cache = new ConcurrentHashMap<>();

    /**
     * Random generator for generating salt.
     */
    private final Random random;

    /**
     * Subject used in the JWT payload (for VAPID)
     */
    private final String subject;

    /**
     * The public key (for VAPID)
     */
    private final String base64PublicKeyCryptoWithoutPadding;

    /**
     * The private key (for VAPID)
     */
    private final PrivateKey privateKey;

    /**
     * The token expire time (for VAPID)
     */
    private final long vapidTokenExpireNanos;

    /**
     * The generate local secret and public key timeout
     */
    private final long localKeyExpireNanos;

    /**
     * The push sending timeout
     */
    private final long pushTimeoutNanos;

    /**
     * New {@link VapidPusherBuilder} for creating {@link VapidPusher} instance.
     */
    public static VapidPusherBuilder builder(String subject,
                                             String encodedPublicKey,
                                             String encodedPrivateKey) {
        return new VapidPusherBuilder(subject, encodedPublicKey, encodedPrivateKey);
    }

    VapidPusher(String subject,
                String encodedPublicKey,
                String encodedPrivateKey,
                long pushTimeoutNanos,
                long vapidTokenExpireNanos,
                long localKeyExpireNanos,
                Random random) throws Exception {
        this.subject = subject;
        this.random = random;
        this.vapidTokenExpireNanos = vapidTokenExpireNanos;
        this.pushTimeoutNanos = pushTimeoutNanos;
        this.localKeyExpireNanos = localKeyExpireNanos;

        final var publicKey = Utils.loadPublicKey(encodedPublicKey);
        this.privateKey = Utils.loadPrivateKey(encodedPrivateKey);
        if (privateKey == null || publicKey == null) {
            throw new IllegalStateException("Missing public key or private key");
        }
        if (!Utils.verifyKeyPair(privateKey, publicKey)) {
            throw new IllegalStateException("Public key and private key do not match.");
        }
        final var pk = Utils.encode((ECPublicKey) publicKey);
        base64PublicKeyCryptoWithoutPadding = Base64.getUrlEncoder().withoutPadding().encodeToString(pk);
    }

    /**
     * Create webpush request. After created, use {@link HttpClient#send(HttpRequest, HttpResponse.BodyHandler)} to send request.
     */
    public HttpRequest prepareRequest(byte[] payload, Subscription subscription, NotificationOptions options) {
        try {
            return doPrepareRequest(payload, subscription, options);
        } catch (MalformedURLException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create webpush request. After created, use {@link HttpClient#send(HttpRequest, HttpResponse.BodyHandler)} to send request.
     */
    public HttpRequest prepareRequest(byte[] payload, Subscription subscription) {
        return prepareRequest(payload, subscription, new NotificationOptions());
    }

    private HttpRequest doPrepareRequest(byte[] payload, Subscription subscription, NotificationOptions options) throws GeneralSecurityException, MalformedURLException {
        final var url = new URL(subscription.getEndpoint());
        final var keys = generateKeys(url.getProtocol() + "://" + url.getHost());

        final var salt = new byte[16];
        random.nextBytes(salt);
        final var ciphertext = HttpEceUtils.encrypt(keys.keyPair, payload, salt, subscription, localKeyExpireNanos);

        final var builder = HttpRequest.newBuilder();
        builder
                .header("TTL", String.valueOf(options.ttl()))
                .header("Content-Encoding", "aes128gcm")
                .header("Authorization", "vapid t=" + keys.jws + ", k=" + base64PublicKeyCryptoWithoutPadding)
                .header("Content-Type", "application/octet-stream");
        if (options.urgency() != null) {
            builder.header("Urgency", options.urgency().getHeaderValue());
        }
        if (options.topic() != null && !options.topic().isEmpty()) {
            builder.header("Topic", options.topic());
        }
        try {
            return builder
                    .uri(url.toURI())
                    .POST(HttpRequest.BodyPublishers.ofByteArray(ciphertext))
                    .timeout(Duration.ofNanos(pushTimeoutNanos))
                    .build();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Generate or reuse keypair, jws for each origin.
     *
     * @see #generateJws jws expire time
     */
    private ReusableWebPushKeys generateKeys(String origin) {
        final var now = Instant.now();
        if (vapidTokenExpireNanos <= 0) {
            return new ReusableWebPushKeys(
                    generateLocalKeyPair(),
                    generateJws(origin),
                    now
            );
        }
        return cache.compute(origin, (ignored, pushKeys) -> {
            if (pushKeys == null || pushKeys.expireAt.isBefore(now)) {
                return new ReusableWebPushKeys(
                        generateLocalKeyPair(),
                        generateJws(origin),
                        now.plusNanos(vapidTokenExpireNanos)
                );
            }
            return pushKeys;
        });
    }

    /**
     * Generate the local (ephemeral) keys.
     */
    private static KeyPair generateLocalKeyPair() {
        try {
            final var parameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
            keyPairGenerator.initialize(parameterSpec);

            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String generateJws(String origin) {
        final var claims = new JwtClaims();
        claims.setAudience(origin);
        claims.setExpirationTimeMinutesInTheFuture(12 * 60);
        claims.setSubject(subject);

        final var jws = new JsonWebSignature();
        jws.setHeader("typ", "JWT");
        jws.setHeader("alg", "ES256");
        jws.setPayload(claims.toJson());
        jws.setKey(privateKey);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        try {
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new IllegalStateException(e);
        }
    }

    @Value
    @Accessors(fluent = true)
    private static class ReusableWebPushKeys {
        KeyPair keyPair;
        String jws;
        Instant expireAt;
    }


    /**
     * Close the backing {@link HttpClient client}
     */
    @Override
    @Deprecated
    public void close() {
        // No-op.
    }
}
