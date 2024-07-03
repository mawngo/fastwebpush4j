package io.github.mawngo.fastwebpush4j;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.client.BytesRequestContent;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.Request;
import org.eclipse.jetty.client.Response;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.util.component.LifeCycle;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import java.io.Closeable;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public final class VapidPusher implements Closeable {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final ConcurrentHashMap<String, ReusableWebPushKeys> cache = new ConcurrentHashMap<>();

    private final Random random;

    private final HttpClient client;

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

    private final long localKeyExpireNanos;

    private final long pushTimeoutNanos;

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
                HttpClient client,
                Random random) throws Exception {
        this.subject = subject;
        this.client = client;
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

        // Start the client.
        this.client.start();
    }

    /**
     * Create webpush request. After created, use {@link Request#send(Response.CompleteListener) send} to send request
     */
    public Request prepareRequest(byte[] payload, Subscription subscription, NotificationOptions options) {
        try {
            return doPrepareRequest(payload, subscription, options);
        } catch (MalformedURLException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public Request prepareRequest(byte[] payload, Subscription subscription) {
        return prepareRequest(payload, subscription, new NotificationOptions());
    }

    private Request doPrepareRequest(byte[] payload, Subscription subscription, NotificationOptions options) throws GeneralSecurityException, MalformedURLException {
        final var url = new URL(subscription.getEndpoint());
        final var keys = generateKeys(url.getProtocol() + "://" + url.getHost());

        final var salt = new byte[16];
        random.nextBytes(salt);
        final var ciphertext = HttpEceUtils.encrypt(keys.keyPair, payload, salt, subscription, localKeyExpireNanos);

        return client.newRequest(subscription.getEndpoint())
                .method(HttpMethod.POST)
                .timeout(pushTimeoutNanos, TimeUnit.NANOSECONDS)
                .headers(header -> {
                    header.add("TTL", String.valueOf(options.ttl()));
                    header.add("Content-Encoding", "aes128gcm");
                    header.add("Authorization", "vapid t=" + keys.jws + ", k=" + base64PublicKeyCryptoWithoutPadding);
                    if (options.topic() != null && !options.topic().isEmpty()) {
                        header.add("Topic", options.topic());
                    }
                    if (options.urgency() != null) {
                        header.add("Urgency", options.urgency().getHeaderValue());
                    }
                })
                .body(new BytesRequestContent("application/octet-stream", ciphertext));
    }

    /**
     * Generate or reuse keypair, jws for each origin.
     *
     * @see #generateJws jws expire time
     */
    private ReusableWebPushKeys generateKeys(String origin) {
        return cache.compute(origin, (ignored, pushKeys) -> {
            var now = Instant.now();
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
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
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

    @RequiredArgsConstructor
    private static final class ReusableWebPushKeys {
        final KeyPair keyPair;
        final String jws;
        final Instant expireAt;
    }


    /**
     * Close the backing {@link HttpClient client}
     */
    @Override
    public void close() {
        new Thread(() -> LifeCycle.stop(client)).start();
    }
}
