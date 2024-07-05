package io.github.mawngo.fastwebpush4j;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/**
 * Builder for {@link VapidPusher}
 */
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public final class VapidPusherBuilder {
    private final String subject;
    private final String encodedPublicKey;
    private final String encodedPrivateKey;

    private Random random;
    private long pushTimeoutNanos = TimeUnit.SECONDS.toNanos(30);
    private long vapidTokenExpireNanos = TimeUnit.HOURS.toNanos(6);
    private long localKeyExpireNanos = 0;


    /**
     * Configure the random instance for generating salt.
     */
    public VapidPusherBuilder withRandom(Random random) {
        this.random = random;
        return this;
    }

    /**
     * Configure the maximum timeout when pushed.
     */
    public VapidPusherBuilder pushTimeout(long timeout, TimeUnit unit) {
        this.pushTimeoutNanos = unit.toNanos(timeout);
        return this;
    }

    /**
     * Configure the expiry time of cached vapid token.
     */
    public VapidPusherBuilder vapidTokenTTL(long expiry, TimeUnit unit) {
        this.vapidTokenExpireNanos = unit.toNanos(expiry);
        return this;
    }

    /**
     * Configure the expiry time of cached local public key and secret. Set to 0 to disable any caching.
     */
    public VapidPusherBuilder localSecretTTL(long expiry, TimeUnit unit) {
        this.localKeyExpireNanos = unit.toNanos(expiry);
        return this;
    }


    private Random getRandom() {
        if (random == null) {
            random = new SecureRandom();
        }
        return random;
    }

    /**
     * Build the {@link VapidPusher}
     */
    public VapidPusher build() throws Exception {
        return new VapidPusher(
                subject,
                encodedPublicKey,
                encodedPrivateKey,
                pushTimeoutNanos,
                vapidTokenExpireNanos,
                localKeyExpireNanos,
                getRandom()
        );
    }

    /**
     * Build the {@link VapidPusher} or throw {@link IllegalArgumentException} if keypair or client is invalid.
     */
    public VapidPusher buildOrThrow() {
        try {
            return build();
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
}
