package io.github.mawngo.fastwebpush4j;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.WWWAuthenticationProtocolHandler;
import org.eclipse.jetty.client.transport.HttpClientConnectionFactory;
import org.eclipse.jetty.client.transport.HttpClientTransportDynamic;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.transport.ClientConnectionFactoryOverHTTP2;
import org.eclipse.jetty.io.ClientConnectionFactory;
import org.eclipse.jetty.io.ClientConnector;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public final class VapidPusherBuilder {
    private final String subject;
    private final String encodedPublicKey;
    private final String encodedPrivateKey;

    private Random random;
    private HttpClient client;
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
     * Configure the client used to push the message. The client must not be started.
     */
    public VapidPusherBuilder withClient(HttpClient client) {
        this.client = client;
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
    public VapidPusherBuilder localKeyTTL(long expiry, TimeUnit unit) {
        this.localKeyExpireNanos = unit.toNanos(expiry);
        return this;
    }

    /**
     * Use default client with specific http version enabled.
     */
    @Deprecated
    public VapidPusherBuilder withClientHttpVersion(String... httpVersions) {
        final ClientConnector connector = new ClientConnector();
        final var clientConnections = Arrays.stream(httpVersions).map(version -> {
            switch (version) {
                case "1.1":
                    return HttpClientConnectionFactory.HTTP11;
                case "2":
                    final HTTP2Client http2Client = new HTTP2Client(connector);
                    return new ClientConnectionFactoryOverHTTP2.HTTP2(http2Client);
            }
            throw new IllegalArgumentException("Invalid http version " + version + ": not supported");
        }).toArray(ClientConnectionFactory.Info[]::new);

        final HttpClientTransportDynamic transport = new HttpClientTransportDynamic(connector, clientConnections);
        final var client = new HttpClient(transport);
        client.setConnectBlocking(false);
        client.getContentDecoderFactories().clear();
        client.getProtocolHandlers().remove(WWWAuthenticationProtocolHandler.NAME);
        this.client = client;
        return this;
    }

    private Random getRandom() {
        if (random == null) {
            random = new SecureRandom();
        }
        return random;
    }

    private HttpClient getClient() {
        if (client == null) {
            withClientHttpVersion("2", "1.1");
        }
        return client;
    }

    public VapidPusher build() throws Exception {
        return new VapidPusher(
                subject,
                encodedPublicKey,
                encodedPrivateKey,
                pushTimeoutNanos,
                vapidTokenExpireNanos,
                localKeyExpireNanos,
                getClient(),
                getRandom()
        );
    }
}
