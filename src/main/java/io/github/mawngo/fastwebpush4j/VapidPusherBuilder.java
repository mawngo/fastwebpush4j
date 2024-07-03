package io.github.mawngo.fastwebpush4j;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
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

@Accessors(fluent = true, chain = true)
@Setter
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
     * Use default client with specific http version enabled.
     */
    @Deprecated
    private VapidPusherBuilder withClientHttpVersion(String... httpVersions) {
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
            withClientHttpVersion("1.1", "2");
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
