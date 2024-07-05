# Fast Webpush for Java

Implement of VAPID webpush that sacrifice security and feature for raw speed.

This library use java `HttpClient` for sending push.

## Installation

Require java 11+.

Add library to gradle dependencies.

```groovy
dependencies {
    implementation 'io.github.mawngo:fastwebpush4j:2.0.0-java11'
}
```

## Example Usage

```java
import io.github.mawngo.fastwebpush4j.Subscription;
import io.github.mawngo.fastwebpush4j.VapidPusher;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.concurrent.TimeUnit;

public class Main {
    public static void main(String[] args) throws Exception {
        // Preparation
        final var privateKey = "<VAPID_PRIVATE_KEY>";
        final var publicKey = "<VAPID_PUBLIC_KEY>";
        final var sub = new Subscription(
            "<SUB_ENDPOINT>",
            new Subscription.Keys(
                "<p256dh>",
                "<auth>"
            )
        );

        // Build the pusher.
        final var client = HttpClient.newHttpClient();
        final var pusher = VapidPusher.builder("example@example.com", publicKey, privateKey)
            .vapidTokenTTL(2, TimeUnit.HOURS)    // Configure vapid and local keypair cache time.
            .localSecretTTL(10, TimeUnit.HOURS)  // Enable local public key and secret caching.
            .build();

        // Send the message.
        var req = pusher.prepareRequest("Hello World!".getBytes(), sub);
        var res = client.send(req, HttpResponse.BodyHandlers.ofString());
        System.out.println(res.statusCode());
    }
}
```
