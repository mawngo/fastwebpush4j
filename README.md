# Fast Webpush for Java

Implement of VAPID webpush that sacrifice security and feature for raw speed.

This library use java `HttpClient` for sending push.

## Installation

Require java 11+.

Add library to gradle dependencies.

```groovy
dependencies {
    implementation 'io.github.mawngo:fastwebpush4j:2.0.1-java11'
}
```
## Optimization

This library provides some optimizations which can be enabled when creating `VapidPusher`.

- `vapidTokenTTL`: Caching vapid jwt token, and local public key + secret for each host. This optimization is enabled by
  default and can be disabled by setting it to `0`.
- `localSecretTTL`: Enable local public key and secret reuse. When enabled, the pusher
  will reuse local public key and secret if provided in `Subscription.LocalKey` otherwise it generate secret and
  local public key to `Subscription.LocalKey`. We can save those case for reuse for the later push to the same
  `Subscription`.
- `withRandom`: Allow to configure alternative `Random` implementation.

## Example Usage

```java
package io.github.mawngo.fastwebpush4j.example;

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
