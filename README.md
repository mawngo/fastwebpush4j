# Fast Webpush for Java

Implement of VAPID webpush that sacrifice security and feature for raw speed.

This library use jetty client to send push for better http2 performance over java `HttpClient`, thus make the minimum
supported java version to be at least 17.

## Installation

Require java 17+. For java 11 support: check [java11 branch](https://github.com/mawngo/fastwebpush4j/tree/java11)

Add library to gradle dependencies.

```groovy
dependencies {
    implementation 'io.github.mawngo:fastwebpush4j:2.0.0'
}
```

## Optimization

This library provides some optimizations which can be enabled when creating `VapidPusher`.

- `vapidTokenTTL`: Caching vapid jwt token, and local public key + secret for each host. This optimization is enabled by
  default and can be disabled by setting it to `0`.
- `localSecretTTL`: Enable local public key and secret reuse, the pusher will reuse provided. When enabled, the pusher
  will reuse local public key and secret if provided in `Subscription.LocalKey` otherwise it generate secret and
  local public key to `Subscription.LocalKey`. We can save those case for reuse for the later push to the same
  `Subscription`.
- `withRandom`: Allow to configure alternative `Random` implementation.

## Example Usage

```java
package io.github.mawngo.fastwebpush4j.example;

import io.github.mawngo.fastwebpush4j.Subscription;
import io.github.mawngo.fastwebpush4j.VapidPusher;

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
        final var pusher = VapidPusher.builder("example@example.com", publicKey, privateKey)
            .vapidTokenTTL(2, TimeUnit.HOURS)    // Configure vapid and local keypair cache time.
            .localSecretTTL(10, TimeUnit.HOURS)  // Enable local public key and secret caching.
            .build();

        // Send the message.
        final var res = pusher.prepareRequest("Test".getBytes(), sub).send();
        System.out.println(res.getStatus());
        // Close after used.
        pusher.close();
    }
}
```
