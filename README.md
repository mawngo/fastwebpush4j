# Fast Webpush for Java

Implement of VAPID webpush that sacrifice security and feature for raw speed.

This library use jetty client to send push for better http2 performance over java `HttpClient`, thus make the minimum
supported java version to be at least 17.

## Installation

Require java 17+.

Add library to gradle dependencies.

```groovy
dependencies {
    implementation 'io.github.mawngo:fastwebpush4j:1.0.0'
}
```

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
            .vapidTokenTTL(2, TimeUnit.HOURS) // Configure vapid cache time.
            .localKeyTTL(10, TimeUnit.HOURS)  // Enable local key caching.
            .build();

        // Send the message.
        final var res = pusher.prepareRequest("Test".getBytes(), sub).send();
        System.out.println(res.getStatus());
        // Close after used.
        pusher.close();
    }
}
```
