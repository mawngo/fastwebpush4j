# Fast Webpush for Java

Implement of VAPID webpush that sacrifice security and feature for raw speed.

This library use jetty client to send push for better http2 performance over java `HttpClient`, thus make the minimum
supported java version to be at least 17.
