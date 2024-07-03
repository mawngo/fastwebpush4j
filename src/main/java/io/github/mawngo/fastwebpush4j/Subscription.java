package io.github.mawngo.fastwebpush4j;


import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@RequiredArgsConstructor
@Getter
@Setter
public class Subscription {
    private final String endpoint;
    private final Keys keys;
    private LocalKey localKey;

    @RequiredArgsConstructor
    @Getter
    @Setter
    public static final class Keys {
        private final String p256dh;
        private final String auth;
    }


    @Getter
    @Setter
    @RequiredArgsConstructor
    public static final class LocalKey {
        private final String secret;
        private final String publicKey;
        private final long expire;
    }
}
