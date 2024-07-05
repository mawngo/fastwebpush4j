package io.github.mawngo.fastwebpush4j;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@RequiredArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class Subscription {
    private final String endpoint;
    private final Keys keys;

    /**
     * The generated local key. When enabled, the {@link VapidPusher} will set the generated public key and secret for reusing.
     */
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
        private final long at;
    }
}
