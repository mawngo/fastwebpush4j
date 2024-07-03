package io.github.mawngo.fastwebpush4j;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Accessors(fluent = true, chain = true)
@Getter
@Setter
public class NotificationOptions {
    private long ttl;
}
