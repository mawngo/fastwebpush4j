package io.github.mawngo;

import lombok.experimental.UtilityClass;

@UtilityClass
public class HelloWorldUtils {
    public String sayHello(String name) {
        return "Hello " + name + "!";
    }
}
