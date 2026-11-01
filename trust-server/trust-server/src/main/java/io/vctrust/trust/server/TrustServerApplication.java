package io.vctrust.trust.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class TrustServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(TrustServerApplication.class, args);
    }
}
