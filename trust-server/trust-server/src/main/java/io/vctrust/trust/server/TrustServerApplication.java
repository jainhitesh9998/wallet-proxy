package io.vctrust.trust.server;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
@OpenAPIDefinition(info = @Info(title = "Wallet Proxy trust service", version = "1",
        description = "Signed trust snapshots for wallets and verifiers, and a proxy for the lookups they need about issuers and verifiers: "
                + "issuer metadata, DID documents, CRLs and credential status lists. See docs/architecture.md."))
public class TrustServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(TrustServerApplication.class, args);
    }
}
