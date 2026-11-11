package io.vctrust.trust.server;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.vctrust.trust.core.policy.ClientProfile;
import org.springdoc.core.utils.SpringDocUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
@OpenAPIDefinition(info = @Info(title = "Wallet Proxy trust service", version = "1",
        description = "Signed trust snapshots for wallets and verifiers, and a proxy for the lookups they need about issuers and verifiers: "
                + "issuer metadata, DID documents, CRLs and credential status lists. See docs/architecture.md. "
                + "Every operation needs a client, except discovery (/.well-known/**)."),
        security = {@SecurityRequirement(name = "bearer"), @SecurityRequirement(name = "apiKey")})
@SecurityScheme(name = "bearer", type = SecuritySchemeType.HTTP, scheme = "bearer",
        description = "An OAuth 2.0 JWT access token (RFC 9068) of the operator's authorization server, or an API key where those are enabled")
@SecurityScheme(name = "apiKey", type = SecuritySchemeType.APIKEY, in = SecuritySchemeIn.HEADER, paramName = "X-API-Key",
        description = "An API key (development, or behind another gateway)")
public class TrustServerApplication {

    static {
        // The calling client is resolved from the request's credentials; it is not a parameter of any operation.
        SpringDocUtils.getConfig().addRequestWrapperToIgnore(ClientProfile.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(TrustServerApplication.class, args);
    }
}
