package io.vctrust.trust.server.api;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.server.service.DocumentSigner;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * Content negotiation for signed responses: when the client sends {@code Accept: application/jwt}, the JSON
 * body is wrapped as the {@code data} claim of a JWT signed by the service key ({@code typ} per endpoint),
 * audience-bound to the calling client.
 */
@Component
public class ResponseSigner {

    public static final MediaType JWT = MediaType.parseMediaType("application/jwt");

    private final DocumentSigner signer;

    public ResponseSigner(DocumentSigner signer) {
        this.signer = signer;
    }

    public static boolean wantsJwt(HttpServletRequest request) {
        String accept = request.getHeader(HttpHeaders.ACCEPT);
        return accept != null && accept.contains("application/jwt");
    }

    public ResponseEntity<Object> respond(HttpServletRequest request, ClientProfile client, String typ, Object body,
                                          ResponseEntity.BodyBuilder builder) {
        if (!wantsJwt(request)) {
            return builder.contentType(MediaType.APPLICATION_JSON).body(body);
        }
        String jwt = signer.sign(typ, body, client);
        return builder.contentType(JWT).body(jwt);
    }
}
