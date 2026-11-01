package io.vctrust.trust.server.security;

import io.vctrust.trust.core.policy.ClientProfile;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/** Injects the authenticated {@link ClientProfile} into controller methods. */
public class ClientProfileArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return ClientProfile.class.equals(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mav, NativeWebRequest request,
                                  WebDataBinderFactory binderFactory) {
        Object p = request.getAttribute(ClientAuthenticationFilter.ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        if (p == null) {
            throw new IllegalStateException("No client profile on request");
        }
        return p;
    }
}
