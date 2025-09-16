package com.demo.mcpserver;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimAccessor;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Configuration
public class ResourceServerConfiguration {

    @Bean
    static BeanPostProcessor beanPostProcessor() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
                if (bean instanceof SpringOpaqueTokenIntrospector introspector) {
                    Converter<OAuth2TokenIntrospectionClaimAccessor, ? extends OAuth2AuthenticatedPrincipal> authenticationConverter = (accessor) -> {
                        Collection<GrantedAuthority> authorities = new ArrayList<>();
                        List<String> scopes = accessor.getScopes();
                        if (scopes != null) {
                            for (String scope : scopes) {
                                authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
                            }
                        }

                        List<String> roles = accessor.getClaimAsStringList("role");
                        if (roles != null) {
                            for (String role : roles) {
                                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                            }
                        }
                        return new OAuth2IntrospectionAuthenticatedPrincipal(accessor.getClaims(), authorities);
                    };
                    introspector.setAuthenticationConverter(authenticationConverter);
                }
                return bean;
            }
        };
    }
}
