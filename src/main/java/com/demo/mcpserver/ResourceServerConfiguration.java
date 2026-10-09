package com.demo.mcpserver;

import org.springframework.boot.security.oauth2.server.resource.autoconfigure.SpringOpaqueTokenIntrospectorBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Configuration
public class ResourceServerConfiguration {

    @Bean
    SpringOpaqueTokenIntrospectorBuilderCustomizer springOpaqueTokenIntrospectorBuilderCustomizer() {
        return builder -> builder.postProcessor(introspector ->
                introspector.setAuthenticationConverter(accessor -> {
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
                }));
    }

}
