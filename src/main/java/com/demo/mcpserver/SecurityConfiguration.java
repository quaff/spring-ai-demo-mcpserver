package com.demo.mcpserver;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.authorizationServer;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(SecurityConfiguration.RsaKeyProperties.class)
class SecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
			.with(authorizationServer(), Customizer.withDefaults())
			.oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()))
			.csrf(CsrfConfigurer::disable)
			.cors(Customizer.withDefaults())
			.build();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(RsaKeyProperties properties) {
		RSAKey rsaKey = new RSAKey.Builder(properties.publicKey())
				.privateKey(properties.privateKey())
				.keyID("secured-key-id")
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	@ConfigurationProperties("rsa-keys")
	public record RsaKeyProperties(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

	}
}