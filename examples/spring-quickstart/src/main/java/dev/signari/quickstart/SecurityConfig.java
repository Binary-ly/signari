package dev.signari.quickstart;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Sign-in through Signari, with the two settings it needs that Spring does not assume.
 *
 * PKCE for this confidential client: Signari requires it of every client, and Spring adds
 * it by itself only for public ones. And the ID token's algorithm: Spring checks an ID
 * token's signature against the provider's published keys, expecting RS256 unless told
 * otherwise, and Signari signs with ES256 by default.
 */
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain signIn(HttpSecurity http, ClientRegistrationRepository registrations) throws Exception {
        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        http.authorizeHttpRequests(a -> a.requestMatchers("/").permitAll().anyRequest().authenticated())
                .oauth2Login(o -> o.authorizationEndpoint(e -> e.authorizationRequestResolver(resolver))
                        .defaultSuccessUrl("/me", true));
        return http.build();
    }

    /** ES256, Signari's default. A client set to another with `signari client set-alg` names it here. */
    @Bean
    JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
        OidcIdTokenDecoderFactory factory = new OidcIdTokenDecoderFactory();
        factory.setJwsAlgorithmResolver(registration -> SignatureAlgorithm.ES256);
        return factory;
    }
}
