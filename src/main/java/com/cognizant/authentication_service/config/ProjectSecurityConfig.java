package com.cognizant.authentication_service.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class ProjectSecurityConfig {
    
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception{
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = 
                        OAuth2AuthorizationServerConfigurer.authorizationServer();
        
        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer,
                    (authorizationServer) -> authorizationServer.oidc(Customizer.withDefaults()))
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            .exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"), 
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            );
        
            return http.build();
    }
    
    @Bean
    @Order(2)
    public SecurityFilterChain defauSecurityFilterChain(HttpSecurity http) throws Exception{
        http
            // This chain handles API and general web endpoints (not auth-server endpoints)
            .securityMatcher("/api/**", "/login", "/")
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests((authorize) -> authorize
                .requestMatchers("/api/auth/register").permitAll()
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public RegisteredClientRepository registeredClientRepository(){
        // Raw client secret that external clients must use
        String rawClientSecret = "my-client-secret";

        // Encode the client secret using the same PasswordEncoder
        String encodedClientSecret = passwordEncoder().encode(rawClientSecret);

        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("oidc-client")
        .clientSecret(encodedClientSecret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .redirectUri("http://127.0.0.1:3000/callback")
        .postLogoutRedirectUri("http://127.0.0.1:3000/")
        .scopes(scopeConfig -> scopeConfig.addAll(List.of(OidcScopes.OPENID, "ADMIN", "USER")))
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.PROFILE)
        .clientSettings(
            ClientSettings
            .builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();
        return new InMemoryRegisteredClientRepository(oidcClient);    
    }
    
    @Bean
    public JWKSource<SecurityContext> jwkSource(){
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
    
    public static KeyPair generateRsaKey(){
        KeyPair keyPair;
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex){
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
    
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().build();
    }

}
