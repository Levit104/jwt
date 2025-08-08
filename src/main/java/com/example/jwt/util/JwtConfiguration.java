package com.example.jwt.util;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import lombok.Getter;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.Assert;

import javax.crypto.spec.SecretKeySpec;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

@Getter
public class JwtConfiguration {
    private final JwtDecoder decoder;
    private final JwtIssuer issuer;

    private JwtConfiguration(JwtDecoder decoder, JwtIssuer issuer) {
        this.decoder = decoder;
        this.issuer = issuer;
    }

    public static SecretJwtConfigurationBuilder withSecret(String secret) {
        return new SecretJwtConfigurationBuilder(secret);
    }

    public static RSAKeysJwtConfigurationBuilder withRSAKeys(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        return new RSAKeysJwtConfigurationBuilder(publicKey, privateKey);
    }

    public static final class SecretJwtConfigurationBuilder {
        private final String secret;
        private MacAlgorithm algorithm = MacAlgorithm.HS256;
        private Duration lifetime = Duration.ofHours(1);

        private SecretJwtConfigurationBuilder(String secret) {
            Assert.notNull(secret, "secret cannot be null");
            this.secret = secret;
        }

        public SecretJwtConfigurationBuilder algorithm(MacAlgorithm algorithm) {
            Assert.notNull(algorithm, "algorithm cannot be null");
            this.algorithm = algorithm;
            return this;
        }

        public SecretJwtConfigurationBuilder algorithm(String algorithm) {
            Assert.notNull(algorithm, "algorithm cannot be null");
            var parsedAlgorithm = MacAlgorithm.from(algorithm);
            Assert.notNull(parsedAlgorithm, "invalid algorithm");
            this.algorithm = parsedAlgorithm;
            return this;
        }

        public SecretJwtConfigurationBuilder lifetime(Duration lifetime) {
            Assert.notNull(lifetime, "lifetime cannot be null");
            this.lifetime = lifetime;
            return this;
        }

        public JwtConfiguration build() {
            return new JwtConfiguration(decoder(), issuer());
        }

        private JwtDecoder decoder() {
            var secretKey = new SecretKeySpec(this.secret.getBytes(), "HmacSHA256"); // здесь алгоритм ни на что не влияет
            return NimbusJwtDecoder
                    .withSecretKey(secretKey)
                    .macAlgorithm(this.algorithm)
                    .build();
        }

        private JwtIssuer issuer() {
            var jwkSource = new ImmutableSecret<>(this.secret.getBytes());
            var encoder = new NimbusJwtEncoder(jwkSource);
            return new DefaultJwtIssuer(encoder, this.algorithm, this.lifetime);
        }
    }

    public static final class RSAKeysJwtConfigurationBuilder {
        private final RSAPublicKey publicKey;
        private final RSAPrivateKey privateKey;
        private SignatureAlgorithm algorithm = SignatureAlgorithm.RS256;
        private Duration lifetime = Duration.ofHours(1);

        private RSAKeysJwtConfigurationBuilder(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
            Assert.notNull(publicKey, "publicKey cannot be null");
            Assert.notNull(privateKey, "privateKey cannot be null");
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public RSAKeysJwtConfigurationBuilder algorithm(SignatureAlgorithm algorithm) {
            Assert.notNull(algorithm, "algorithm cannot be null");
            this.algorithm = algorithm;
            return this;
        }

        public RSAKeysJwtConfigurationBuilder algorithm(String algorithm) {
            Assert.notNull(algorithm, "algorithm cannot be null");
            var parsedAlgorithm = SignatureAlgorithm.from(algorithm);
            Assert.notNull(parsedAlgorithm, "invalid algorithm");
            this.algorithm = parsedAlgorithm;
            return this;
        }

        public RSAKeysJwtConfigurationBuilder lifetime(Duration lifetime) {
            Assert.notNull(lifetime, "lifetime cannot be null");
            this.lifetime = lifetime;
            return this;
        }

        public JwtConfiguration build() {
            return new JwtConfiguration(decoder(), issuer());
        }

        private JwtDecoder decoder() {
            return NimbusJwtDecoder
                    .withPublicKey(this.publicKey)
                    .signatureAlgorithm(this.algorithm)
                    .build();
        }

        private JwtIssuer issuer() {
            var jwk = new RSAKey.Builder(this.publicKey).privateKey(this.privateKey).build();
            var jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
            var encoder = new NimbusJwtEncoder(jwkSource);
            return new DefaultJwtIssuer(encoder, this.algorithm, this.lifetime);
        }
    }
}
