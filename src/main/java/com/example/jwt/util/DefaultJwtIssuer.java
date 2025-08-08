package com.example.jwt.util;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Duration;
import java.time.Instant;

@RequiredArgsConstructor
public class DefaultJwtIssuer implements JwtIssuer {
    private final JwtEncoder encoder;
    private final JwsAlgorithm algorithm;
    private final Duration lifetime;

    @Override
    public String issueToken(Authentication authentication) {
        var now = Instant.now();

        var scope = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        var header = JwsHeader.with(algorithm).type("JWT").build();

        var claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(lifetime))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();

        var jwt = encoder.encode(JwtEncoderParameters.from(header, claims));

        return jwt.getTokenValue();
    }
}
