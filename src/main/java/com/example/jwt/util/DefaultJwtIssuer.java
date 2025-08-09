package com.example.jwt.util;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.time.Duration;
import java.time.Instant;

@RequiredArgsConstructor
public class DefaultJwtIssuer implements JwtIssuer {
    private final JwtEncoder encoder;
    private final JwsAlgorithm algorithm;
    private final Duration lifetime;

    @Override
    public Jwt issueToken(Authentication authentication) {
        var header = JwsHeader.with(algorithm).type("JWT").build();

        var now = Instant.now();

        var authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        var claims = JwtClaimsSet.builder()
                .subject(authentication.getName())
                .issuedAt(now)
                .expiresAt(now.plus(lifetime))
                .claim("scp", authorities)
                .build();

        return encoder.encode(JwtEncoderParameters.from(header, claims));
    }
}
