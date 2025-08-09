package com.example.jwt.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

public interface JwtIssuer {
    Jwt issueToken(Authentication authentication);
}
