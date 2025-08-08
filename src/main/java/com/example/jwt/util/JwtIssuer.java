package com.example.jwt.util;

import org.springframework.security.core.Authentication;

public interface JwtIssuer {
    String issueToken(Authentication authentication);
}
