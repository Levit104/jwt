package com.example.jwt.auth;

import java.time.Instant;

public record AuthResponseDto(
        String token,
        Instant expiresAt
) {
}
