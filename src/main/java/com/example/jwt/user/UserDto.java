package com.example.jwt.user;

public record UserDto(
        Long id,
        String username,
        String firstName,
        String lastName,
        Short age
) {
}