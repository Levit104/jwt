package com.example.jwt.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final AuthTokenIssuer authTokenIssuer;

    public AuthResponseDto signIn(AuthRequestDto authRequestDto) {
        var authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequestDto.username(), authRequestDto.password())
        );

        var token = authTokenIssuer.issueToken(authentication);
        return new AuthResponseDto(token);
    }
}
