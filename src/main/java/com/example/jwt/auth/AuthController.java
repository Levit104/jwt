package com.example.jwt.auth;

import com.example.jwt.user.UserCreationDto;
import com.example.jwt.user.UserDto;
import com.example.jwt.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final UserService userService;

    @PostMapping("/sign-up")
    public UserDto signUp(@RequestBody @Valid UserCreationDto userCreationDto) {
        return userService.createUser(userCreationDto);
    }

    @PostMapping("/sign-in")
    public AuthResponseDto signIn(@RequestBody @Valid AuthRequestDto authRequestDto) {
        return authService.signIn(authRequestDto);
    }
}