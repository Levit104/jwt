package com.example.jwt.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    public UserDto createUser(UserCreationDto userCreationDto) {
        if (userRepository.existsByUsername(userCreationDto.username())) {
            throw new UserExistsException("Username taken");
        }

        var user = userMapper.toEntity(userCreationDto);
        user.setPassword(passwordEncoder.encode(userCreationDto.password()));
        userRepository.save(user);

        return userMapper.toDto(user);
    }

    public UserDto getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(userMapper::toDto)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    public List<UserDto> getAllUsers() {
        return userMapper.toDtoList(userRepository.findAll());
    }
}
