package com.example.jwt.user;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingConstants;

import java.util.List;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface UserMapper {
    @Mapping(target = "id", ignore = true)
    User toEntity(UserCreationDto userCreationDto);

    UserDto toDto(User user);

    List<UserDto> toDtoList(List<User> users);
}