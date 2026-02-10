package com.cognizant.authentication_service.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserRegisterRequestDTO {
    @NotNull(message = "User ID is required")
    @Positive(message = "User ID must be a positive number")
    private Long userId;
    private String userName;
    private String email;
    private String phoneNumber;
    private String role;
    private String department;
    private Long locationId;
    private String password;
}
