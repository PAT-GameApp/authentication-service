package com.cognizant.authentication_service.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserRegisterResponseDTO {
    private Long userId;
    private String userName;
    private String email;
    private String phoneNumber;
    private String role;
    private String department;
    private String officeLocation;
}
