package com.cognizant.authentication_service.client;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserRegisterClientRequestDTO {
    private String userName;
    private String email;
    private String phoneNumber;
    private String role;
    private String department;
    private Long locationId;
}
