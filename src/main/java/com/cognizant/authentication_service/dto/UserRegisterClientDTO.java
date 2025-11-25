package com.cognizant.authentication_service.dto;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class UserRegisterClientDTO {
    private Long user_id;
    private String user_name;
    private String email;
    private String phone_number;
    private String role;
    private String department;
    private String office_location;
    private LocalDateTime created_at;
    private LocalDateTime modified_at;
}
