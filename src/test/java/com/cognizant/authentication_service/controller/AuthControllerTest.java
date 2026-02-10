package com.cognizant.authentication_service.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.cognizant.authentication_service.dto.UserRegisterRequestDTO;
import com.cognizant.authentication_service.dto.UserRegisterResponseDTO;
import com.cognizant.authentication_service.service.UserService;

import java.util.List;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private AuthController authController;

    @Test
    void register_shouldReturnCreatedUser() {
        UserRegisterRequestDTO request = UserRegisterRequestDTO.builder()
            .userId(1234567890L)
                .userName("john")
                .email("john.doe@test.com")
                .phoneNumber("9999999999")
                .role("USER")
                .department("IT")
                .locationId(1L)
                .password("password")
                .build();

        UserRegisterResponseDTO responseDto = UserRegisterResponseDTO.builder()
                .userId(1L)
                .userName("john")
                .email("john.doe@test.com")
                .phoneNumber("9999999999")
                .role("USER")
                .department("IT")
                .locationId(1L)
                .build();

        when(userService.registerUser(any(UserRegisterRequestDTO.class))).thenReturn(responseDto);

        ResponseEntity<?> response = authController.register(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        UserRegisterResponseDTO body = (UserRegisterResponseDTO) response.getBody();
        assertEquals(1L, body.getUserId());
        assertEquals("john.doe@test.com", body.getEmail());
    }

    @Test
    void me_whenNotAuthenticated_shouldReturn401() {
        ResponseEntity<?> response = authController.me(null, null, null);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    void me_whenAuthenticated_shouldReturnUserInfo() {
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                "john.doe@test.com",
                "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        Authentication authentication = org.mockito.Mockito.mock(Authentication.class);
        Principal principal = () -> "john.doe@test.com";

        ResponseEntity<?> response = authController.me(userDetails, authentication, principal);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        Map<?, ?> body = (Map<?, ?>) response.getBody();
        assertEquals("john.doe@test.com", body.get("username"));
        assertEquals("john.doe@test.com", body.get("principal"));
    }
}
