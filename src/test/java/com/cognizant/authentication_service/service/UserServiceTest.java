package com.cognizant.authentication_service.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.cognizant.authentication_service.client.UserRegisterClientRequestDTO;
import com.cognizant.authentication_service.client.UserRegisterClientResponseDTO;
import com.cognizant.authentication_service.client.UserServiceClient;
import com.cognizant.authentication_service.dto.UserRegisterRequestDTO;
import com.cognizant.authentication_service.dto.UserRegisterResponseDTO;
import com.cognizant.authentication_service.entity.User;
import com.cognizant.authentication_service.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserServiceClient userServiceClient;

    @InjectMocks
    private UserService userService;

    @Test
    void registerUser_shouldCreateUserAndReturnResponse() {
        UserRegisterRequestDTO request = UserRegisterRequestDTO.builder()
                .userName("john")
                .email("john.doe@test.com")
                .phoneNumber("9999999999")
                .role("USER")
                .department("IT")
                .locationId(1L)
                .password("password")
                .build();

        UserRegisterClientResponseDTO feignResponse = UserRegisterClientResponseDTO.builder()
                .userId(1L)
                .userName("john")
                .email("john.doe@test.com")
                .phoneNumber("9999999999")
                .role("USER")
                .department("IT")
                .locationId(1L)
                .build();

        when(userServiceClient.createUser(any(UserRegisterClientRequestDTO.class))).thenReturn(feignResponse);
        when(passwordEncoder.encode("password")).thenReturn("encoded");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserRegisterResponseDTO response = userService.registerUser(request);

        assertNotNull(response);
        assertEquals(1L, response.getUserId());
        assertEquals("john.doe@test.com", response.getEmail());
    }

    @Test
    void loadUserByUsername_whenUserExists_shouldReturnUserDetails() {
        User user = User.builder()
                .userId(1L)
                .email("john.doe@test.com")
                .password("encoded")
                .role("USER")
                .build();

        when(userRepository.findByEmail("john.doe@test.com")).thenReturn(Optional.of(user));

        UserDetails userDetails = userService.loadUserByUsername("john.doe@test.com");

        assertEquals("john.doe@test.com", userDetails.getUsername());
        assertEquals("encoded", userDetails.getPassword());
        assertEquals(1, userDetails.getAuthorities().size());
    }

    @Test
    void loadUserByUsername_whenUserNotFound_shouldThrowException() {
        when(userRepository.findByEmail("missing@test.com")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class,
                () -> userService.loadUserByUsername("missing@test.com"));
    }
}
