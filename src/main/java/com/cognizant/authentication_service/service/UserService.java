package com.cognizant.authentication_service.service;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.cognizant.authentication_service.client.UserRegisterClientRequestDTO;
import com.cognizant.authentication_service.client.UserRegisterClientResponseDTO;
import com.cognizant.authentication_service.client.UserServiceClient;
import com.cognizant.authentication_service.dto.UserRegisterRequestDTO;
import com.cognizant.authentication_service.dto.UserRegisterResponseDTO;
import com.cognizant.authentication_service.entity.User;
import com.cognizant.authentication_service.repository.UserRepository;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserServiceClient userServiceFeign;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder,
            UserServiceClient userServiceFeign) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.userServiceFeign = userServiceFeign;
    }

    public UserRegisterResponseDTO registerUser(UserRegisterRequestDTO request) {
        // feign call to create user entity in user service
        UserRegisterClientResponseDTO userServiceResponse = userServiceFeign.createUser(
                UserRegisterClientRequestDTO.builder()
                        .userId(request.getUserId())
                        .userName(request.getUserName())
                        .email(request.getEmail())
                        .phoneNumber(request.getPhoneNumber())
                        .role(request.getRole())
                        .department(request.getDepartment())
                        .locationId(request.getLocationId())
                        .build());
        User user = User.builder()
                .userId(userServiceResponse.getUserId())
                .email(userServiceResponse.getEmail())
                .password(
                        passwordEncoder.encode(request.getPassword()))
                .role(userServiceResponse.getRole()).build();
        userRepository.save(user);
        UserRegisterResponseDTO response = UserRegisterResponseDTO.builder()
                .userId(userServiceResponse.getUserId())
                .userName(userServiceResponse.getUserName())
                .email(userServiceResponse.getEmail())
                .phoneNumber(userServiceResponse.getPhoneNumber())
                .role(userServiceResponse.getRole())
                .department(userServiceResponse.getDepartment())
                .locationId(userServiceResponse.getLocationId())
                .build();
        return response;
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Collection<? extends GrantedAuthority> authorities = List
                .of(new SimpleGrantedAuthority("ROLE_" + user.getRole()));

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                authorities);
    }
}
