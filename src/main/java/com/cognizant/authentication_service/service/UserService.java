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

    public User registerUser(UserRegisterRequestDTO request) {
        UserRegisterClientResponseDTO userServiceResponse = userServiceFeign.createUser(
                UserRegisterClientRequestDTO.builder()
                        .userName(request.getUserName())
                        .email(request.getEmail())
                        .phoneNumber(request.getPhoneNumber())
                        .role(request.getRole())
                        .department(request.getDepartment())
                        .officeLocation(request.getDepartment())
                        .build());
        User user = User.builder()
                .id(userServiceResponse.getUserId())
                .email(userServiceResponse.getEmail())
                .password(
                        passwordEncoder.encode(request.getPassword()))
                .role(userServiceResponse.getRole()).build();
        return userRepository.save(user);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> findByUserId(String userId) {
        return userRepository.findByUserId(userId);
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
