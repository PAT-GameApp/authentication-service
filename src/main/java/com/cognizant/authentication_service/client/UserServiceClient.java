package com.cognizant.authentication_service.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", path = "/users")
public interface UserServiceClient {
    @PostMapping()
    UserRegisterClientResponseDTO createUser(@RequestBody UserRegisterClientRequestDTO user);
}
