package com.cognizant.authentication_service.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.cognizant.authentication_service.dto.UserRegisterDTO;

@FeignClient(name = "user-service", path = "/users")
public interface UserServiceClient {
    @PostMapping("/create_user")
    String createUser(@RequestBody UserRegisterDTO user);
}
