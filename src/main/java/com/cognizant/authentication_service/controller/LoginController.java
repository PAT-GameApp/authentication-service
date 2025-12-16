package com.cognizant.authentication_service.controller;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.cognizant.authentication_service.client.GameServiceClient;
import com.cognizant.authentication_service.client.GameServiceLocationResponse;

import lombok.RequiredArgsConstructor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final GameServiceClient gameServiceClient;
    private final ObjectMapper objectMapper;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register(Model model) {
        List<GameServiceLocationResponse> locations = gameServiceClient.getAllLocations();
        try {
            String locationsJson = objectMapper.writeValueAsString(locations);
            model.addAttribute("locations", locationsJson);
        } catch (JsonProcessingException e) {
            model.addAttribute("locations", "[]");
        }
        return "register";
    }
}
