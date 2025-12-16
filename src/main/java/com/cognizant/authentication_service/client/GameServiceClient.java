package com.cognizant.authentication_service.client;

import java.util.List;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "game-catalog")
public interface GameServiceClient {
    @GetMapping("/locations/")
    List<GameServiceLocationResponse> getAllLocations();
}
