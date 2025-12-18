package com.cognizant.authentication_service.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import com.cognizant.authentication_service.client.GameServiceClient;
import com.cognizant.authentication_service.client.GameServiceLocationResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@ExtendWith(MockitoExtension.class)
class LoginControllerTest {

    @Mock
    private GameServiceClient gameServiceClient;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private LoginController loginController;

    @Test
    void login_shouldReturnLoginView() {
        String view = loginController.login();
        assertEquals("login", view);
    }

    @Test
    void register_shouldPopulateLocationsAndReturnRegisterView() throws Exception {
        List<GameServiceLocationResponse> locations = List.of(
                GameServiceLocationResponse.builder().locationId(1L).country("IN").city("Chennai").office("DLF").build());

        when(gameServiceClient.getAllLocations()).thenReturn(locations);
        when(objectMapper.writeValueAsString(locations)).thenReturn("[{}]");

        Model model = new ConcurrentModel();
        String view = loginController.register(model);

        assertEquals("register", view);
        assertTrue(model.containsAttribute("locations"));
        assertEquals("[{}]", model.getAttribute("locations"));
    }

    @Test
    void register_whenJsonProcessingException_shouldSetEmptyArray() throws Exception {
        List<GameServiceLocationResponse> locations = List.of();

        when(gameServiceClient.getAllLocations()).thenReturn(locations);
        when(objectMapper.writeValueAsString(locations)).thenThrow(new JsonProcessingException("error") {
        });

        Model model = new ConcurrentModel();
        String view = loginController.register(model);

        assertEquals("register", view);
        assertTrue(model.containsAttribute("locations"));
        assertEquals("[]", model.getAttribute("locations"));
    }
}
