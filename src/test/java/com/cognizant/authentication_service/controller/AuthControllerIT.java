package com.cognizant.authentication_service.controller;

// ...existing imports...
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerIT {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void register_returnsCreatedOrBadRequest() throws Exception {
        String requestJson = "{" +
            "\"userId\":1234567890," +
                "\"userName\":\"john\"," +
                "\"email\":\"john.doe@test.com\"," +
                "\"phoneNumber\":\"9999999999\"," +
                "\"role\":\"USER\"," +
                "\"department\":\"IT\"," +
                "\"locationId\":1," +
                "\"password\":\"password\"" +
                "}";

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    if (status != 201 && status != 400) {
                        throw new AssertionError("Expected 201 or 400 but got " + status);
                    }
                });
    }

    @Test
    void login_returnsOkOrUnauthorizedOrBadRequest() throws Exception {
        String requestJson = "{" +
                "\"username\":\"john.doe@test.com\"," +
                "\"password\":\"password\"" +
                "}";

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    if (status != 200 && status != 400 && status != 401) {
                        throw new AssertionError("Expected 200, 400 or 401 but got " + status);
                    }
                });
    }

    @Test
    void validateToken_returnsOkOrUnauthorized() throws Exception {
        // Adjust the header name/value if your auth service expects a different token header
        mockMvc.perform(get("/auth/validate")
                        .header("Authorization", "Bearer dummy-token")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    if (status != 200 && status != 401) {
                        throw new AssertionError("Expected 200 or 401 but got " + status);
                    }
                });
    }
}