package com.cognizant.authentication_service.client;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class GameServiceLocationResponse {
    private Long locationId;
    private String country;
    private String city;
    private String office;
}
