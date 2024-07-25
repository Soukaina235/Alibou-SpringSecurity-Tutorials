package com.soukaina.security.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    @JsonProperty("access_token") // Just to change the name of the json field
    private String accessToken; // this is the string that will be sent back to the user
    @JsonProperty("refresh_token")
    private String refreshToken;
}
