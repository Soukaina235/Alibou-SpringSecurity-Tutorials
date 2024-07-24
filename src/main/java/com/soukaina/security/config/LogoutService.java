package com.soukaina.security.config;

import com.soukaina.security.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // we can use the authentication object in case we want to get the user data beforehand

        final String authenticationHeader = request.getHeader("Authorization"); 
        final String jwt;
        if (authenticationHeader == null || !authenticationHeader.startsWith("Bearer ")) {
            // in this case, we don't need to do anything at all
            return;
        }
        jwt = authenticationHeader.substring(7);
        var storedToken = tokenRepository.findByToken(jwt)
                .orElse(null);
        if (storedToken != null) { // invalidate the token
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
        }
    }
}
