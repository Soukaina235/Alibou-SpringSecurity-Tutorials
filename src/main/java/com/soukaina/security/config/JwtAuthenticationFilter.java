package com.soukaina.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain // this is a design pattern based interface that contains the list of filter that we need to execute
    ) throws ServletException, IOException {
        // we can intercept our request and extract data from it and then add it to the response
        final String authenticationHeader = request.getHeader("Authorization"); // extracting the authorization header
        final String jwt;
        final String userEmail; // the username of the user in our case is the email
        if (authenticationHeader == null || !authenticationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // passing the request and the response to the next filter
            return;
        }
        jwt = authenticationHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) { // we also check if the user is not authenticated, because if so, we don't need to redo all of the process
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // the authToken is needed by spring and by the context security holder in order to update our security context
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request) // building the details out of our http request
                );

                // This is the final step which is updating the security context holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // !!!!!!!!! at the end, we need always to pass the hand to the next filter to be executed
        filterChain.doFilter(request, response);
    }
}
