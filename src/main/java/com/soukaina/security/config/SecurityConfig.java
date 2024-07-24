package com.soukaina.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFilter; // it is final, so it will be automatically injected by spring security
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler; // Spring will use our LogoutService implementation of the LogoutHandler


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable() // disable the csrf
                .authorizeHttpRequests() // for our white list requests
                .requestMatchers("/api/v1/auth/**")
                .permitAll()
                .anyRequest() // any other request
                .authenticated()
                .and() // now, we need to configure our session management
                .sessionManagement() // the sessions should be stateless => to ensure that each request is authenticated
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class) // we want to execute the JwtAuthenticationFilter before executing the UserNamePasswordAuthenticationFilter
                .logout()
                .logoutUrl("/api/v1/auth/logout") // we don't need to have a controller endpoint for this
                // Here is where we need to do all the logout logic
                .addLogoutHandler(logoutHandler)
                // The logoutSuccessHandler defines what we want to do once the logout is succeeded
                // All we want to do here is to clear our security context (so that the user won't be able to access
                // any secured endpoint with an invalid token
                .logoutSuccessHandler(
                        (request, response, authentication) ->
                                SecurityContextHolder.clearContext()
                )
                ;
        return http.build();
    }
}
