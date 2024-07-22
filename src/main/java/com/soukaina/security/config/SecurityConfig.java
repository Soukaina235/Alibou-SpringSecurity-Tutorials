package com.soukaina.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFilter; // it is final, so it will be automatically injected by spring security
    private final AuthenticationProvider authenticationProvider;


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
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // we want to execute the JwtAuthenticationFilter before executing the UserNamePasswordAuthenticationFilter
        return http.build();
    }
}
