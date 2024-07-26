package com.soukaina.security;

import com.soukaina.security.auth.AuthenticationService;
import com.soukaina.security.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.soukaina.security.user.Role.ADMIN;
import static com.soukaina.security.user.Role.MANAGER;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService service
	) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("admin@mail.com")
					.password("admin")
					.role(ADMIN)
					.build();

			System.out.println("Admin token: " + service.register(admin).getAccessToken());

			var manager = RegisterRequest.builder()
					.firstname("Manager")
					.lastname("Manager")
					.email("manager@mail.com")
					.password("manager")
					.role(MANAGER)
					.build();

			System.out.println("Manager token: " + service.register(manager).getAccessToken());
		};
	}
}
