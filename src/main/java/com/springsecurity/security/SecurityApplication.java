package com.springsecurity.security;

import com.springsecurity.security.entities.Role;
import com.springsecurity.security.entities.User;
import com.springsecurity.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SecurityApplication implements CommandLineRunner {
	@Autowired
	private UserRepository userRepository;

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		// Fetch Admin user from database
		User adminUser = userRepository.findByRole(Role.ADMIN);

		// Check if admin user was not available in the database
		if(adminUser == null) {
			// Create a new user
			User user = new User();

			// Set ADMIN related details for the user
			user.setFirstname("admin");
			user.setSecondname("admin");
			user.setEmail("admin@somemail.com");
			user.setRole(Role.ADMIN);
			user.setPassword(new BCryptPasswordEncoder().encode("admin"));

			// Persist admin data to database
			userRepository.save(user);
		}

	}
}
