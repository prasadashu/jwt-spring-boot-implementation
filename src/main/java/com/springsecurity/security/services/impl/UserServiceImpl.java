package com.springsecurity.security.services.impl;

import com.springsecurity.security.repository.UserRepository;
import com.springsecurity.security.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    /*
        Service to fetch user details from database
     */

    // Declare object used to fetch data from database
    private final UserRepository userRepository;

    @Override
    public UserDetailsService userDetailsService() {
        /*
            Function to fetch user details from database
         */
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return userRepository.findByEmail(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            }
        };
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        /*
            Function uses a Data Access Object responsible for fetching user details from database
            - It also encodes passwords.
         */
        // Declare an "Authentication Provider"
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        // Specify which "UserDetailsService" is to be used to fetch information about our user
        // - This is because we can have several "UserDetailsService"
        // - In this case, we are fetching it through "UserRepository" from our database
        // - There might be an implementation which fetches data from In Memory database
        // - Or, an implementation which fetches data from LDAP server
        authProvider.setUserDetailsService(userDetailsService());

        // Then we need to tell our "Authentication Provider" which "Password Encoder" is to be used
        // - This is because, there can be several password encoders being used
        // - This "Password Encoder" will be used to encode/decode the password saved in database when authenticating users
        authProvider.setPasswordEncoder(passwordEncoder());

        // Return the "Authentication Provider"
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        /*
            Function to return a Password Encoder
            - This Password Encoder will be used by "Authentication Provider" to encode the password
            - This same "Password Encoder" will be required while decoding the password for a user during authentication
         */
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        /*
            Function to return an Authentication Manager
         */
        return authenticationConfiguration.getAuthenticationManager();
    }
}
