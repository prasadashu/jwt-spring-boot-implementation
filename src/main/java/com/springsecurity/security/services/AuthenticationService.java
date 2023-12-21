package com.springsecurity.security.services;

import com.springsecurity.security.dto.*;
import com.springsecurity.security.entities.User;

public interface AuthenticationService {
    public SignUpResponse signUpRequest(SignUpRequest signUpRequest);
    public JwtAuthenticationResponse signInRequest(SignInRequest signInRequest);
    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
