package com.example.jwtAuth.Controller.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.jwtAuth.Config.JwtService;
import com.example.jwtAuth.Model.Role;
import com.example.jwtAuth.Model.User;
import com.example.jwtAuth.Repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.var;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  @Autowired
  private final UserRepository userRepository;
  @Autowired
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse register(RegisterRequest request) {
    var user = User.builder()
      .firstname(request.getFirstname())
      .lastname(request.getLastname())
      .email(request.getEmail())
      .password(passwordEncoder.encode(request.getPassword()))
      .role(Role.USER)
      .build();

    userRepository.save(user);
    var jwtToken = jwtService.generateToken(user);

    return AuthenticationResponse.builder()
      .token(jwtToken)
      .build();
  }

  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    authenticationManager.authenticate(
      new UsernamePasswordAuthenticationToken(
          request.getEmail(),
          request.getPassword()
      )
    );

    //find user by email after authentication
    var user = userRepository.findByEmail(request.getEmail()).orElseThrow(
      () ->  new UsernameNotFoundException("user with email not found")
    );

    var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder().token(jwtToken).build();
  }
}
