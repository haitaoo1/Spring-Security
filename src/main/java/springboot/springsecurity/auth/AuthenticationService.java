package springboot.springsecurity.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import springboot.springsecurity.auth.Model.AuthenticationRequest;
import springboot.springsecurity.auth.Model.AuthenticationResponse;
import springboot.springsecurity.auth.Model.RegisterRequest;
import springboot.springsecurity.config.JwtService;
import springboot.springsecurity.token.Token;
import springboot.springsecurity.token.TokenRepository;
import springboot.springsecurity.token.TokenType;
import springboot.springsecurity.user.Role;
import springboot.springsecurity.user.User;
import springboot.springsecurity.user.UserRepository;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;
    public AuthenticationResponse register(RegisterRequest request){
        User user = User.builder()
                        .firstname(request.getFirstname())
                        .lastname(request.getLastname())
                        .email(request.getEmail())
                        .password(passwordEncoder.encode(request.getPassword()))
                        .role(request.getRole())
                        .build();
        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        saveUserToken(savedUser, jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }
    public AuthenticationResponse authenticate(AuthenticationRequest request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(), request.getPassword()
                )
        );

        User user = repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                                    .accessToken(jwtToken)
                                    .refreshToken(refreshToken)
                                    .build();

    }

    private void revokeAllUserTokens(User user){
        var validUserToken = tokenRepository.finAllValidTokenByUser(user.getId());
        if(validUserToken.isEmpty())
            return;
        validUserToken.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });

        tokenRepository.saveAll(validUserToken);
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .token(jwtToken)
                .user(user)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }

    //copy-paste from jwtAuthenticationFilter
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        //No authorization or no Bearer(no auth token)
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        // Counting -->  Bearer so the next is 7
        refreshToken = authHeader.substring(7);

        userEmail = jwtService.extractUsername(refreshToken);

        if(userEmail != null){
            var user = this.repository.findByEmail(userEmail).orElseThrow();

            if(jwtService.isTokenValid(refreshToken, user)){
                var accesToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accesToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accesToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }


}
