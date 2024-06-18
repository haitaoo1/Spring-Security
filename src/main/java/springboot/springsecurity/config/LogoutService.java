package springboot.springsecurity.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import springboot.springsecurity.token.TokenRepository;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {

        //invalide the token
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        //No authorization or no Bearer(no auth token)
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        // Counting -->  Bearer so the next is 7
        jwt = authHeader.substring(7);

        var storedToken = tokenRepository.findByToken(jwt).orElseThrow();
        if(storedToken != null){
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
        }

    }
}
