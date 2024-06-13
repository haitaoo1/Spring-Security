package springboot.springsecurity.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import springboot.springsecurity.auth.Model.AuthenticationRequest;
import springboot.springsecurity.auth.Model.AuthenticationResponse;
import springboot.springsecurity.auth.Model.RegisterRequest;

@RestController
@RequestMapping("/api/v1/auth")

public class AuthenticationController {

    @Autowired
    private  AuthenticationService authenticationService;
    @Autowired
    private  PasswordEncoder passwordEncoder;


    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

}
