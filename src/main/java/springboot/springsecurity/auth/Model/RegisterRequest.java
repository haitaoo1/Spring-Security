package springboot.springsecurity.auth.Model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import springboot.springsecurity.user.Role;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    private String firstname;
    private String lastname;
    private String email;
    private String password;
    private Role role;

}
