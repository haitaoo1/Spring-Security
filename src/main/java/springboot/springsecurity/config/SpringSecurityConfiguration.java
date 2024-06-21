package springboot.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.springframework.http.HttpMethod.*;
import static springboot.springsecurity.user.Permission.*;
import static springboot.springsecurity.user.Role.ADMIN;
import static springboot.springsecurity.user.Role.MANAGER;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity //
public class SpringSecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http.authorizeHttpRequests((auth) ->
                auth.requestMatchers("api/v1/auth/**").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/api/v1/managment/**").hasAnyRole(ADMIN.name(), MANAGER.name())

                        .requestMatchers(GET, "/api/v1/managment/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                        .requestMatchers(POST, "/api/v1/managment/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                        .requestMatchers(PUT, "/api/v1/managment/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                        .requestMatchers(DELETE, "/api/v1/managment/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

                        /*.requestMatchers("/api/v1/admin/**").hasAnyRole(ADMIN.name())

                        .requestMatchers(GET, "/api/v1/admin/**").hasAuthority(ADMIN_READ.name())
                        .requestMatchers(POST, "/api/v1/admin/**").hasAuthority(ADMIN_CREATE.name())
                        .requestMatchers(PUT, "/api/v1/admin/**").hasAuthority(ADMIN_UPDATE.name())
                        .requestMatchers(DELETE, "/api/v1/admin/**").hasAuthority(ADMIN_DELETE.name())*/


                        .anyRequest().authenticated())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(authenticationProvider)
                .csrf(config ->config.disable())
                .sessionManagement(magament-> magament.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout((logout) ->
                        logout.logoutUrl("/api/v1/auth/logout")
                                .addLogoutHandler(logoutHandler)
                                .logoutSuccessHandler(
                                        (request, response, authentication) ->
                                            SecurityContextHolder.clearContext()))

                .build();
    }

}


