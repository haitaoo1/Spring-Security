package springboot.springsecurity.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public enum Role {
    ADMIN(
            Set.of(Permission.ADMIN_READ,
                    Permission.ADMIN_DELETE,
                    Permission.ADMIN_UPDATE,
                    Permission.ADMIN_CREATE,
                    Permission.MANAGER_READ,
                    Permission.MANAGER_DELETE,
                    Permission.MANAGER_UPDATE,
                    Permission.MANAGER_CREATE
                    )
    ),
    USER(Collections.emptySet()),
    MANAGER(
            Set.of(Permission.MANAGER_UPDATE,
                    Permission.MANAGER_DELETE,
                    Permission.MANAGER_READ,
                    Permission.MANAGER_CREATE)
    )
    ;

    @Getter
    private final Set<Permission> permission;

    public List<SimpleGrantedAuthority> getAuthoritites(){
        var authorities = getPermission()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
