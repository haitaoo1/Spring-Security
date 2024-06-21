package springboot.springsecurity.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permission {
    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),

    MANAGER_READ("managment:read"),
    MANAGER_UPDATE("managment:update"),
    MANAGER_CREATE("managment:create"),
    MANAGER_DELETE("managment:delete")
    ;
    @Getter
    private final String permission;
}
