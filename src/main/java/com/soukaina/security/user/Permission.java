package com.soukaina.security.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permission {
    // instead of admin:read, we can name whatever we want
    ADMIN_READ("admin:read"), // it will contain a permission to read a resource for an admin role
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),
    MANAGER_READ("management:read"),
    MANAGER_UPDATE("management:update"),
    MANAGER_CREATE("management:create"),
    MANAGER_DELETE("management:delete")
    ;

    @Getter
    private final String permission; // this is going to be the permission name
}
