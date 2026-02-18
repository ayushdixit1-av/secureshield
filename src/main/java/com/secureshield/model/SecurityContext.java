package com.secureshield.model;

import java.util.Set;

public record SecurityContext(String username, Set<String> roles, Set<String> permissions) {
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }
}
