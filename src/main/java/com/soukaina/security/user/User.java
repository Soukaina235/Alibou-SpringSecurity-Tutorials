package com.soukaina.security.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder // with this annotation, we need the AllArgsConstructor annotation
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "_user") // because, in this we are using postgresql, and postgresql already has a table called user
public class User implements UserDetails {
    @Id
    @GeneratedValue // auto
//    if the strategy is auto, it depends
//    if we are using postgresql: it will be sequence
//    if we are using mysql: it will pick table
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password; // Get password is overidden actually, because we are using the lombok annotation
    @Enumerated(EnumType.STRING)
    private Role role;

    // This function should return a list of roles
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
//        return UserDetails.super.isAccountNonExpired();
        return true; // NonExpired = true
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
