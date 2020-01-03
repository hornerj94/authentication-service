/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */

package de.rtuni.ms.as.service;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Class that is able to load users.
 * 
 * @author Julian
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    //---------------------------------------------------------------------------------------------

    /** The password encoder. */
    @Autowired
    private BCryptPasswordEncoder encoder;

    //---------------------------------------------------------------------------------------------

    /**
     * Load a user by the given name.
     * 
     * @param The stated name
     */
    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        // Hard coding users, all passwords are encoded.
        final List<AppUser> appUsers = Arrays.asList(
                new AppUser(1, "default", encoder.encode("12345"), "USER"),
                new AppUser(2, "admin", encoder.encode("12345"), "ADMIN"));
          
        String userRole;
        for (AppUser appUser : appUsers) {
            if (appUser.getUsername().equals(username)) {
                // Spring needs roles to be in a format like "ROLE_" + user role.
                userRole = "ROLE_" + appUser.getRole();
                
                List<GrantedAuthority> grantedAuthorities = 
                        AuthorityUtils.commaSeparatedStringToAuthorityList(userRole);
                
                // Since a specific Spring object has to be returned for the method, 
                // we convert our user into this object.
                return new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
            }
        }

        // If the user is not found an exception is thrown.
        throw new UsernameNotFoundException("Username: " + username + "wasn't found");
    }

    //---------------------------------------------------------------------------------------------

    /**
     * A (temporary) class for representing an user.
     * 
     * @author Julian
     *
     */
    @SuppressWarnings("unused")
    private static class AppUser {
        private Integer id;
        private String username;
        private String password;
        private String role;

        public AppUser(final Integer id, final String username, final String password, 
                final String role) {
            this.id = id;
            this.username = username;
            this.password = password;
            this.role = role;
        }

        public Integer getId() { return id; }
        public void setId(final Integer value) { id = value; }

        public String getUsername() { return username; }
        public void setUsername(final String value) { username = value; }

        public String getPassword() { return password; }
        public void setPassword(final String value) { password = value; }

        public String getRole() { return role; }
        public void setRole(final String value) { role = value; }
    }

    //---------------------------------------------------------------------------------------------
}
