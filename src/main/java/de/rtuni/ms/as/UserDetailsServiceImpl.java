/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */

package de.rtuni.ms.as;

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
    //----------------------------------------------------------------------------------------------

    /** The password encoder. */
    @Autowired
    private BCryptPasswordEncoder encoder;

    //----------------------------------------------------------------------------------------------

    /**
     * Loads a user by the given name.
     * 
     * @param The stated name
     */
    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        // hard coding users. All passwords must be encoded.
        final List<AppUser> users = Arrays.asList(
                new AppUser(1, "julian", encoder.encode("12345"), "USER"),
                new AppUser(2, "admin", encoder.encode("12345"), "ADMIN"));
          
        for (AppUser appUser : users) {
            if (appUser.getUsername().equals(username)) {
                /*
                 * Remember that Spring needs roles to be in this format: "ROLE_" + userRole 
                 * (i.e."ROLE_ADMIN")
                 * So, we need to set it to that format, so we can verify and compare roles
                 * (i.e. hasRole("ADMIN")).
                 */
                List<GrantedAuthority> grantedAuthorities = 
                        AuthorityUtils.commaSeparatedStringToAuthorityList(
                                "ROLE_" + appUser.getRole());
                
                /*
                 * The "User" class is provided by Spring and represents a model class for user to
                 * be returned by UserDetailsService and used by authentication manager to verify
                 * and check use authentication.
                 */
                return new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
            }
        }

        // If user not found. Throw this exception.
        throw new UsernameNotFoundException("Username: " + username + " not found");
    }

    //----------------------------------------------------------------------------------------------

    /**
     * A (temporary) class represent the user saved in the database.
     * 
     * @author Julian
     *
     */
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

    //----------------------------------------------------------------------------------------------
}
