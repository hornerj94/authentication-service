/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */

package de.rtuni.ms.as;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Filter class for json web token authentication of user name and password.
 * 
 * @author Julian
 */
public class JwtUsernameAndPasswordAuthenticationFilter
        extends UsernamePasswordAuthenticationFilter {
    //----------------------------------------------------------------------------------------------

    /** We use auth manager to validate the user credentials */
    private AuthenticationManager authManager;
    
    /** The configuration for the json web token. */
    private final JwtConfig jwtConfig;

    //----------------------------------------------------------------------------------------------

    /**
     * Creates an instance with the given <code>AuthenticationManager</code> and the given
     * <code>JwtConfig</code>.
     * 
     * @param authManager The stated manager
     * @param jwtConfig The stated configuration for json web token
     */
    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authManager,
            JwtConfig jwtConfig) {
        this.authManager = authManager;
        this.jwtConfig = jwtConfig;
        
        // By default, UsernamePasswordAuthenticationFilter listens to "/login" path. 
        // In our case, we use "/auth". So, we need to override the defaults.
        this.setRequiresAuthenticationRequestMatcher(
                new AntPathRequestMatcher(jwtConfig.getUri(), "POST"));
    }

    //----------------------------------------------------------------------------------------------

    /**
     * Read the credentials from the given request and tries to authenticate them.
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest requ, HttpServletResponse resp)
            throws AuthenticationException {
        try {
            // Reads the credentials from the request body 
            // and put them in a newly created UserCredentials object.
            UserCredentials credentials =
                    new ObjectMapper().readValue(requ.getInputStream(), UserCredentials.class);
            
            // Creates an authentication token object with the credentials from the request
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    credentials.getUsername(), credentials.getPassword(), Collections.emptyList());
            
            // The manager tries to authenticate, it uses the loadUserByUsername() method in 
            // UserDetailsServiceImpl to load one of the embedded user.
            return authManager.authenticate(authToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //----------------------------------------------------------------------------------------------

    /**
     * Upon successful authentication, generate a token. The given <code>Authentication<code> object
     * is the current authenticated user.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest requ, HttpServletResponse resp,
            FilterChain chain, Authentication auth) throws IOException, ServletException {
        Long now = System.currentTimeMillis();
        
        // Building of the token
        String token = Jwts.builder().setSubject(auth.getName())
                
                // Convert authorities to list of strings
                // This is important because it affects the way we get them back in the Gateway
                .claim("authorities",
                        auth.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + jwtConfig.getExpiration() * 1000))
                
                // Sign the token with a hash-based message authentication code,sha256 hash function
                // and the given secret
                .signWith(SignatureAlgorithm.HS512, jwtConfig.getSecret().getBytes()).compact();

        // Add token to the header
        resp.addHeader(jwtConfig.getHeader(), jwtConfig.getPrefix() + token);
        resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    //----------------------------------------------------------------------------------------------

    /**
     * A (temporary) class to represent the user credentials.
     * 
     * @author Julian
     *
     */
    @SuppressWarnings("unused")
    private static class UserCredentials {
        private String username;        
        private String password;

        public String getUsername() { return username; }

        public void setUsername(final String value) { username = value; }

        public String getPassword() { return password; }

        public void setPassword(final String value) { password = value; }
         
    }

    //----------------------------------------------------------------------------------------------
}
