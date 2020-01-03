/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */

package de.rtuni.ms.as.filter;

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

import de.rtuni.ms.as.config.JWTConfiguration;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Filter class for authentication of user credentials, generating a JWT and adding the token to 
 * the response.
 * 
 * @author Julian
 */
public class JWTUsernameAndPasswordAuthenticationFilter
extends UsernamePasswordAuthenticationFilter {
    //---------------------------------------------------------------------------------------------

    /** The <code>JwtConfiguration</code>. */
    private JWTConfiguration jwtConfiguration;

    /** The <code>AuthenticationManager</code> for validating user credentials. */
    private AuthenticationManager authManager;
    
    //---------------------------------------------------------------------------------------------

    /**
     * Creates an instance with the given <code>AuthenticationManager</code> and the given
     * <code>JWTConfiguration</code>.
     * 
     * @param authManager The stated manager
     * @param config The stated configuration
     */
    public JWTUsernameAndPasswordAuthenticationFilter(AuthenticationManager authManager,
            JWTConfiguration config) {
        this.authManager = authManager;
        this.jwtConfiguration = config;
        
        // Overrides default path of UsernamePasswordAuthenticationFilter with auth path.
        this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(
                config.getUri(), "POST"));
    }
    
    //---------------------------------------------------------------------------------------------

    /**
     * Read the credentials from the given request, tries to authenticate them and returns the
     * authenticated user token, or null if authentication is incomplete.
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException {
        try {
            // Reads the credentials from the request and put them in an UserCredentials object.
            UserCredentials credentials = new ObjectMapper().readValue(
                    req.getInputStream(), UserCredentials.class);
            // Creates a spring object for representing the credentials and inserts the previously
            // created informations into it.
            UsernamePasswordAuthenticationToken userPassAuth = 
                    new UsernamePasswordAuthenticationToken(
                            credentials.getUsername(), 
                            credentials.getPassword(), 
                            Collections.emptyList()
                    );
            
            // The manager tries to authenticate the credentials.
            return authManager.authenticate(userPassAuth);
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    //---------------------------------------------------------------------------------------------

    /**
     * Will be executed only upon successful authentication. Generate a token for the
     * <code>Authentication</code> object that is returned from the
     * <code>attemptAuthentication()</code> method.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res,
            FilterChain chain, Authentication auth) throws IOException, ServletException {
        Long now = System.currentTimeMillis();

        // Builds the token
        String token = Jwts.builder().setSubject(auth.getName())
                // Converts the authorities to Strings and append them to the builder.
                .claim("authorities", auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + jwtConfiguration.getExpiration() * 1000))

                // Signs the token with a hash-based message authentication code, a sha256 hash 
                // function and the given secret.
                .signWith(SignatureAlgorithm.HS512, jwtConfiguration.getSecret().getBytes())
                // Builds the JWT.
                .compact();

        res.setStatus(HttpServletResponse.SC_NO_CONTENT);
        // Add token to the Authorization header.
        res.addHeader(jwtConfiguration.getHeader(), jwtConfiguration.getPrefix() + token);
    }

    //---------------------------------------------------------------------------------------------

    /**
     * A (temporary) class for representing user credentials.
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

    //---------------------------------------------------------------------------------------------
}
