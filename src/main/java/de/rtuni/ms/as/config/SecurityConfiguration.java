/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */

package de.rtuni.ms.as.config;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import de.rtuni.ms.as.filter.JWTUsernameAndPasswordAuthenticationFilter;

/**
 * Class that handles several security configurations.
 * 
 * @author Julian
 *
 */
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    //---------------------------------------------------------------------------------------------

    /** The <code>JwtConfiguration</code>. */
    @Autowired
    private JWTConfiguration jwtConfiguration;

    /** The service that loads users from the database. */
    @Autowired
    private UserDetailsService userDetailsService;

    //---------------------------------------------------------------------------------------------

    /**
     * Get a new <code>JwtConfiguration</code>.
     * 
     * @return The stated JWT configuration
     */
    @Bean
    public JWTConfiguration jwtConfiguration() { return new JWTConfiguration(); }

    //---------------------------------------------------------------------------------------------

    /**
     * Get a new <code>BCryptPasswordEncoder</code>.
     * 
     * @return The stated encoder
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
    
    //---------------------------------------------------------------------------------------------

    /**
     * Configure custom security configurations.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
        // Use stateless sessions.
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        
        // Response if the user is unauthenticated.
        .exceptionHandling().authenticationEntryPoint(
                (req, rsp, e) -> { 
                    rsp.setContentType("application/json"); 
                    rsp.setCharacterEncoding("UTF-8");
                    rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED); 
                }
        ).and()
        
        // Add a filter to validate user credentials with every request.
        .addFilter(new JWTUsernameAndPasswordAuthenticationFilter(
                authenticationManager(), jwtConfiguration))
        // The passed authentication manager is build in the configure() method below.

        .authorizeRequests()
        // Permit all POST requests to auth path.
        .antMatchers(HttpMethod.POST, jwtConfiguration.getUri()).permitAll()
        // Any other request must be authenticated.
        .anyRequest().authenticated();
    }
    
    /**
     * The auth manager will use our implementation of the <code>UserDetailsService</code>
     * interface to load the user. In addition, we define a password encoder so that the
     * authentication manager is able to compare and verify passwords.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder authManagerBuilder) throws Exception {
        authManagerBuilder.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    //---------------------------------------------------------------------------------------------
}
