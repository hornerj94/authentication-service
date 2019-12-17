/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */

package de.rtuni.ms.as;

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

/**
 * Class that handles security configuration.
 * 
 * @author Julian
 *
 */
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    //----------------------------------------------------------------------------------------------
    
    /** A service that loads users from the database. */
    @Autowired
    private UserDetailsService userDetailsService;

    /** The configuration for the json web token. */
    @Autowired
    private JwtConfig jwtConfig;

    //----------------------------------------------------------------------------------------------

    /**
     * Overrides the default configuration.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
        // make sure we use stateless session; session won't be used to store user's state.
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        // handle an authorized attempts 
        .exceptionHandling().authenticationEntryPoint(
                (req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
        .and()
        
        /*
         * Add a filter to validate user credentials and add token in the response header.
         * 
         * What's the authenticationManager()? An object provided by WebSecurityConfigurerAdapter, 
         * used to authenticate the user passing user's credentials. The filter needs this 
         * authentication manager to authenticate the user.
         */
        .addFilter(
                new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig))
        .authorizeRequests()
        // allow all POST requests 
        .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
        // any other requests must be authenticated
        .anyRequest().authenticated();
    }
    
    /**
     * Spring has <code>UserDetailsService</code> interface, which can be overridden to provide our
     * implementation for fetching user from database (or any other source).
     * <p>
     * The UserDetailsService object is used by the authentication manager to load the user
     * from database. In addition, we need to define the password encoder also. So, authentication
     * manager can compare and verify passwords.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    //----------------------------------------------------------------------------------------------

    /**
     * Get a new <code>JwtConfig</code>.
     * 
     * @return The stated configuration
     */
    @Bean
    public JwtConfig jwtConfig() { return new JwtConfig(); }

    //----------------------------------------------------------------------------------------------

    /**
     * Get a new <code>BCryptPasswordEncoder</code>.
     * 
     * @return The stated encoder
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
    
    //----------------------------------------------------------------------------------------------
}
