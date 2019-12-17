/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */

package de.rtuni.ms.as;

import org.springframework.beans.factory.annotation.Value;

/**
 * Configuration class for json web token.
 * 
 * @author Julian
 *
 */
public class JwtConfig {
    //----------------------------------------------------------------------------------------------

    @Value("${security.jwt.uri:/auth/**}")
    private String Uri;

    @Value("${security.jwt.header:Authorization}")
    private String header;

    @Value("${security.jwt.prefix:Bearer}")
    private String prefix;

    @Value("${security.jwt.expiration:#{24*60*60}}")
    private int expiration;

    @Value("${security.jwt.secret:JwtSecretKey}")
    private String secret;

    //----------------------------------------------------------------------------------------------

    /**
     * Get the uri.
     * 
     * @return The uri
     */
    public String getUri() { return Uri; }

    /**
     * Get the header.
     * 
     * @return The header
     */
    public String getHeader() { return header; }

    /**
     * Get the prefix.
     * 
     * @return The prefix
     */
    public String getPrefix() { return prefix; }

    /**
     * Get the expiration.
     * 
     * @return The expiration
     */
    public int getExpiration() { return expiration; }

    /**
     * Get the secret.
     * 
     * @return The secret
     */
    public String getSecret() { return secret; }

    //----------------------------------------------------------------------------------------------
}
