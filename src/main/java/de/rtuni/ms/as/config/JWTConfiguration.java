/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */

package de.rtuni.ms.as.config;

import org.springframework.beans.factory.annotation.Value;

/**
 * Configuration class for JWT.
 * 
 * @author Julian
 *
 */
public class JWTConfiguration {
    //---------------------------------------------------------------------------------------------

    /** Get the URI where the credentials needs to be send. */
    @Value("${security.jwt.uri:/auth/**}")
    private String Uri;

    /** Get the header authorization type. */
    @Value("${security.jwt.header:Authorization}")
    private String header;

    /** Get the prefix of the token message. */
    @Value("${security.jwt.prefix:Bearer}")
    private String prefix;

    /** Get the expiration of the token in seconds. */
    @Value("${security.jwt.expiration:#{24*60*60}}")
    private int expiration;

    /** Get the key for encryption and decryption. */
    @Value("${security.jwt.secret:JwtSecretKey}")
    private String secret;

    //---------------------------------------------------------------------------------------------

    /**
     * Get the URI where the credentials needs to be send.
     * 
     * @return The stated URI
     */
    public String getUri() { return Uri; }

    /**
     * Get the header authorization type.
     * 
     * @return The stated header
     */
    public String getHeader() { return header; }

    /**
     * Get the prefix of the token message.
     * 
     * @return The stated prefix
     */
    public String getPrefix() { return prefix; }

    /**
     * Get the expiration of the token in seconds.
     * 
     * @return The stated expiration
     */
    public int getExpiration() { return expiration; }

    /**
     * Get the the key for encryption and decryption.
     * 
     * @return The stated secret
     */
    public String getSecret() { return secret; }

    //---------------------------------------------------------------------------------------------
}
