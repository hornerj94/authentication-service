package de.rtuni.ms.as;
/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */



import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

/**
 * Authentication service for microservice architecture.
 * 
 * @author Julian
 *
 */
@SpringBootApplication
@EnableEurekaClient     
public class Application {
    //---------------------------------------------------------------------------------------------
    
    /**
     * Starts the application.
     * 
     * @param args The arguments
     */
    public static void main(final String[] args) { SpringApplication.run(Application.class, args); }

    //---------------------------------------------------------------------------------------------
}
