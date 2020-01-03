/*
 * Copyright 2019 (C) by Julian Horner.
 * All Rights Reserved.
 */

package de.rtuni.ms.as;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

/**
 * Class for starting authentication service.
 * 
 * @author Julian
 *
 */
@SpringBootApplication
@EnableEurekaClient     
public class Application {
    //---------------------------------------------------------------------------------------------
    
    /**
     * Start the application.
     * 
     * @param args The arguments
     */
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    //---------------------------------------------------------------------------------------------
}
