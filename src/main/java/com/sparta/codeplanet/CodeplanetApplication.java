package com.sparta.codeplanet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(scanBasePackages = "com.sparta.codeplanet")
public class CodeplanetApplication {

    public static void main(String[] args) {
        SpringApplication.run(CodeplanetApplication.class, args);
    }

}
