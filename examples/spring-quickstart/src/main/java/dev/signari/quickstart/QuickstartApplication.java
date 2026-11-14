package dev.signari.quickstart;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** A Spring Boot application that signs people in with Signari. See docs/quickstart-spring.md. */
@SpringBootApplication
public class QuickstartApplication {
    public static void main(String[] args) {
        SpringApplication.run(QuickstartApplication.class, args);
    }
}
