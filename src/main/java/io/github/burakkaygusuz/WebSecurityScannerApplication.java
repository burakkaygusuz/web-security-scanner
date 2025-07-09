package io.github.burakkaygusuz;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Main Spring Boot application class for Web Security Scanner. This class serves as the entry point
 * for the Spring Boot application.
 */
@ConfigurationPropertiesScan
@SpringBootApplication
public class WebSecurityScannerApplication {

  public static void main(String[] args) {
    SpringApplication.run(WebSecurityScannerApplication.class, args);
  }
}
