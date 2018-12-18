package org.eso.oauth.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class AuthenticationServer {
    public static void main(String[] args) {
        SpringApplication.run(AuthenticationServer.class, args);
    }
}
