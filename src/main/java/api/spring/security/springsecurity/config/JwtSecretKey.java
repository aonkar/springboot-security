package api.spring.security.springsecurity.config;

import api.spring.security.springsecurity.config.JwtConfig;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.util.Base64;

@Configuration
public class JwtSecretKey {

    @Autowired
    private final JwtConfig jwtConfig;

    public JwtSecretKey(final JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    @Bean
    public SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(jwtConfig.getSecretKey()));
    }
}
