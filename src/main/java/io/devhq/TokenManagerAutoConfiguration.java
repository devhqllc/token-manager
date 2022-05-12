package io.devhq;

import io.devhq.client.credentials.ClientCredentials;
import io.devhq.client.credentials.JwtValidator;
import io.devhq.client.credentials.TokenManagerConfig;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class TokenManagerAutoConfiguration {

    @Bean
    public TokenManagerConfig tokenManagerConfig() {
        return new TokenManagerConfig();
    }

    @Bean
    @ConditionalOnMissingBean(RestTemplate.class)
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public ClientCredentials clientCredentials(RestTemplate restTemplate, TokenManagerConfig tokenManagerConfig) {
        return new ClientCredentials(restTemplate, tokenManagerConfig);
    }

    @Bean
    public JwtValidator jwtValidator(TokenManagerConfig tokenManagerConfig) {
        return new JwtValidator(tokenManagerConfig);
    }
}
