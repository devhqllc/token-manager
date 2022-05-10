package devhq.io;

import devhq.io.client.credentials.ClientCredentials;
import devhq.io.client.credentials.JwtValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class TokenManagerAutoConfiguration {


    @Bean
    @ConditionalOnMissingBean(RestTemplate.class)
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public ClientCredentials clientCredentials() {
        return new ClientCredentials(restTemplate());
    }

    @Bean
    public JwtValidator jwtValidator() {
        return new JwtValidator();
    }
}
