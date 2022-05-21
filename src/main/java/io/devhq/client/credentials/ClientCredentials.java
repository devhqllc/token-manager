package io.devhq.client.credentials;


import io.devhq.model.TokenCollection;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.security.sasl.AuthenticationException;
import java.io.IOException;
import java.util.Objects;

public class ClientCredentials {

    private final RestTemplate restTemplate;
    private final TokenManagerConfig tokenManagerConfig;

    public ClientCredentials(RestTemplate restTemplate, TokenManagerConfig tokenManagerConfig) {
        this.restTemplate = restTemplate;
        this.tokenManagerConfig = tokenManagerConfig;
    }


    public HttpHeaders createBearerAuthorizationHeader(String clientId, String clientSecret) throws IOException {
        TokenCollection tokenCollection;
        HttpHeaders httpHeaders = new HttpHeaders();
        tokenCollection = authorizeClient(clientId, clientSecret);
        if (Objects.requireNonNull(tokenCollection.getAccessToken()).length() > 1) {
            httpHeaders.set("Authorization", "Bearer " + tokenCollection.getAccessToken());
        } else {
            throw new AuthenticationException();
        }

        return httpHeaders;
    }

    public TokenCollection authorizeClient(String clientId, String clientSecret) throws IOException {
        ResponseEntity<TokenCollection> tokenCollectionCurrent = getTokenCollection(clientId, clientSecret);
        if (tokenCollectionCurrent.getBody() == null || tokenCollectionCurrent.getBody().getAccessToken() == null) {
            throw new AuthenticationException();
        }
        return tokenCollectionCurrent.getBody();
    }

    private ResponseEntity<TokenCollection> getTokenCollection(String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "client_credentials");
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
        return restTemplate.exchange(tokenManagerConfig.getKeycloakUrl(), HttpMethod.POST, entity, TokenCollection.class);
    }

    public TokenManagerConfig getTokenManagerConfig() {
        return tokenManagerConfig;
    }
}
