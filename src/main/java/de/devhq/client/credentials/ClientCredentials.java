package de.devhq.client.credentials;


import de.devhq.model.TokenCollection;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.security.sasl.AuthenticationException;
import java.io.IOException;
import java.util.Objects;

public class ClientCredentials {

    private RestTemplate restTemplate;

    @Value("${de.devhq.keycloak.url}")
    private String keycloakUrl;

    public ClientCredentials(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public HttpHeaders getHttpHeaders(String clientId, String clientSecret) throws IOException {
        TokenCollection tokenCollection;
        HttpHeaders httpHeaders = new HttpHeaders();
        tokenCollection = getToken(clientId, clientSecret);
        if (Objects.requireNonNull(tokenCollection.getAccessToken()).length() > 1) {
            httpHeaders.set("Authorization", "Bearer " + tokenCollection.getAccessToken());
        } else {
            throw new AuthenticationException();
        }

        return httpHeaders;
    }

    public TokenCollection getToken(String clientId, String clientSecret) throws IOException {
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
        return restTemplate.exchange(keycloakUrl, HttpMethod.POST, entity, TokenCollection.class);
    }

}
