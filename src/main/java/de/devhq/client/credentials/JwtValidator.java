package de.devhq.client.credentials;

import de.devhq.TokenManagerProperties;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;

public class JwtValidator {


    private static final Logger logger = LoggerFactory.getLogger(JwtValidator.class);

    private JwtValidator() {
    }

    public static Integer tryExtractUserIdFromJwt() {
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) TokenManagerProperties.getSecurityContext().getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        Object value = details.getKeycloakSecurityContext().getToken().getOtherClaims().get(TokenManagerProperties.getUserId());
        if (value != null)
            return Integer.valueOf((String)value);
        return null;
    }

    public static int extractUserIdFromJwt() {
        Integer userId = tryExtractUserIdFromJwt();
        if (userId == null) {
            logger.error("Requesting client is not an end user, hence token does not contain gitlab user id!");
            throw new ValidationException();
        }

        if (userId <= 0) {
            logger.error("User id may not be none positive number! API seems to be hacked! Please report this to admin");
            throw new ValidationException();
        }

        return userId;
    }

    public static String getCustomerId() {
        return (String) JwtValidator.extractValueFromJwt(TokenManagerProperties.getCustomerId());
    }

    public static Object extractValueFromJwt(String key) {
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) TokenManagerProperties.getSecurityContext().getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        return details.getKeycloakSecurityContext().getToken().getOtherClaims().get(key);
    }

    public static String getName() {
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) TokenManagerProperties.getSecurityContext().getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        return details.getKeycloakSecurityContext().getToken().getName();
    }

    public static boolean isInternalUser(HttpServletRequest request) {
        return request.isUserInRole(TokenManagerProperties.getMachineRole()) || request.isUserInRole(TokenManagerProperties.getAdminRole());
    }

    public static boolean isExternalUser(HttpServletRequest request) {
        return !(request.isUserInRole(TokenManagerProperties.getMachineRole()) || request.isUserInRole(TokenManagerProperties.getAdminRole()))
                && request.isUserInRole(TokenManagerProperties.getUserRole());
    }

    public static boolean isCustomer(HttpServletRequest request) {
        return request.isUserInRole(TokenManagerProperties.getCustomerRole());
    }

    public static boolean isSuperCustomer(HttpServletRequest request) {
        return request.isUserInRole(TokenManagerProperties.getSuperCustomerRole());
    }
}
