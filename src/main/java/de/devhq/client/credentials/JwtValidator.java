package de.devhq.client.credentials;

import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;

public class JwtValidator {

    private static final Logger logger = LoggerFactory.getLogger(JwtValidator.class);

    @Value("${de.devhq.gitlab.user.id}")
    private String gitlabUserId;
    @Value("${de.devhq.role.machine}")
    private String roleMachine;
    @Value("${de.devhq.role.admin}")
    private String roleAdmin;
    @Value("${de.devhq.role.user}")
    private String roleUser;
    @Value("${de.devhq.customer.id}")
    private String customerId;
    @Value("${de.devhq.role.customer}")
    private String roleCustomer;
    @Value("${de.devhq.role.supercustomer}")
    private String roleSuperCustomer;

    public JwtValidator() {

    }

    public Integer tryExtractUserIdFromJwt() {
        SecurityContext context = SecurityContextHolder.getContext();
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) context.getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        Object value = details.getKeycloakSecurityContext().getToken().getOtherClaims().get(gitlabUserId);
        if (value != null)
            return Integer.valueOf((String) value);
        return null;
    }

    public int extractUserIdFromJwt() {
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

    public String getCustomerId() {
        return (String) extractValueFromJwt(customerId);
    }

    public Object extractValueFromJwt(String key) {
        SecurityContext context = SecurityContextHolder.getContext();
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) context.getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        return details.getKeycloakSecurityContext().getToken().getOtherClaims().get(key);
    }

    public String getName() {
        SecurityContext context = SecurityContextHolder.getContext();
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) context.getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        return details.getKeycloakSecurityContext().getToken().getName();
    }

    public boolean isInternalUser(HttpServletRequest request) {
        return request.isUserInRole(roleMachine) || request.isUserInRole(roleAdmin);
    }

    public boolean isExternalUser(HttpServletRequest request) {
        return !(request.isUserInRole(roleMachine) || request.isUserInRole(roleAdmin))
                && request.isUserInRole(roleUser);
    }

    public boolean isCustomer(HttpServletRequest request) {
        return request.isUserInRole(roleCustomer);
    }

    public boolean isSuperCustomer(HttpServletRequest request) {
        return request.isUserInRole(roleSuperCustomer);
    }
}
