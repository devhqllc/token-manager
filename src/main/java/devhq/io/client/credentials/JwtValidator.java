package devhq.io.client.credentials;

import org.keycloak.TokenVerifier;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.representations.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;

public class JwtValidator {
    private static final Logger logger = LoggerFactory.getLogger(JwtValidator.class);
    private final TokenManagerConfig tokenManagerConfig;

    public JwtValidator(TokenManagerConfig tokenManagerConfig) {
        this.tokenManagerConfig = tokenManagerConfig;
    }

    private int extractUserIdFromJwt(String jwt) {
        Integer userId = extractIntegerFromJwt(jwt, tokenManagerConfig.getUserIdAttributeName());
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

    private int extractUserIdFromJwt() {
        Integer userId = extractIntegerFromJwt(tokenManagerConfig.getUserIdAttributeName());
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

    public String extractStringFromJwt(String key) {
        Object claim = getClaim(key);
        if (claim == null) {
            return null;
        }

        return String.valueOf(claim);
    }

    public String extractStringFromJwt(String jwt, String key) {
        Object claim = getClaim(jwt, key);
        if (claim == null) {
            return null;
        }

        return String.valueOf(claim);
    }

    public Integer extractIntegerFromJwt(String key) {
        String stringClaim = extractStringFromJwt(key);
        if (stringClaim == null) {
            return null;
        }
        return Integer.valueOf(stringClaim);
    }

    public Integer extractIntegerFromJwt(String jwt, String key) {
        String stringClaim = extractStringFromJwt(jwt, key);
        if (stringClaim == null) {
            return null;
        }
        return Integer.valueOf(stringClaim);
    }

    private Object getClaim(String key) {
        SecurityContext context = SecurityContextHolder.getContext();
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) context.getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        return details.getKeycloakSecurityContext().getToken().getOtherClaims().get(key);
    }

    private Object getClaim(String jwt, String key) {
        try {
            return TokenVerifier.create(jwt, JsonWebToken.class).getToken().getOtherClaims().get(key);
        } catch (Exception e) {
            return null;
        }
    }

    public String extractJwtToken() {
        SecurityContext context = SecurityContextHolder.getContext();
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) context.getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        return details.getKeycloakSecurityContext().getTokenString();
    }

    public String getName() {
        SecurityContext context = SecurityContextHolder.getContext();
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) context.getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        return details.getKeycloakSecurityContext().getToken().getName();
    }

    public boolean isInternalUser(HttpServletRequest request) {

        return request.isUserInRole(tokenManagerConfig.getMachineRole())
                || request.isUserInRole(tokenManagerConfig.getAdminRole());
    }

    public boolean isExternalUser(HttpServletRequest request) {
        return !(request.isUserInRole(tokenManagerConfig.getMachineRole())
                || request.isUserInRole(tokenManagerConfig.getAdminRole()))
                && (request.isUserInRole(tokenManagerConfig.getUserRole()) ||
                request.isUserInRole(tokenManagerConfig.getSuperCustomerRole())
                || request.isUserInRole(tokenManagerConfig.getCustomerRole()));
    }

    public boolean isCustomer(HttpServletRequest request) {
        return request.isUserInRole(tokenManagerConfig.getCustomerRole());
    }

    public boolean isCustomer(String jwt) {
        String strCustomerId = extractStringFromJwt(jwt, tokenManagerConfig.getCustomerIdAttributeName());
        return strCustomerId != null && strCustomerId.equalsIgnoreCase(tokenManagerConfig.getCustomerRole());
    }

    public boolean isSuperCustomer(HttpServletRequest request) {
        return request.isUserInRole(tokenManagerConfig.getSuperCustomerRole());
    }

    public boolean isSuperCustomer(String jwt) {
        String strCustomerId = extractStringFromJwt(jwt, tokenManagerConfig.getCustomerIdAttributeName());
        return strCustomerId != null && strCustomerId.equalsIgnoreCase(tokenManagerConfig.getSuperCustomerRole());
    }

    public boolean isCustomerOrSuperCustomer(String jwt) {
        return isCustomer(jwt) || isSuperCustomer(jwt);
    }

    public boolean isChmOrCore(HttpServletRequest request) {
        return isInternalUser(request);
    }


    public boolean isCustomerOrSuperCustomer(HttpServletRequest request) {
        return isCustomer(request) || isSuperCustomer(request);
    }

    public String getCustomerId(HttpServletRequest request) {
        String stringClaim = extractStringFromJwt(tokenManagerConfig.getCustomerIdAttributeName());

        if (stringClaim == null && isChmOrCore(request)) {
            return TokenManagerConfig.DEVHQ_ADMIN_CUSTOMER_ID;
        } else if (stringClaim == null && isExternalUser(request)) {
            return TokenManagerConfig.DEVELOPER_CUSTOMER_ID;
        } else if (stringClaim == null && isCustomerOrSuperCustomer(request)) {
            logger.error("Requesting client is not an end user, hence token does not contain customer id!");
            throw new ValidationException();
        }

        return stringClaim;
    }

    public int getUserId(HttpServletRequest request) {
        if (isChmOrCore(request)) {
            return 0;
        }

        return extractUserIdFromJwt();
    }

}
