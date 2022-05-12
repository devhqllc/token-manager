package io.devhq.client.credentials;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;

@Getter
@Setter
public class TokenManagerConfig {

    @Value("${devhq.jwt.attribute.user.id}")
    private String userIdAttributeName;
    @Value("${devhq.role.machine}")
    private String machineRole;
    @Value("${devhq.role.admin}")
    private String adminRole;
    @Value("${devhq.role.user}")
    private String userRole;
    @Value("${devhq.jwt.attribute.customer.id}")
    private String customerIdAttributeName;
    @Value("${devhq.role.customer}")
    private String customerRole;
    @Value("${devhq.role.supercustomer}")
    private String superCustomerRole;
    @Value("${devhq.keycloak.url}")
    private String keycloakUrl;


    public static final String DEVELOPER_CUSTOMER_ID = "user";
    public static final String DEVHQ_ADMIN_CUSTOMER_ID = "devhq";

}
