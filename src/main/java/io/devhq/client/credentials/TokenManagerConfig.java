package io.devhq.client.credentials;

import org.springframework.beans.factory.annotation.Value;

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

    public String getUserIdAttributeName() {
        return userIdAttributeName;
    }

    public void setUserIdAttributeName(String userIdAttributeName) {
        this.userIdAttributeName = userIdAttributeName;
    }

    public String getMachineRole() {
        return machineRole;
    }

    public void setMachineRole(String machineRole) {
        this.machineRole = machineRole;
    }

    public String getAdminRole() {
        return adminRole;
    }

    public void setAdminRole(String adminRole) {
        this.adminRole = adminRole;
    }

    public String getUserRole() {
        return userRole;
    }

    public void setUserRole(String userRole) {
        this.userRole = userRole;
    }

    public String getCustomerIdAttributeName() {
        return customerIdAttributeName;
    }

    public void setCustomerIdAttributeName(String customerIdAttributeName) {
        this.customerIdAttributeName = customerIdAttributeName;
    }

    public String getCustomerRole() {
        return customerRole;
    }

    public void setCustomerRole(String customerRole) {
        this.customerRole = customerRole;
    }

    public String getSuperCustomerRole() {
        return superCustomerRole;
    }

    public void setSuperCustomerRole(String superCustomerRole) {
        this.superCustomerRole = superCustomerRole;
    }

    public String getKeycloakUrl() {
        return keycloakUrl;
    }

    public void setKeycloakUrl(String keycloakUrl) {
        this.keycloakUrl = keycloakUrl;
    }

    public static final String DEVELOPER_CUSTOMER_ID = "user";
    public static final String DEVHQ_ADMIN_CUSTOMER_ID = "devhq";

}
