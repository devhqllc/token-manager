package de.devhq.client.credentials;

import static org.mockito.Mockito.mock;

//@RunWith(MockitoJUnitRunner.class)
public class JwtValidatorTest {

//    @Mock
//    TokenManagerProperties tokenManagerProperties;
//    SecurityContext securityContext;
//
//    @Before
//    public void setUp() {
//        securityContext = Mockito.mock(SecurityContext.class);
//        ReflectionTestUtils.setField(tokenManagerProperties, "userId", "gitlab_user_id");
//        ReflectionTestUtils.setField(tokenManagerProperties, "machineRole", "MACHINE_ROLE");
//        ReflectionTestUtils.setField(tokenManagerProperties, "adminRole", "ADMIN_ROLE");
//        ReflectionTestUtils.setField(tokenManagerProperties, "userRole", "USER_ROLE");
//        ReflectionTestUtils.setField(tokenManagerProperties, "customerRole", "DEVHQ_CUSTOMER_ROLE");
//        ReflectionTestUtils.setField(tokenManagerProperties, "superCustomerRole", "DEVHQ_SUPERCUSTOMER_ROLE");
//        ReflectionTestUtils.setField(tokenManagerProperties, "securityContext", securityContext);
//
//    }
//
//    @Test(expected = ValidationException.class)
//    public void extractUserIdFromJwtWithNullClaims() {
//        AbstractAuthenticationToken authentication = Mockito.mock(AbstractAuthenticationToken.class);
//        SimpleKeycloakAccount simpleKeycloakAccount = mock(SimpleKeycloakAccount.class);
//        AccessToken accessToken = mock(AccessToken.class);
//        RefreshableKeycloakSecurityContext refreshableKeycloakSecurityContext = mock(RefreshableKeycloakSecurityContext.class);
//        when(securityContext.getAuthentication()).thenReturn(authentication);
//        when(authentication.getDetails()).thenReturn(simpleKeycloakAccount);
//        when(simpleKeycloakAccount.getKeycloakSecurityContext()).thenReturn(refreshableKeycloakSecurityContext);
//        when(refreshableKeycloakSecurityContext.getToken()).thenReturn(accessToken);
//        JwtValidator.extractUserIdFromJwt();
//    }
//
//    @Test
//    public void extractUserIdFromJwt() {
//        AbstractAuthenticationToken authentication = Mockito.mock(AbstractAuthenticationToken.class);
//        SimpleKeycloakAccount simpleKeycloakAccount = mock(SimpleKeycloakAccount.class);
//        AccessToken accessToken = new AccessToken();
//        accessToken.setOtherClaims("gitlab_user_id", "1");
//        RefreshableKeycloakSecurityContext refreshableKeycloakSecurityContext = mock(RefreshableKeycloakSecurityContext.class);
//        when(securityContext.getAuthentication()).thenReturn(authentication);
//        when(authentication.getDetails()).thenReturn(simpleKeycloakAccount);
//        when(simpleKeycloakAccount.getKeycloakSecurityContext()).thenReturn(refreshableKeycloakSecurityContext);
//        when(refreshableKeycloakSecurityContext.getToken()).thenReturn(accessToken);
//        assertEquals(1, JwtValidator.extractUserIdFromJwt());
//    }
//
//    @Test(expected = ValidationException.class)
//    public void extractUserIdFromJwtWith0() {
//        AbstractAuthenticationToken authentication = Mockito.mock(AbstractAuthenticationToken.class);
//        SimpleKeycloakAccount simpleKeycloakAccount = mock(SimpleKeycloakAccount.class);
//        AccessToken accessToken = new AccessToken();
//        accessToken.setOtherClaims("gitlab_user_id", "0");
//        RefreshableKeycloakSecurityContext refreshableKeycloakSecurityContext = mock(RefreshableKeycloakSecurityContext.class);
//        when(securityContext.getAuthentication()).thenReturn(authentication);
//        when(authentication.getDetails()).thenReturn(simpleKeycloakAccount);
//        when(simpleKeycloakAccount.getKeycloakSecurityContext()).thenReturn(refreshableKeycloakSecurityContext);
//        when(refreshableKeycloakSecurityContext.getToken()).thenReturn(accessToken);
//        JwtValidator.extractUserIdFromJwt();
//    }
//
//
//    @Test
//    public void isInternalUser() {
//        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
//        assertFalse(JwtValidator.isInternalUser(httpServletRequest));
//
//    }
//
//    @Test
//    public void isInternalUserMachineRole() {
//        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
//        when(httpServletRequest.isUserInRole("MACHINE_ROLE")).thenReturn(true);
//        assertTrue(JwtValidator.isInternalUser(httpServletRequest));
//
//    }
//
//    @Test
//    public void isInternalUserMAdminRole() {
//        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
//        when(httpServletRequest.isUserInRole("ADMIN_ROLE")).thenReturn(true);
//        assertTrue(JwtValidator.isInternalUser(httpServletRequest));
//
//    }
//
//    @Test
//    public void isExternalUser() {
//        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
//        assertFalse(JwtValidator.isExternalUser(httpServletRequest));
//    }
//
//    @Test
//    public void isExternalUserMachineRole() {
//        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
//        when(httpServletRequest.isUserInRole("MACHINE_ROLE")).thenReturn(true);
//        assertFalse(JwtValidator.isExternalUser(httpServletRequest));
//    }
//
//    @Test
//    public void isExternalUserAdminRole() {
//        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
//        when(httpServletRequest.isUserInRole("ADMIN_ROLE")).thenReturn(true);
//        assertFalse(JwtValidator.isExternalUser(httpServletRequest));
//    }
//
//    @Test
//    public void isExternalUserUserRole() {
//        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
//        when(httpServletRequest.isUserInRole("USER_ROLE")).thenReturn(true);
//        assertTrue(JwtValidator.isExternalUser(httpServletRequest));
//    }
//
//
//    @Test
//    public void isCustomer() {
//        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
//        when(httpServletRequest.isUserInRole("DEVHQ_CUSTOMER_ROLE")).thenReturn(true);
//        assertTrue(JwtValidator.isCustomer(httpServletRequest));
//    }
//
//    @Test
//    public void isSuperCustomer() {
//        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
//        when(httpServletRequest.isUserInRole("DEVHQ_SUPERCUSTOMER_ROLE")).thenReturn(true);
//        assertTrue(JwtValidator.isSuperCustomer(httpServletRequest));
//    }
}