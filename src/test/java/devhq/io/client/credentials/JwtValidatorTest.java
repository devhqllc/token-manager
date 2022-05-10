package devhq.io.client.credentials;

import org.mockito.Mock;

//@RunWith(MockitoJUnitRunner.class)
public class JwtValidatorTest {

//    @Mock
//    SecurityContext securityContext;
//    JwtValidator jwtValidator;

    ////
//    @Before
//    public void setUp() {
//        securityContext = mock(SecurityContext.class);
//        jwtValidator = new JwtValidator();
//    }

    ////
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
//        jwtValidator.extractUserIdFromJwt();
//    }
//
//    @Test
//    public void extractUserIdFromJwt() {
//        AbstractAuthenticationToken authentication = mock(AbstractAuthenticationToken.class);
//        SimpleKeycloakAccount simpleKeycloakAccount = mock(SimpleKeycloakAccount.class);
//        HttpServletRequest request = mock(HttpServletRequest.class);
//
//        when(jwtValidator.extractStringFromJwt(anyString())).thenReturn("1");
//        assertEquals(1, jwtValidator.getUserId(request));
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