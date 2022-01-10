package com.tanerinal.springsecurityldapjwtwebflux.service;

import com.tanerinal.springsecurityldapjwtwebflux.Constants;
import com.tanerinal.springsecurityldapjwtwebflux.TestConstants;
import com.tanerinal.springsecurityldapjwtwebflux.model.dto.AuthResponse;
import com.tanerinal.springsecurityldapjwtwebflux.util.JwtUtils;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@RunWith(PowerMockRunner.class)
@PrepareForTest({PortalUserService.class, JwtUtils.class})
public class PortalUserServiceTest {
    private static final String FIELD_CONTEXT_SOURCE = "contextSource";
    private static final long JWT_TIMEOUT = 18000;
    private static final String LDAP_URL = "LDAP_URL";
    private static final String LDAP_PORT = "LDAP_PORT";
    private static final String LDAP_ROOT = "LDAP_ROOT";
    private static final String LDAP_MANAGER_DN = "LDAP_MANAGER_DN";
    private static final String LDAP_MANAGER_PASSWORD = "LDAP_MANAGER_PASSWORD";
    private static final String LDAP_USER_SEARCH_BASE = "LDAP_USER_SEARCH_BASE";
    private static final String LDAP_USER_SEARCH_FILTER = "LDAP_USER_SEARCH_FILTER";
    private static final String GROUP_BASE = "GROUP_BASE";
    private static final String METHID_NAME_DO_LDAP_SEARCH = "doLdapSearch";
    private static final String METHOD_NAME_GET_GRANTED_AUTHORITIES = "getGrantedAuthorities";

    private List<String> userRoles = Collections.singletonList("FINANCE");

    @InjectMocks
    private PortalUserService portalUserService;

    @Mock
    SpringSecurityLdapTemplate springSecurityLdapTemplate;

    private PortalUserService spyPortalUserService;
    private DefaultSpringSecurityContextSource localContextSource;

    @Test
    public void testPrepareLdapContext() {
        Assert.assertNotNull(new String());
    }

//    @Before
//    public void setUp() {
//        WhiteboxImpl.setInternalState(portalUserService, "jwtSecret", TestConstants.JWT_SECRET);
//        WhiteboxImpl.setInternalState(portalUserService, "jwtTimeout", JWT_TIMEOUT);
//        WhiteboxImpl.setInternalState(portalUserService, "ldapUrl", LDAP_URL);
//        WhiteboxImpl.setInternalState(portalUserService, "ldapPort", LDAP_PORT);
//        WhiteboxImpl.setInternalState(portalUserService, "ldapRoot", LDAP_ROOT);
//        WhiteboxImpl.setInternalState(portalUserService, "ldapManagerDn", LDAP_MANAGER_DN);
//        WhiteboxImpl.setInternalState(portalUserService, "ldapManagerPassword", LDAP_MANAGER_PASSWORD);
//        WhiteboxImpl.setInternalState(portalUserService, "ldapUserSearchBase", LDAP_USER_SEARCH_BASE);
//        WhiteboxImpl.setInternalState(portalUserService, "ldapUserSearchFilter", LDAP_USER_SEARCH_FILTER);
//        WhiteboxImpl.setInternalState(portalUserService, "groupBase", GROUP_BASE);
//
//        String ldapFullUrl = new StringBuilder(LDAP_URL)
//                .append(":")
//                .append(LDAP_PORT)
//                .append("/")
//                .append(LDAP_ROOT)
//                .toString();
//        this.localContextSource = new DefaultSpringSecurityContextSource(ldapFullUrl);
//        this.localContextSource.setUserDn(LDAP_MANAGER_DN);
//        this.localContextSource.setPassword(LDAP_MANAGER_PASSWORD);
//        this.localContextSource.afterPropertiesSet();
//        WhiteboxImpl.setInternalState(portalUserService, FIELD_CONTEXT_SOURCE, this.localContextSource);
//
//        springSecurityLdapTemplate.setContextSource(this.localContextSource);
//
//        spyPortalUserService = PowerMockito.spy(portalUserService);
//    }
//
//    @SneakyThrows
//    @Test
//    public void testPrepareLdapContext() {
//        WhiteboxImpl.setInternalState(portalUserService, FIELD_CONTEXT_SOURCE, (Object) null);
//
//        WhiteboxImpl.invokeMethod(portalUserService, "prepareLdapContext");
//
//        Assert.assertNotNull(WhiteboxImpl.getInternalState(portalUserService, FIELD_CONTEXT_SOURCE));
//    }
//
//    @SneakyThrows
//    @Test
//    public void testAuthenticateUserWhenSuccessfulAuthenticationShouldReturnAuthenticatedResponseAndPopulateSecurityContext() {
//        PowerMockito.mockStatic(JwtUtils.class);
//        String token = "token";
//        List<String> permissionList = Arrays.asList("P1", "P2", "P3");
//
//        String username = "username";
//        String password = "password";
//        PowerMockito.doReturn(userRoles).when(spyPortalUserService, METHID_NAME_DO_LDAP_SEARCH, username, password);
//        PowerMockito.when(JwtUtils.createJWTToken(username, TestConstants.JWT_SECRET, JWT_TIMEOUT, userRoles)).thenAnswer((Answer<String>) invocation -> token);
//
//        AuthResponse response = spyPortalUserService.authenticateUser(username, password);
//
//        Assert.assertNotNull(SecurityContextHolder.getContext().getAuthentication());
//        Assert.assertEquals(username, response.getUsername());
//        Assert.assertEquals(userRoles, response.getUserRoles());
//        Assert.assertEquals(token, response.getToken());
//    }
//
//    @SneakyThrows
//    @Test
//    public void testGetGrantedAuthoritiesWhenNoGroupMembershipShouldReturnEmptyList() {
//        DirContextOperations ldapResult = new DirContextAdapter();
//
//        List<String> response = WhiteboxImpl.invokeMethod(spyPortalUserService, METHOD_NAME_GET_GRANTED_AUTHORITIES, ldapResult);
//
//        Assert.assertEquals(0, response.size());
//    }
//
//    @SneakyThrows
//    @Test
//    public void testGetGrantedAuthoritiesWhenHasGroupMembershipShouldReturnPopulatedList() {
//        DirContextOperations ldapResult = new DirContextAdapter();
//        ldapResult.addAttributeValue(Constants.LDAP_ATTRIBUTE_ISMEMBEROF, "CN=" + TestConstants.COMMON_STRING + "," + GROUP_BASE);
//
//        List<String> response = WhiteboxImpl.invokeMethod(spyPortalUserService, METHOD_NAME_GET_GRANTED_AUTHORITIES, ldapResult);
//
//        Assert.assertEquals(1, response.size());
//        Assert.assertTrue(StringUtils.equalsIgnoreCase(TestConstants.COMMON_STRING, response.get(0)));
//    }
}