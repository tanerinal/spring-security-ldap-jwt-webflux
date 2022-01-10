package com.tanerinal.springsecurityldapjwtwebflux.configuration;

import com.tanerinal.springsecurityldapjwtwebflux.TestConstants;
import com.tanerinal.springsecurityldapjwtwebflux.entrypoint.AuthenticationEntryPoint;
import com.tanerinal.springsecurityldapjwtwebflux.handler.AccessDeniedHandler;
import com.tanerinal.springsecurityldapjwtwebflux.handler.AuthenticationSuccessHandler;
import com.tanerinal.springsecurityldapjwtwebflux.service.PortalUserService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.util.ReflectionTestUtils;

@RunWith(MockitoJUnitRunner.class)
public class WebSecurityConfigurationTest {

    @Mock
    private ReactiveAuthenticationManager authenticationManager;

    @Mock
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Mock
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Mock
    private AccessDeniedHandler accessDeniedHandler;

    @Mock
    private PortalUserService portalUserService;

    @InjectMocks
    WebSecurityConfiguration webSecurityConfiguration;

    private ServerHttpSecurity http;
    private String[] accessiblePaths = new String[]{"/actuator/health/**", "/actuator/gateway/**", "/authenticate", "/jwt-util/**"};
    private String[] financeRolePermittedPaths = new String[]{"/finance-zone/**"};
    private String[] businessRolePermittedPaths = new String[]{"/business-zone/**"};

    @BeforeEach
    public void setup() {
        this.http = ServerHttpSecurity.http().authenticationManager(this.authenticationManager);
    }

    @Before
    public void setUp() {
        ReflectionTestUtils.setField(webSecurityConfiguration, "permittedPaths", accessiblePaths);
        ReflectionTestUtils.setField(webSecurityConfiguration, "financeRolePermittedPaths", financeRolePermittedPaths);
        ReflectionTestUtils.setField(webSecurityConfiguration, "businessRolePermittedPaths", businessRolePermittedPaths);
        ReflectionTestUtils.setField(webSecurityConfiguration, "jwtSecret", TestConstants.JWT_SECRET);
    }


    @Test
    public void testSpringSecurityFilterChainWhenAllIsWellShouldReturnPopulatedSecurityWebFilterChain() {
        this.http = ServerHttpSecurity.http().authenticationManager(this.authenticationManager);

        SecurityWebFilterChain result = webSecurityConfiguration.springSecurityFilterChain(http);

        Assert.assertNotNull(result);
    }
}