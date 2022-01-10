package com.tanerinal.springsecurityldapjwtwebflux.filter;

import com.tanerinal.springsecurityldapjwtwebflux.TestConstants;
import com.tanerinal.springsecurityldapjwtwebflux.handler.AuthenticationSuccessHandler;
import com.tanerinal.springsecurityldapjwtwebflux.service.PortalUserService;
import com.tanerinal.springsecurityldapjwtwebflux.util.JwtUtils;
import lombok.SneakyThrows;
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
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;

@RunWith(PowerMockRunner.class)
@PrepareForTest({JwtRequestFilter.class, JwtUtils.class})
public class JwtRequestFilterTest {
    public static final String METHOD_VERIFY_AND_AUTHENTICATE_PORTAL_USER = "verifyAndAuthenticatePortalUser";
    public static final String METHOD_ON_AUTH_SUCCESS = "onAuthSuccess";
    @InjectMocks
    private JwtRequestFilter jwtRequestFilter;
    @Mock
    PortalUserService portalUserService;
    @Mock
    AuthenticationSuccessHandler authenticationSuccessHandler;

    private JwtRequestFilter spyJwtRequestFilter;

    private ServerWebExchange serverWebExchange;

    private WebFilterChain chain = Mockito.mock(WebFilterChain.class);


    @Before
    public void setUp() {
        mockStatic(JwtUtils.class);

        ReflectionTestUtils.setField(jwtRequestFilter, "jwtSecret", TestConstants.JWT_SECRET);
        ReactiveSecurityContextHolder.clearContext();
        serverWebExchange = MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.valueOf("GET"), "/"));

        spyJwtRequestFilter = spy(jwtRequestFilter);
    }

    @SneakyThrows
    @Test
    public void testDoFilterWhenNoTokenShouldNotCallVerifyAndAuthenticatePortalUser() {
        PowerMockito.when(JwtUtils.getTokenWithoutBearer(serverWebExchange)).thenAnswer((Answer<Optional>) invocation -> Optional.empty());

        spyJwtRequestFilter.filter(serverWebExchange, chain);

        PowerMockito.verifyPrivate(spyJwtRequestFilter, times(0)).invoke(METHOD_VERIFY_AND_AUTHENTICATE_PORTAL_USER, anyString());
        Mockito.verify(chain).filter(serverWebExchange);
    }

    @SneakyThrows
    @Test
    public void testDoFilterWhenTokenFoundShouldCallVerifyAndAuthenticatePortalUserButNotOnAuthSuccess() {
        PowerMockito.when(JwtUtils.getTokenWithoutBearer(serverWebExchange)).thenAnswer((Answer<Optional>) invocation -> Optional.of(TestConstants.JWT_TOKEN));
        PowerMockito.doReturn(Mono.empty()).when(spyJwtRequestFilter, METHOD_VERIFY_AND_AUTHENTICATE_PORTAL_USER, TestConstants.JWT_TOKEN);
        Mockito.when(chain.filter(serverWebExchange)).thenReturn(Mono.empty());

        spyJwtRequestFilter.filter(serverWebExchange, chain);

        PowerMockito.verifyPrivate(spyJwtRequestFilter).invoke(METHOD_VERIFY_AND_AUTHENTICATE_PORTAL_USER, TestConstants.JWT_TOKEN);
        PowerMockito.verifyPrivate(spyJwtRequestFilter, times(0)).invoke(METHOD_ON_AUTH_SUCCESS, any(Authentication.class), eq(serverWebExchange), eq(chain));
    }
}