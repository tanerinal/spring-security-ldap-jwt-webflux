package com.tanerinal.springsecurityldapjwtwebflux.entrypoint;

import com.tanerinal.springsecurityldapjwtwebflux.Constants;
import com.tanerinal.springsecurityldapjwtwebflux.TestConstants;
import com.tanerinal.springsecurityldapjwtwebflux.exception.UnauthenticatedException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Signal;

@RunWith(MockitoJUnitRunner.class)
public class AuthenticationEntryPointTest {
    @InjectMocks
    AuthenticationEntryPoint authenticationEntryPoint;

    private ServerWebExchange serverWebExchange;

    @Before
    public void setUp() {
        serverWebExchange = MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.valueOf("GET"), "/"));
    }

    @Test
    public void testCmmenceWhenAuthorizationHeaderExistsShouldReturnMonoEmpty() {
        serverWebExchange.getRequest().mutate().header(Constants.HEADER_AUTHORIZATION, TestConstants.COMMON_STRING).build();

        Mono<Void> response = authenticationEntryPoint.commence(serverWebExchange, null);

        Assert.assertEquals(Mono.empty(), response);
    }

    @Test
    public void testCmmenceWhenAuthorizationHeaderDoesNotExistShouldReturnMonoError() {
        serverWebExchange.getRequest().mutate().header(Constants.HEADER_X_FORWARDED_FOR, TestConstants.COMMON_STRING).build();

        Mono<Void> response = authenticationEntryPoint.commence(serverWebExchange, null);
        Signal<Void> signal = response.materialize().block();
        Assert.assertEquals(UnauthenticatedException.class, signal.getThrowable().getClass());
    }
}