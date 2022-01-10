package com.tanerinal.springsecurityldapjwtwebflux.handler;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import com.tanerinal.springsecurityldapjwtwebflux.Constants;
import com.tanerinal.springsecurityldapjwtwebflux.TestConstants;
import com.tanerinal.springsecurityldapjwtwebflux.exception.UnauthorizedException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Signal;

import java.net.InetSocketAddress;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class AccessDeniedHandlerTest {
    @InjectMocks
    AccessDeniedHandler accessDeniedHandler;

    @Mock
    Appender<ILoggingEvent> mockAppender;

    private ServerWebExchange serverWebExchange;

    @Before
    public void setUp() {
        serverWebExchange = MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.valueOf("GET"), "/")
                .header(Constants.HEADER_X_FORWARDED_FOR, TestConstants.COMMON_STRING)
                .header(Constants.HEADER_AUTHORIZATION, TestConstants.JWT_TOKEN)
                .remoteAddress(InetSocketAddress.createUnresolved(TestConstants.COMMON_STRING, TestConstants.COMMON_INT)));

        Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        root.addAppender(mockAppender);
    }

    @Test
    public void testHandleWhenAllIsWellShouldLogAndReturnException() {
        Mono<Void> response = accessDeniedHandler.handle(serverWebExchange, null);
        Signal<Void> signal = response.materialize().block();

        Assert.assertEquals(UnauthorizedException.class, signal.getThrowable().getClass());
        verify(mockAppender).doAppend(argThat(argument -> argument.getFormattedMessage().startsWith("Access Denied. Unauthorized access attempt to resource")));
    }
}